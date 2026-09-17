use crate::AuthzError;
use crate::keys::VerificationKeyRing;
use crate::revocation::{RevocationChecker, RevocationStore, RevocationTarget};
use crate::token::{
    SensitiveToken, root_block_id, valid_operation, valid_prefixed_id, valid_resource,
};
use biscuit_auth::builder::{date, fact, string};
use biscuit_auth::format::schema::SnapshotBlock;
use biscuit_auth::{Authorizer, AuthorizerBuilder, AuthorizerLimits, Biscuit, UnverifiedBiscuit};
use biscuit_parser::builder::{Binary, Check, CheckKind, Op, Rule, Term};
use biscuit_parser::parser::parse_source;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SESSIONS_POLICY: &str = include_str!("../vendored/authz/sessions-v1.datalog");
const MISSIONS_POLICY: &str = include_str!("../vendored/authz/missions-v1.datalog");
const MAX_TOKEN_SIZE: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalPolicy {
    Sessions,
    Missions,
}

impl CanonicalPolicy {
    fn source(self) -> &'static str {
        match self {
            Self::Sessions => SESSIONS_POLICY,
            Self::Missions => MISSIONS_POLICY,
        }
    }
}

#[derive(Clone)]
pub struct AuthorizationContext {
    pub policy: CanonicalPolicy,
    pub resource: String,
    pub operation: String,
    pub request_tenant: String,
    pub resource_tenant: String,
    pub audience: Option<String>,
    pub contribution_owner_user_id: Option<String>,
    pub now: SystemTime,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    pub user_id: String,
    pub tenant_id: String,
    pub role: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationDecision {
    pub principal: VerifiedPrincipal,
    pub root_block_id: String,
    pub matched_policy: usize,
    revocation_target: RevocationTarget,
}

impl AuthorizationDecision {
    #[must_use]
    pub fn revocation_target(&self) -> &RevocationTarget {
        &self.revocation_target
    }
}

impl std::fmt::Debug for AuthorizationDecision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationDecision")
            .field("principal", &"[REDACTED]")
            .field("root_block_id", &self.root_block_id)
            .field("matched_policy", &self.matched_policy)
            .finish()
    }
}

pub fn authorize<S: RevocationStore>(
    serialized: &SensitiveToken,
    context: AuthorizationContext,
    keys: &VerificationKeyRing,
    revocations: &mut RevocationChecker<S>,
) -> Result<AuthorizationDecision, AuthzError> {
    validate_context(&context)?;
    if serialized.expose().len() > MAX_TOKEN_SIZE {
        return Err(AuthzError::new("auth.biscuit_invalid"));
    }
    let unverified = UnverifiedBiscuit::from_base64(serialized.expose())
        .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
    let key_id = unverified
        .root_key_id()
        .ok_or_else(|| AuthzError::new("auth.key_unavailable"))?;
    let public_key = keys.select(key_id, context.now)?;
    let token = Biscuit::from_base64(serialized.expose(), public_key)
        .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
    let root_block_id = root_block_id(&token)?;
    // The structural validation below trusts the printed Datalog source of
    // blocks 0 and 1. biscuit-auth 6.0's printer emits `Term::Str`, variable
    // names and predicate names without escaping, so a holder of the root key
    // could otherwise sign a block whose reprinted source reparses to a
    // canonical shape while the binary the authorizer actually evaluates is
    // weaker (e.g. an unbounded `operation($x)` printed as a set-restricted
    // check). Reject any decoded term that would not survive the pinned
    // print/parse grammar unchanged, restoring the injectivity the validators
    // rely on. See SECURITY.md, evidence/reviews/fbbe360/ (5.0 pair) and
    // evidence/reviews/bfc2c0d/ (6.0 pair).
    //
    // biscuit-auth 6.0 split `AuthorizerBuilder` from `Authorizer`, and
    // `dump()` — the only public view of the *decoded* terms — exists on the
    // built `Authorizer` alone. The guard must inspect decoded terms (the
    // printed source is exactly what cannot be trusted yet), and it must run
    // before revocation, the structural checks and any decision. So the token
    // is loaded twice: once here into a token-only authorizer (no ambient
    // fact, no policy, never executed) whose dump is exactly the signed
    // blocks, and once below into the decision authorizer. The cost is one
    // extra block translation, a `dump()` and a `snapshot()` per request:
    // 13.4 µs of a 123.1 µs `authorize()` in release, median of three runs
    // (`double_load_cost_is_measured`, round 3); the alternative — building the
    // decision authorizer first and dumping it — would run the guard over the
    // ambient facts and the contract policy as well (whose `[...]` arrays the
    // guard deliberately rejects) and would move the decision authorizer's
    // construction ahead of the injectivity and revocation checks in the
    // documented verification order.
    let signed_blocks = token
        .authorizer()
        .map_err(|_| AuthzError::for_root("auth.biscuit_invalid", &root_block_id))?;
    if !blocks_roundtrip_safe(&signed_blocks) {
        return Err(AuthzError::for_root("auth.biscuit_invalid", &root_block_id));
    }
    // Block-level scopes (`trusting ...;` at block level, as opposed to a
    // rule's `trusting` suffix) are never printed by `Block::print_source`, so
    // the reprinted source that steps 7-8 validate cannot reveal them; they are
    // read on the decoded structure instead. Blocks 0 and 1 must carry none:
    // the canonical shapes are defined without a scope, and a scope can only
    // change which facts those blocks' own checks see.
    // The same snapshot serves the holder-block operation bound: the printer
    // emits no parenthesis, so a compound expression's reprint is not a
    // faithful rendering of its op sequence (see
    // `holder_expressions_carry_at_most_one_operation`).
    let Ok(snapshot) = signed_blocks.snapshot() else {
        return Err(AuthzError::for_root("auth.biscuit_invalid", &root_block_id));
    };
    drop(signed_blocks);
    if !canonical_blocks_have_no_block_scope(&snapshot.world.blocks)
        || !holder_expressions_carry_at_most_one_operation(&snapshot.world.blocks)
    {
        return Err(AuthzError::for_root("auth.biscuit_invalid", &root_block_id));
    }
    drop(snapshot);
    revocations.check(&root_block_id, context.now)?;
    let (principal, expires_at) = authority_principal(&token, &root_block_id)?;
    validate_initial_attenuation(&token, &principal, expires_at, &root_block_id)?;
    if principal.tenant_id != context.request_tenant {
        return Err(AuthzError::for_root("auth.tenant_mismatch", &root_block_id));
    }
    let remaining = expires_at
        .duration_since(context.now)
        .map_err(|_| AuthzError::for_root("auth.biscuit_invalid", &root_block_id))?;
    if remaining.is_zero() || remaining > Duration::from_secs(900) {
        return Err(AuthzError::for_root("auth.biscuit_invalid", &root_block_id));
    }

    let denied = || AuthzError::for_root("auth.operation_denied", &root_block_id);
    let mut builder = AuthorizerBuilder::new();
    for ambient_fact in [
        fact("time", &[date(&context.now)]),
        fact("resource", &[string(&context.resource)]),
        fact("operation", &[string(&context.operation)]),
        fact("request_tenant", &[string(&context.request_tenant)]),
        fact("resource_tenant", &[string(&context.resource_tenant)]),
    ] {
        builder = builder.fact(ambient_fact).map_err(|_| denied())?;
    }
    if let Some(audience) = &context.audience {
        builder = builder
            .fact(fact("audience", &[string(audience)]))
            .map_err(|_| denied())?;
    }
    if let Some(owner) = &context.contribution_owner_user_id {
        builder = builder
            .fact(fact("contribution_owner", &[string(owner)]))
            .map_err(|_| denied())?;
    }
    let mut authorizer = builder
        .code(context.policy.source())
        .map_err(|_| denied())?
        .build(&token)
        .map_err(|_| denied())?;
    let matched_policy = authorizer
        .authorize_with_limits(AuthorizerLimits {
            max_facts: 256,
            max_iterations: 32,
            max_time: Duration::from_millis(50),
        })
        .map_err(|_| AuthzError::for_root("auth.operation_denied", &root_block_id))?;
    let revocation_target = RevocationTarget::new(root_block_id.clone(), expires_at);
    Ok(AuthorizationDecision {
        principal,
        root_block_id,
        matched_policy,
        revocation_target,
    })
}

fn authority_principal(
    token: &Biscuit,
    root_block_id: &str,
) -> Result<(VerifiedPrincipal, SystemTime), AuthzError> {
    let denied = || AuthzError::for_root("auth.biscuit_invalid", root_block_id);
    if !matches!(token.context().first(), Some(None)) {
        return Err(denied());
    }
    let source = token.print_block_source(0).map_err(|_| denied())?;
    let parsed = parse_source(&source).map_err(|_| denied())?;
    // `parsed.scopes` is never populated here: the printer does not emit
    // block-level scopes. They are rejected on the structure in `authorize`
    // (`canonical_blocks_have_no_block_scope`) before this function runs.
    if !parsed.rules.is_empty()
        || !parsed.policies.is_empty()
        || parsed.facts.len() != 3
        || parsed.checks.len() != 1
    {
        return Err(denied());
    }

    let mut user_id = None;
    let mut tenant_id = None;
    let mut role = None;
    for (_, fact) in &parsed.facts {
        match (
            fact.predicate.name.as_str(),
            fact.predicate.terms.as_slice(),
        ) {
            ("user", [Term::Str(value)]) if user_id.is_none() => user_id = Some(value.clone()),
            ("tenant", [Term::Str(value)]) if tenant_id.is_none() => {
                tenant_id = Some(value.clone());
            }
            ("role", [Term::Str(user), Term::Str(value)]) if role.is_none() => {
                role = Some((user.clone(), value.clone()));
            }
            _ => return Err(denied()),
        }
    }
    let user_id = user_id.ok_or_else(denied)?;
    let tenant_id = tenant_id.ok_or_else(denied)?;
    let (role_user, role) = role.ok_or_else(denied)?;
    if role_user != user_id
        || !valid_prefixed_id(&user_id, "usr_")
        || !valid_prefixed_id(&tenant_id, "ten_")
        || !valid_operation(&role)
    {
        return Err(denied());
    }

    let expires_at = exact_expiration_check(&parsed.checks[0].1).ok_or_else(denied)?;
    Ok((
        VerifiedPrincipal {
            user_id,
            tenant_id,
            role,
        },
        expires_at,
    ))
}

fn validate_initial_attenuation(
    token: &Biscuit,
    principal: &VerifiedPrincipal,
    authority_expires_at: SystemTime,
    root_block_id: &str,
) -> Result<(), AuthzError> {
    let invalid = || AuthzError::for_root("auth.biscuit_invalid", root_block_id);
    if token.block_count() < 2 || !matches!(token.context().get(1), Some(None)) {
        return Err(invalid());
    }
    let source = token.print_block_source(1).map_err(|_| invalid())?;
    let parsed = parse_source(&source).map_err(|_| invalid())?;
    // Block-level scopes are checked on the structure in `authorize`, never
    // through the printed source (see `authority_principal`).
    if !parsed.facts.is_empty()
        || !parsed.rules.is_empty()
        || !parsed.policies.is_empty()
        || parsed.checks.len() != 4
    {
        return Err(invalid());
    }

    let resource = exact_string_check(&parsed.checks[0].1, "resource").ok_or_else(invalid)?;
    let tenant = exact_string_check(&parsed.checks[2].1, "tenant").ok_or_else(invalid)?;
    let expires_at = exact_expiration_check(&parsed.checks[3].1).ok_or_else(invalid)?;
    if !valid_resource(resource)
        || !canonical_operation_check(&parsed.checks[1].1)
        || tenant != principal.tenant_id
        || expires_at != authority_expires_at
    {
        return Err(invalid());
    }
    Ok(())
}

fn canonical_query(check: &Check) -> Option<&Rule> {
    if check.kind != CheckKind::One || check.queries.len() != 1 {
        return None;
    }
    let query = &check.queries[0];
    if query.head.name != "query" || !query.head.terms.is_empty() || !query.scopes.is_empty() {
        return None;
    }
    Some(query)
}

fn exact_string_check<'a>(check: &'a Check, predicate: &str) -> Option<&'a str> {
    let query = canonical_query(check)?;
    if !query.expressions.is_empty() || query.body.len() != 1 {
        return None;
    }
    match (query.body[0].name.as_str(), query.body[0].terms.as_slice()) {
        (name, [Term::Str(value)]) if name == predicate => Some(value),
        _ => None,
    }
}

fn canonical_operation_check(check: &Check) -> bool {
    let Some(query) = canonical_query(check) else {
        return false;
    };
    if query.body.len() != 1 || query.expressions.len() != 1 {
        return false;
    }
    let operation_variable = match (query.body[0].name.as_str(), query.body[0].terms.as_slice()) {
        ("operation", [Term::Variable(variable)]) => variable,
        _ => return false,
    };
    match query.expressions[0].ops.as_slice() {
        [
            Op::Value(Term::Set(operations)),
            Op::Value(Term::Variable(variable)),
            Op::Binary(Binary::Contains),
        ] if variable == operation_variable => {
            !operations.is_empty()
                && operations.len() <= 20
                && operations.iter().all(
                    |operation| matches!(operation, Term::Str(value) if valid_operation(value)),
                )
        }
        _ => false,
    }
}

fn exact_expiration_check(check: &Check) -> Option<SystemTime> {
    let query = canonical_query(check)?;
    if query.body.len() != 1 || query.expressions.len() != 1 {
        return None;
    }
    let time_variable = match (query.body[0].name.as_str(), query.body[0].terms.as_slice()) {
        ("time", [Term::Variable(variable)]) => variable,
        _ => return None,
    };
    match query.expressions[0].ops.as_slice() {
        [
            Op::Value(Term::Variable(variable)),
            Op::Value(Term::Date(expires_at)),
            Op::Binary(Binary::LessThan),
        ] if variable == time_variable => UNIX_EPOCH.checked_add(Duration::from_secs(*expires_at)),
        _ => None,
    }
}

fn validate_context(context: &AuthorizationContext) -> Result<(), AuthzError> {
    if context.request_tenant != context.resource_tenant {
        return Err(AuthzError::new("auth.tenant_mismatch"));
    }
    if context.now.duration_since(UNIX_EPOCH).is_err()
        || !valid_prefixed_id(&context.request_tenant, "ten_")
        || !valid_resource(&context.resource)
        || !valid_operation(&context.operation)
        || context
            .audience
            .as_deref()
            .is_some_and(|audience| !valid_operation(audience))
        || context
            .contribution_owner_user_id
            .as_deref()
            .is_some_and(|user| !valid_prefixed_id(user, "usr_"))
    {
        return Err(AuthzError::new("auth.operation_denied"));
    }
    Ok(())
}

/// Reject any token whose decoded terms would not survive the pinned
/// print/parse round trip unchanged.
///
/// [`authority_principal`] and [`validate_initial_attenuation`] validate the
/// canonical shape of blocks 0 and 1 by reprinting them with biscuit-auth 6.0's
/// printer and reparsing with biscuit-parser 0.2.0. That printer emits string
/// values (`"{}"`), variable names (`${}`) and predicate names verbatim, with
/// no escaping, while the parser terminates a string at the first raw `"`,
/// treats `\` as an escape introducer and stops an identifier at the first
/// non-identifier byte. A term carrying one of those bytes therefore reparses
/// into a *different* structure than the binary the authorizer evaluates. This
/// guard removes that entire differential class up front: if every decoded
/// `Term::Str` is free of `"`/`\` and every emitted identifier is a plain
/// datalog identifier, the printed source is a faithful (injective) rendering
/// of the binary and the structural validators can be trusted.
///
/// datalog 3.3 (biscuit-auth 6.0) added terms and operators this issuer never
/// emits: `null`, arrays, maps (whose keys print unescaped), closures (whose
/// parameter names print as identifiers) and `extern::` calls (whose names
/// print as identifiers). Rather than extend the injectivity proof to each new
/// channel, the guard rejects them as a class: a canonical token carries only
/// strings, dates, variables and sets, so the presence of any other kind in a
/// signed block is itself non-canonical, and rejecting it keeps the proof
/// obligation exactly where it was under 5.0. The `Term` and `Op` matches are
/// exhaustive on purpose — a future printer variant fails compilation instead
/// of silently passing through.
///
/// Two further families are rejected because their *printing* is not
/// injective even though the issuer could in principle emit them: the strict
/// boolean operators `And`/`Or` print as `&&!`/`||!`, which parser 0.2.0 reads
/// as `&& !x`/`|| !x` (lazy operator plus negation); the closure-taking
/// operators `TryOr`/`LazyAnd`/`LazyOr` in their binary (closure-less) form
/// reparse with a closure operand the binary never carried; and a `Term::Date`
/// above the last RFC 3339 second (`9999-12-31T23:59:59Z`) prints as a 1969
/// date or `<invalid date>` that no parser reads back.
fn blocks_roundtrip_safe(authorizer: &Authorizer) -> bool {
    use biscuit_auth::builder::{Binary, Op, Predicate, Rule, Term, Unary};

    // Last second the printer renders faithfully (`as i64` then RFC 3339,
    // year <= 9999); above it the rendering is `<invalid date>` or, past
    // i64::MAX, a wrapped 1969 date.
    const LAST_PRINTABLE_SECOND: u64 = 253_402_300_799;

    fn safe_string(value: &str) -> bool {
        !value.bytes().any(|byte| byte == b'"' || byte == b'\\')
    }
    fn safe_identifier(value: &str) -> bool {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b':')
    }
    fn term_ok(term: &Term) -> bool {
        match term {
            Term::Str(value) => safe_string(value),
            Term::Variable(name) => safe_identifier(name),
            Term::Set(members) => members.iter().all(term_ok),
            Term::Date(seconds) => *seconds <= LAST_PRINTABLE_SECOND,
            Term::Integer(_) | Term::Bytes(_) | Term::Bool(_) => true,
            // No signed block can carry an unbound parameter (the builder
            // refuses or panics before signing); the datalog 3.3 kinds are
            // rejected as a class (see the doc comment).
            Term::Parameter(_) | Term::Null | Term::Array(_) | Term::Map(_) => false,
        }
    }
    fn op_ok(op: &Op) -> bool {
        match op {
            Op::Value(term) => term_ok(term),
            // Identifier channels printed verbatim.
            Op::Unary(Unary::Ffi(_)) | Op::Binary(Binary::Ffi(_)) | Op::Closure(..) => false,
            // Printed `&&!` / `||!`: no such token in the parser.
            Op::Binary(Binary::And | Binary::Or) => false,
            // Reparse inserts a closure operand the binary form never had.
            Op::Binary(Binary::TryOr | Binary::LazyAnd | Binary::LazyOr) => false,
            Op::Unary(_) | Op::Binary(_) => true,
        }
    }
    fn predicate_ok(predicate: &Predicate) -> bool {
        safe_identifier(&predicate.name) && predicate.terms.iter().all(term_ok)
    }
    fn rule_ok(rule: &Rule) -> bool {
        predicate_ok(&rule.head)
            && rule.body.iter().all(predicate_ok)
            && rule
                .expressions
                .iter()
                .all(|expression| expression.ops.iter().all(op_ok))
    }

    let (facts, rules, checks, policies) = authorizer.dump();
    facts.iter().all(|fact| predicate_ok(&fact.predicate))
        && rules.iter().all(rule_ok)
        && checks.iter().all(|check| check.queries.iter().all(rule_ok))
        && policies
            .iter()
            .all(|policy| policy.queries.iter().all(rule_ok))
}

/// Blocks 0 and 1 must carry no block-level scope.
///
/// A block-level scope (`trusting authority;` / `trusting previous;` /
/// `trusting <key>;` at the top of a block) is not part of either canonical
/// shape. `Block::print_source` never prints it, so the reprinted source that
/// [`authority_principal`] and [`validate_initial_attenuation`] parse cannot
/// reveal it; this reads the decoded structure through the token-only
/// authorizer's snapshot instead, which carries each signed block's scopes as
/// the token stores them. Later blocks may carry scopes: they only narrow what
/// that block's own checks can see.
fn canonical_blocks_have_no_block_scope(blocks: &[SnapshotBlock]) -> bool {
    blocks.len() >= 2 && blocks.iter().take(2).all(|block| block.scope.is_empty())
}

/// Every expression of a holder-appended block (index 2 onwards) carries at
/// most one operation, and never `Parens`.
///
/// The 6.0 printer renders an op stack as a flat `left op right` string: only
/// an explicit `Unary::Parens` op prints `(...)`. Parser 0.2.0 reads that
/// string back under its own precedence layers (`||` < `&&` < comparisons,
/// non-associative < bitwise < `+ -` < `* /` < `!` < methods), so any
/// expression whose evaluation order differs from that precedence reprints as
/// a different tree — `[1, 2, Add, 3, Mul]` prints `1 + 2 * 3` and reparses
/// as `1 + (2 * 3)`; `[true, false, Equal, Negate]` prints `!true === false`
/// and reparses as `(!true) === false`; `[1, 2, LessThan, true, Equal]` prints
/// `1 < 2 === true`, which does not parse at all. Blocks 0 and 1 are matched
/// on exact op sequences by [`authority_principal`] and
/// [`validate_initial_attenuation`], so the divergence cannot reach them. For
/// holder blocks the guard is fail-closed instead of proving each shape: an
/// expression with a single unary or binary operation has exactly one parse,
/// and that parse is the op sequence; two operations, or a `Parens` op, are
/// refused as a class. This is read on the snapshot's proto structure, which
/// keeps the per-block boundary `dump()` merges away. Owner decision of
/// 2026-09-08 on the governance security verdict for d65e877.
fn holder_expressions_carry_at_most_one_operation(blocks: &[SnapshotBlock]) -> bool {
    use biscuit_auth::format::schema::{Expression, Rule, op, op_unary};

    fn expression_ok(expression: &Expression) -> bool {
        let mut operations = 0usize;
        for op in &expression.ops {
            match &op.content {
                Some(op::Content::Value(_)) => {}
                Some(op::Content::Unary(unary)) => {
                    if unary.kind == op_unary::Kind::Parens as i32 {
                        return false;
                    }
                    operations += 1;
                }
                Some(op::Content::Binary(_)) | Some(op::Content::Closure(_)) => {
                    operations += 1;
                }
                // A content-less op is not a printable expression.
                None => return false,
            }
        }
        operations <= 1
    }
    fn rule_ok(rule: &Rule) -> bool {
        rule.expressions.iter().all(expression_ok)
    }

    blocks.iter().skip(2).all(|block| {
        block.rules.iter().all(rule_ok)
            && block
                .checks
                .iter()
                .all(|check| check.queries.iter().all(rule_ok))
    })
}
