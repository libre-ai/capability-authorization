use crate::AuthzError;
use crate::revocation::{AgentRevocationStore, RevocationStoreUnavailable, RevocationTarget};
use biscuit_auth::builder::{BlockBuilder, Term};
use biscuit_auth::{Biscuit, KeyPair, PublicKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const AUTHORITY_TEMPLATE: &str = include_str!("../vendored/authz/authority-v1.datalog");
const AUTHORITY_TEMPLATE_V2: &str = include_str!("../vendored/authz/authority-v2.datalog");
const MAX_TOKEN_SIZE: usize = 16_384;

pub struct SensitiveToken(String);

impl SensitiveToken {
    pub fn from_transport(mut value: String) -> Result<Self, AuthzError> {
        if value.is_empty() || value.len() > MAX_TOKEN_SIZE {
            value.zeroize();
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SensitiveToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Debug for SensitiveToken {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveToken([REDACTED])")
    }
}

pub struct SerializedBiscuit {
    pub token: SensitiveToken,
    revocation_target: RevocationTarget,
    expires_at: SystemTime,
    key_id: u32,
}

impl SerializedBiscuit {
    #[must_use]
    pub fn token(&self) -> &SensitiveToken {
        &self.token
    }

    #[must_use]
    pub fn root_block_id(&self) -> &str {
        self.revocation_target.root_block_id()
    }

    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    #[must_use]
    pub fn revocation_target(&self) -> &RevocationTarget {
        &self.revocation_target
    }
}

impl Debug for SerializedBiscuit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SerializedBiscuit")
            .field("token", &"[REDACTED]")
            .field("root_block_id", &self.root_block_id())
            .field("key_id", &self.key_id)
            .field("expires_at", &self.expires_at())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TokenBounds {
    pub tenant_id: String,
    pub resource: String,
    pub operations: BTreeSet<String>,
    pub expires_at: SystemTime,
}

impl Debug for TokenBounds {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenBounds([REDACTED])")
    }
}

pub struct BoundedBiscuit {
    biscuit: Biscuit,
    bounds: TokenBounds,
    authority_expires_at: SystemTime,
    key_id: u32,
}

impl Debug for BoundedBiscuit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedBiscuit([REDACTED])")
    }
}

impl BoundedBiscuit {
    #[must_use]
    pub fn bounds(&self) -> &TokenBounds {
        &self.bounds
    }

    pub fn attenuate(
        &self,
        request: AttenuationRequest,
        now: SystemTime,
    ) -> Result<Self, AuthzError> {
        validate_bounds(&request.tenant_id, &request.resource, &request.operations)?;
        validate_time(now)?;
        if !is_whole_second_ttl(request.ttl) {
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        let expires_at = now
            .checked_add(request.ttl)
            .ok_or_else(|| AuthzError::new("auth.biscuit_invalid"))?;
        if now >= self.bounds.expires_at
            || request.tenant_id != self.bounds.tenant_id
            || request.resource != self.bounds.resource
            || !request.operations.is_subset(&self.bounds.operations)
            || expires_at > self.bounds.expires_at
        {
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        let bounds = TokenBounds {
            tenant_id: request.tenant_id,
            resource: request.resource,
            operations: request.operations,
            expires_at,
        };
        let block = attenuation_block(&bounds)?;
        let biscuit = self
            .biscuit
            .append(block)
            .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        Ok(Self {
            biscuit,
            bounds,
            authority_expires_at: self.authority_expires_at,
            key_id: self.key_id,
        })
    }

    pub fn serialize(&self) -> Result<SerializedBiscuit, AuthzError> {
        let root_block_id = root_block_id(&self.biscuit)?;
        let expires_at = effective_expiration(self.bounds.expires_at)?;
        let authority_expires_at = effective_expiration(self.authority_expires_at)?;
        let mut token = self
            .biscuit
            .to_base64()
            .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        if token.len() > MAX_TOKEN_SIZE {
            token.zeroize();
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        Ok(SerializedBiscuit {
            token: SensitiveToken(token),
            revocation_target: RevocationTarget::new(root_block_id, authority_expires_at),
            expires_at,
            key_id: self.key_id,
        })
    }
}

pub struct BiscuitIssuer {
    key_id: u32,
    key_pair: KeyPair,
    max_ttl: Duration,
    valid_from: SystemTime,
}

impl Debug for BiscuitIssuer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BiscuitIssuer")
            .field("key_id", &self.key_id)
            .field("key_pair", &"[REDACTED]")
            .field("max_ttl", &self.max_ttl)
            .field("valid_from", &self.valid_from)
            .finish()
    }
}

impl BiscuitIssuer {
    pub fn new(
        key_id: u32,
        key_pair: KeyPair,
        max_ttl: Duration,
        valid_from: SystemTime,
    ) -> Result<Self, AuthzError> {
        // biscuit-auth 6.0 keys are algorithm-tagged (Ed25519 or P-256). The
        // security boundary is stated for Ed25519 only, so a caller-supplied
        // P-256 signing key is refused here rather than silently accepted and
        // misreported; the ring applies the same rule to verification keys.
        if !crate::keys::is_ed25519(&key_pair.public()) {
            return Err(AuthzError::new("auth.key_unavailable"));
        }
        if !is_whole_second_ttl(max_ttl)
            || max_ttl > Duration::from_secs(900)
            || valid_from.duration_since(UNIX_EPOCH).is_err()
        {
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        Ok(Self {
            key_id,
            key_pair,
            max_ttl,
            valid_from,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public()
    }

    #[must_use]
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Mint a v1 human / browser-session token (no agent identity facts).
    pub fn issue(
        &self,
        request: IssuanceRequest,
        now: SystemTime,
    ) -> Result<BoundedBiscuit, AuthzError> {
        self.issue_inner(request, None, now)
    }

    /// Mint a v2 agent-fleet token carrying the loop-security kernel K1 identity
    /// facts (`agent_fleet`, `mission_agent`, `capability_scope`). The agent
    /// principal is the request's `user_id`.
    pub fn issue_agent(
        &self,
        request: IssuanceRequest,
        agent: AgentIdentity,
        now: SystemTime,
        revocations: &mut impl AgentRevocationStore,
    ) -> Result<BoundedBiscuit, AuthzError> {
        // Fail-closed per-agent revocation (loop-security kernel K1): a revoked
        // agent — or an unavailable revocation store — mints no new token. Live
        // tokens of a revoked agent still lapse under the short TTL ceiling.
        // Store unavailability denies with the generic `auth.biscuit_invalid`
        // (the canonical code set has no distinct "revocation store down" code);
        // distinguishing it from a malformed request needs structured logging.
        match revocations.is_agent_revoked(&request.user_id) {
            Ok(false) => {}
            Ok(true) => return Err(AuthzError::new("auth.agent_revoked")),
            Err(RevocationStoreUnavailable) => {
                return Err(AuthzError::new("auth.biscuit_invalid"));
            }
        }
        self.issue_inner(request, Some(agent), now)
    }

    fn issue_inner(
        &self,
        request: IssuanceRequest,
        agent: Option<AgentIdentity>,
        now: SystemTime,
    ) -> Result<BoundedBiscuit, AuthzError> {
        validate_time(now)?;
        if now < self.valid_from {
            return Err(AuthzError::new("auth.key_unavailable"));
        }
        validate_identity(&request.user_id, &request.tenant_id, &request.role)?;
        validate_bounds(&request.tenant_id, &request.resource, &request.operations)?;
        if !is_whole_second_ttl(request.ttl) || request.ttl > self.max_ttl {
            return Err(AuthzError::new("auth.biscuit_invalid"));
        }
        let expires_at = now
            .checked_add(request.ttl)
            .ok_or_else(|| AuthzError::new("auth.biscuit_invalid"))?;
        let mut parameters = HashMap::<String, Term>::new();
        parameters.insert("user".to_owned(), request.user_id.clone().into());
        parameters.insert("tenant".to_owned(), request.tenant_id.clone().into());
        parameters.insert("role".to_owned(), request.role.into());
        parameters.insert("expires_at".to_owned(), expires_at.into());
        // Human and browser-session tokens use the v1 authority block; agent-fleet
        // tokens use v2, which carries the loop-security kernel K1 identity facts
        // (agent_fleet, mission_agent, capability_scope). The agent principal id is
        // the token's own user id.
        let template = if let Some(agent) = &agent {
            validate_agent_identity(agent)?;
            parameters.insert("agent".to_owned(), request.user_id.clone().into());
            parameters.insert("fleet".to_owned(), agent.fleet.clone().into());
            parameters.insert("mission".to_owned(), agent.mission.clone().into());
            parameters.insert("capability".to_owned(), agent.capability.clone().into());
            AUTHORITY_TEMPLATE_V2
        } else {
            AUTHORITY_TEMPLATE
        };
        // biscuit-auth 6.0 builders are consuming (`self -> Result<Self>`), so
        // the authority block is assembled as one fallible chain.
        let mut builder = Biscuit::builder()
            .root_key_id(self.key_id)
            .code_with_params(template, parameters, HashMap::new())
            .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        // The agent-runs authorizer requires a token_mission fact (the per-token
        // operating mission) distinct from the mission_agent identity fact. For a
        // single-mission agent token it equals the agent's mission membership; the
        // authorizer binds token_mission ∈ mission_agent by unifying the two.
        if let Some(agent) = &agent {
            let mut mission_params = HashMap::<String, Term>::new();
            mission_params.insert("mission".to_owned(), agent.mission.clone().into());
            builder = builder
                .code_with_params("token_mission({mission});", mission_params, HashMap::new())
                .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        }
        let authority = builder
            .build(&self.key_pair)
            .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        let bounds = TokenBounds {
            tenant_id: request.tenant_id,
            resource: request.resource,
            operations: request.operations,
            expires_at,
        };
        let biscuit = authority
            .append(attenuation_block(&bounds)?)
            .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
        Ok(BoundedBiscuit {
            biscuit,
            bounds,
            authority_expires_at: expires_at,
            key_id: self.key_id,
        })
    }
}

#[derive(Clone)]
pub struct IssuanceRequest {
    pub user_id: String,
    pub tenant_id: String,
    pub role: String,
    pub resource: String,
    pub operations: BTreeSet<String>,
    pub ttl: Duration,
}

/// The three loop-security kernel K1 identity facts an agent-fleet token carries.
/// The agent principal is the token's `user_id`; these are its fleet membership,
/// operating mission and explicit capability scope.
///
/// Each field is an issuer-side identifier — never PII or content — and must
/// match the operation grammar (2..=64 bytes, lowercase ASCII start, then
/// lowercase/digit/hyphen), enforced at issuance. This keeps the values
/// injection-free once bound into the datalog authority block.
#[derive(Clone)]
pub struct AgentIdentity {
    pub fleet: String,
    pub mission: String,
    pub capability: String,
}

#[derive(Clone)]
pub struct AttenuationRequest {
    pub tenant_id: String,
    pub resource: String,
    pub operations: BTreeSet<String>,
    pub ttl: Duration,
}

fn attenuation_block(bounds: &TokenBounds) -> Result<BlockBuilder, AuthzError> {
    let mut parameters = HashMap::<String, Term>::new();
    parameters.insert("resource".to_owned(), bounds.resource.clone().into());
    parameters.insert("tenant".to_owned(), bounds.tenant_id.clone().into());
    parameters.insert("expires_at".to_owned(), bounds.expires_at.into());
    parameters.insert(
        "operations".to_owned(),
        Term::Set(bounds.operations.iter().cloned().map(Term::from).collect()),
    );
    // `{operations}` binds a `Term::Set`; under datalog 3.3 the 6.0 printer
    // renders it as `{"a", "b"}` and biscuit-parser 0.2.0 reads that back as a
    // set, so the attenuation check keeps set semantics on both sides of the
    // print/parse round trip (SECURITY.md, "Print/parse injectivity").
    BlockBuilder::new()
        .code_with_params(
            r#"
check if resource({resource});
check if operation($operation), {operations}.contains($operation);
check if tenant({tenant});
check if time($time), $time < {expires_at};
"#,
            parameters,
            HashMap::new(),
        )
        .map_err(|_| AuthzError::new("auth.biscuit_invalid"))
}

fn validate_agent_identity(agent: &AgentIdentity) -> Result<(), AuthzError> {
    // Fleet, mission and capability are issuer-side identifiers, never PII or
    // content; the operation grammar (lowercase, digits, hyphen; 2..=64) is a
    // conservative fit and keeps the datalog values injection-free.
    if !valid_operation(&agent.fleet)
        || !valid_operation(&agent.mission)
        || !valid_operation(&agent.capability)
    {
        return Err(AuthzError::new("auth.biscuit_invalid"));
    }
    Ok(())
}

fn validate_identity(user_id: &str, tenant_id: &str, role: &str) -> Result<(), AuthzError> {
    if !valid_prefixed_id(user_id, "usr_")
        || !valid_prefixed_id(tenant_id, "ten_")
        || !valid_operation(role)
    {
        return Err(AuthzError::new("auth.biscuit_invalid"));
    }
    Ok(())
}

fn validate_bounds(
    tenant_id: &str,
    resource: &str,
    operations: &BTreeSet<String>,
) -> Result<(), AuthzError> {
    if !valid_prefixed_id(tenant_id, "ten_")
        || !valid_resource(resource)
        || operations.is_empty()
        || operations.len() > 20
        || operations
            .iter()
            .any(|operation| !valid_operation(operation))
    {
        return Err(AuthzError::new("auth.biscuit_invalid"));
    }
    Ok(())
}

pub(crate) fn valid_prefixed_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        (16..=64).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

fn validate_time(value: SystemTime) -> Result<(), AuthzError> {
    value
        .duration_since(UNIX_EPOCH)
        .map(|_| ())
        .map_err(|_| AuthzError::new("auth.biscuit_invalid"))
}

/// A token lifetime must be a whole, non-zero number of seconds.
///
/// Biscuit encodes expiry as `Term::Date`, whose resolution is one second, so a
/// sub-second or fractional TTL is silently floored on serialization. That can
/// mint a token that is already expired (the floored expiry lands on the issue
/// second, failing `time < expiry`) or one whose lifetime is unpredictably
/// shortened. Constraining the request to whole seconds removes the ambiguity;
/// the real-clock `now` may still carry nanoseconds and is floored
/// conservatively, never extending the lifetime past `max_ttl`.
fn is_whole_second_ttl(ttl: Duration) -> bool {
    !ttl.is_zero() && ttl.subsec_nanos() == 0
}

fn effective_expiration(value: SystemTime) -> Result<SystemTime, AuthzError> {
    let seconds = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthzError::new("auth.biscuit_invalid"))?
        .as_secs();
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| AuthzError::new("auth.biscuit_invalid"))
}

pub(crate) fn valid_resource(value: &str) -> bool {
    (3..=512).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b':' | b'.' | b'_' | b'-')
        })
}

pub(crate) fn valid_operation(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn root_block_id(token: &Biscuit) -> Result<String, AuthzError> {
    let authority_signature = token
        .revocation_identifiers()
        .into_iter()
        .next()
        .ok_or_else(|| AuthzError::new("auth.biscuit_invalid"))?;
    let digest = Sha256::digest(authority_signature);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").map_err(|_| AuthzError::new("auth.biscuit_invalid"))?;
    }
    Ok(encoded)
}
