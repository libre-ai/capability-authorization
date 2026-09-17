# Biscuit authorization security boundary

## Trust boundary

`libre-ai-authz-biscuit` is the only Rust capability allowed to create or verify
internal Biscuit tokens. Browsers, React applications and pure WIT engines must
never receive a serialized Biscuit.

Trusted inputs are limited to:

- one issuer-held Ed25519 private key (biscuit-auth 6.0 keys are
  algorithm-tagged; `BiscuitIssuer::new` refuses any other algorithm);
- a bounded two-key public verification ring (`VerificationKeyRing::new` and
  `begin_rotation` refuse any non-Ed25519 key; `public_keys()` reports the
  algorithm the key carries, never a constant). The three refusals are each
  exercised by `non_ed25519_keys_are_refused_at_every_entry_point`, whose
  rotation probe holds every other precondition of `begin_rotation` and passes
  the same rotation with an Ed25519 key, so the algorithm is the only reason
  for the refusal (round 3, after the round-2 probe was refused by its
  backdated `valid_from` first);
- canonical policy source embedded at compile time;
- request/resource facts supplied by an already authenticated handler;
- an external revocation store keyed by a verified root block ID.

Token bytes, including `root_key_id`, are untrusted until signature
verification. The key ID may only select a candidate public key. It never grants
authority.

## Fixed verification order

1. Reject an empty or oversized transport value.
2. Read the unverified key ID only to select a currently valid public key.
3. Verify the Ed25519 signature and Biscuit chain.
4. Derive `SHA-256(authority_signature)` as the root block ID.
5. Walk the decoded terms of every signed block and reject the token on any
   item of the exact rejected list in "Print/parse injectivity" below (injection
   bytes in strings and identifiers, the datalog 3.3 kinds, the operators and
   dates whose reprint is not faithful, a block-level scope on block 0 or 1, and
   a holder-block expression with more than one operation or a `Parens` op).
   Together with the exact op-sequence matching of steps 7–8, this makes the
   reprinted source of blocks 0 and 1 a faithful rendering of the binary. The
   guarantee is bounded by that list: a construct that is neither in the
   faithful list nor in the rejected list is not claimed either way.
6. Check external revocation before policy evaluation.
7. Parse the verified authority block and require exactly `user`, `tenant`,
   `role(user, role)` plus one canonical expiry check and no context, rule or
   policy.
8. Require block 1 to be the canonical initial attenuation shape: exact valid
   resource, non-empty bounded operation set, matching tenant and the same
   expiry as authority, with no fact, rule, policy or context (and no block-level
   scope, per step 5).
9. Reject a remaining lifetime greater than 15 minutes; the sole issuer
   independently enforces activation and original TTL.
10. Inject current time, exact resource/operation, request tenant and
    authoritative resource-tenant/audience/ownership facts.
11. Execute an embedded policy under fact, iteration and time limits. Every
    canonical policy ends in `deny if true`.

Any parse, key, revocation, runtime-limit, query or policy error denies.

## Contracts under datalog 3.3

The six vendored policies are byte-identical to the `contracts` authority and
did not change with the engine. What changed is what the grammar makes of them:
under biscuit-auth 5.0 (datalog 3.2) the `["read", "export"]` literal in every
`[...].contains($operation)` clause was a **set**; under 6.0 (datalog 3.3) the
same bytes denote an **array**, and sets are written `{...}`. Membership
semantics are unchanged — `array.contains(str)` is true exactly when the string
is an element, as the set test was — so every allow/deny outcome is preserved;
`canonical_policies_allow_and_deny_as_before_under_the_6_0_evaluator` holds one
positive and one negative case per authorizer contract, and
`every_vendored_policy_parses_under_parser_0_2_and_contains_is_an_array_membership`
proves the fourteen operation lists parse as string arrays and are the only
collection literals in the contracts. The two kinds are not interchangeable
elsewhere: the issuer's own block-1 attenuation binds a `Term::Set` (printed
`{...}`), and the injectivity guard rejects an array in any signed block, so the
array form is confined to the authorizer side, where it is never printed or
reparsed.

## Print/parse injectivity

Steps 7–8 validate the canonical shape of blocks 0 and 1 by reprinting them with
the biscuit-auth 6.0 printer and reparsing with the version-matched
biscuit-parser 0.2.0 (the datalog 3.3 grammar). The pair is pinned exactly:
`biscuit-auth` resolves to the vendored copy under `third_party/` (the published
6.0.0 archive plus upstream fix #306, see its `PATCH.md`) and `biscuit-parser` to
`=0.2.0`. The pinned grammar guarantees the parser understands what the printer
wrote, but it does **not** guarantee that `parse(print(x)) == x`: the printer
emits string values, variable names and predicate names verbatim, with no
escaping, while the parser terminates a string at the first raw `"`, treats `\`
as an escape introducer (`\\`, `\"`, `\n`) and stops an identifier at the first
non-identifier byte. A holder of the root key could therefore sign a block whose
reprinted source reparses into a _different, canonical-looking_ structure than
the binary the authorizer actually evaluates — for example an unbounded
`operation($x)` whose variable name reprints as a set-restricted
`{"read"}.contains` check, silently widening the operation attenuation.

Step 5 removes that entire differential class before the structural checks run.
It loads the token into a token-only authorizer (no ambient fact, no policy,
never executed — biscuit-auth 6.0 exposes decoded terms only on a built
`Authorizer`), walks the decoded terms of every signed block and rejects the
token unless each `Term::Str` is free of `"` and `\` and every emitted identifier
(variable and predicate name) is a plain datalog identifier. Legitimately issued
tokens carry only charset-restricted identifiers, so they always pass; any
injection byte denies with `auth.biscuit_invalid`. Adversarial tests cover the
string and variable-name channels; a resource carrying `/`, `//`, `:`, `.`, `-`
or `_` round-trips faithfully and is still accepted.

datalog 3.3 widened the printer's surface. The 6.0 pair was re-qualified with
the same method as the 5.0 pair, then re-reviewed by two independent K4 passes;
the current record is `evidence/reviews/81ce4b5/` (it supersedes
`evidence/reviews/bfc2c0d/`, kept immutable). What follows is the exact list the
tests hold — nothing more is claimed.

**Proved faithful by print/parse round trip, and relied upon:**

- string terms over every byte `0x01..=0x7f` except `"` and `\`, plus one
  two-byte (`é`), one three-byte (`€`) and one four-byte (`😀`) UTF-8 sample
  (`every_ascii_byte_in_a_string_term_either_round_trips_or_is_denied`);
- `{..}.contains($x)` on a set and `<`/`<=` between a variable and a date — the
  two operators the canonical block 1 relies on (`{operations}.contains($operation)`,
  `$time < <expiry>`) — each reparsing to the same op sequence
  (`set_contains_and_date_comparisons_round_trip`);
- sets: block 1 binds `{operations}` to a `Term::Set`, printed `{"a", "b"}`
  (members in symbol-table order, which the reparsed set ignores) and reparsed
  to the same set; the empty set prints as `{,}`, distinct from the empty map
  `{}`, reparses empty and is then rejected by the non-empty bound of step 8;
- strict and lenient equality: `===`/`!==` and `==`/`!=` each reparse to their
  own operator;
- dates up to `9999-12-31T23:59:59Z` (`253402300799`);
- a rule-level trusted-key scope (`check if … trusting ed25519/<hex>`), which
  prints with its algorithm prefix and reparses to the same algorithm and bytes.

**Rejected by step 5 with `auth.biscuit_invalid`, one test per rule, each test
proved to turn red when its rule is removed (mutation table in the evidence
record):**

- a `"` or `\` byte in any string term, including inside a set member or a fact;
- a variable name or predicate name (fact, rule head, rule body, check body)
  that is not a plain datalog identifier;
- `null`, arrays, maps (keys print unescaped), closures (parameter names print
  as identifiers) and `extern::` calls (names print as identifiers): the issuer
  never emits them, so their presence in any signed block is non-canonical, and
  rejecting them as a class keeps the proof obligation where it stood under 5.0;
- the strict boolean operators `And`/`Or`, printed `&&!`/`||!` — a token the
  parser does not have, read back as `&& !x`/`|| !x`;
- `try_or`, and the lazy `&&`/`||` in their binary form, whose reprint reparses
  with a closure operand the binary never carried;
- a `Term::Date` above `253402300799`, which prints as a wrapped 1969 date or
  `<invalid date>` and reparses as neither;
- a block-level scope on block 0 or 1, read on the decoded structure (the
  printer never emits it);
- in a holder block (index 2 onwards), an expression carrying two or more
  operations, or a `Parens` op: the printer emits no parenthesis, so a
  compound expression reprints as a flat string that parser 0.2.0 reads back
  under its own precedence (`1 + 2 * 3` as `1 + (2 * 3)`, `!true === false`
  as `(!true) === false`, `1 < 2 === true` not at all). Rather than prove each
  shape, the guard admits one unary or binary operation per expression and
  never `Parens`; a faithful two-operation expression such as
  `$x.length() === 4` is refused all the same. Blocks 0 and 1 are held by
  their exact op sequences (steps 7–8). Read on the snapshot structure, which
  keeps the per-block boundary (`guard_holder_expression_with_two_operations`,
  `guard_holder_expression_with_parens`; the single-operation forms the
  canonical block 1 uses, `{..}.contains($x)` and `$time <= <date>`, stay
  accepted: `holder_expressions_with_a_single_operation_stay_accepted`).

Unreachable, and therefore not tested through `authorize()`: a `Term::Parameter`
cannot be signed into a block (the builder fails or panics before signing —
`term_parameter_never_reaches_a_signed_block`), and a token-only authorizer holds
no policy, so the guard's policy walk never sees anything.

Not covered by this list: nested, mixed-type or variable-bearing sets (refused
at load, before the guard, by the block decoder), and holder attenuation written
in datalog 3.3 idioms (see "Issuance and attenuation"). Constructs the printer
can emit that are neither in the faithful list nor in the rejected list are not
claimed either way.

The guard, and this section, are bound to the exact printer/parser pair above:
changing either version invalidates the proof and requires a new evidence
record.

## Issuance and attenuation

Issuance accepts only opaque `usr_` and private `ten_` identifiers, one bounded
role, one exact resource, at most 20 operations, an active signing-key time and
a TTL that is a whole, non-zero number of seconds no greater than 900. Biscuit
encodes expiry at one-second resolution, so a sub-second or fractional TTL is
rejected rather than silently floored into an already-expired or unpredictably
shortened token; the real-clock issue time may still carry nanoseconds and is
floored conservatively, never extending the lifetime. The authority source is
`contracts/authz/authority-v1.datalog`.

Every issued token immediately receives an attenuation block binding exact
resource, operation set, tenant and expiry. Verification independently rejects
a root-only token or a malformed/non-canonical first attenuation block. Further
attenuation is available without the issuer key but only when operations form a
non-empty subset and all other bounds remain equal or earlier. The attenuation
API has no role field. Biscuit block trust semantics additionally prevent
holder-appended role facts from satisfying canonical authorizer policies; this
has an adversarial test.

Holder-appended blocks (block 2 onwards) are never shape-validated, but they
pass through step 5 like every signed block. A block written in datalog 3.3
idioms is denied as a class, whatever it says — by step 5 for `&&`, `||` (the
parser desugars both into a closure, and the binary form is refused),
`.try_or`, `null`, arrays, maps, `&&!`/`||!`, out-of-range dates and every
closure (so `.all`/`.any` as written); by the evaluator, with
`auth.operation_denied`, for `.all`/`.any`/`.get` in their binary
(closure-less) form, which step 5 passes and which the 6.0 evaluator cannot
apply. Holder blocks are further bound by step 5 to one operation per
expression and no `Parens` (the printer emits no parenthesis, so a compound
expression has no faithful reprint). The only holder attenuation this crate
accepts is the shape its own `attenuate()` emits, or a hand-built block
restricted to strings, dates, variables, sets and the pre-3.3 operators, one
operation per expression. A service that appends its own blocks must know
this; it is a fail-closed choice, not an omission.

## Revocation

The revocation key is derived only after successful signature verification. An
opaque `RevocationTarget`, produced only by issuance or successful
authorization, binds the verified root ID to the root authority expiry. The
checker derives each store record from that target plus a constrained reason
code and current revocation time, so neither callers nor a shorter child
attenuation can purge a root-family revocation while a parent token remains
valid. Records never contain token bytes or identity data. Public checker
methods reject any root ID that is not exactly 64 lowercase hexadecimal bytes
before touching the cache or store.

The status cache is positive-only and capped at 10,000 entries and 30 seconds:
it caches only `revoked` verdicts. Revocation is monotonic, so a fresh cached
revocation may be served without a store round trip, but a not-revoked verdict
is never cached — every acceptance re-consults the store. This makes an
emergency revocation written by one verifier instance take effect immediately on
every other instance sharing the store; a negative cache would instead let an
instance keep accepting an already-revoked token for up to the cache TTL, a
bounded fail-open window this design forbids. A local revoke writes the store
first, then records the revocation in the cache. Store failure denies. Clock
rollback invalidates cache freshness. A future storage adapter must also enforce
its own bounded connection and operation timeouts; this synchronous port cannot
turn a hung implementation into an error.

## Key rotation

The ring contains one `Current` key, or one `Current` plus one `Retiring` key.
A second overlapping rotation, non-`Current` steady-state key, reused
in-process key ID/public key, stale/backdated timeline or overlap shorter than
the 900-second maximum TTL is rejected against a caller-supplied trusted current
time. The issuer also refuses signing before its configured activation time.
The sole issuer must switch to the new private key only after the new public key
is active. Operations must add deployment/clock tolerance beyond the enforced
minimum and keep the old public key until every old token has expired; only then
may `finish_rotation` remove it. `finish_rotation` computes the surviving keys
and validates that exactly one `Current` key remains _before_ mutating, so a
rejected finish leaves the ring byte-for-byte unchanged instead of silently
emptying it. `revoke_key` is the emergency fail-closed path.
Durable key-ID non-reuse across process/configuration lifetimes belongs to the
future key registry and ceremony.

Private key generation, storage and ceremony are deliberately not implemented
or provisioned here. They remain blocked until G4 secret-storage approval.

## Sensitive-data handling

`SensitiveToken` zeroizes its transport string on drop. Token, bounds, issuer
key material and principal-bearing structures either omit `Debug` or redact
sensitive fields. Errors contain only one canonical refusal code
(`auth.tenant_mismatch`, `auth.biscuit_invalid`, `auth.biscuit_revoked`,
`auth.operation_denied`, or `auth.key_unavailable`) and, after verification,
optionally the root block ID. Operational logs may record root block ID,
policy/rule ID, resource/request ID and outcome; they must not record token
bytes, user IDs, tenant IDs, session IDs or private keys.
