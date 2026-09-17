# WP-G2-Z01 reverse adversarial review — rejected candidate

- **Review mode:** `candidate-integration`
- **Review pass ID:** `z01-reverse-adversarial-consolidation-87a802e-01`
- **Reviewed commit:** `87a802eeae20464d7f3de591b170bbea8ad499ff`
- **Base commit:** `8ae8abf8302d30bec4bd6232eb2f7276d5e1fb83`
- **Verdict:** `reject`
- **Production authorization:** none

## Authorities recomputed

| Authority | SHA-256 |
| --- | --- |
| `contracts/authz/authority-v1.datalog` | `eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea` |
| `contracts/authz/sessions-v1.datalog` | `93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1` |
| `contracts/authz/missions-v1.datalog` | `9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be` |

The reviewed worktree was clean and remained unchanged during every pass.

## Role-separated passes

| Pass ID | Role | Harness/model | Pass outcome |
| --- | --- | --- | --- |
| `z01-authz-policy-adversarial-87a802e-01` | `authorization-policy-review` | Claude Code 2.1.212 / Sonnet / high effort | `approve-with-minor-reservations`, superseded by confirmed cross-pass blocker |
| `z01-key-rotation-crypto-adversarial-87a802e-01` | `key-rotation-review` | Codex CLI 0.142.4 / OpenAI `gpt-5.4` / read-only sandbox | `reject` |
| `z01-quality-performance-adversarial-87a802e-01` | candidate quality/performance | Codex CLI 0.142.4 / OpenAI `gpt-5.4` / read-only sandbox | `approve-with-minor-reservations` |
| `z01-reverse-test-adversary-87a802e-01` | adversarial test design | Claude Code 2.1.212 / Sonnet / high effort | `approve-with-minor-reservations` |
| `z01-finding-verifier-token-boundary-87a802e-01` | finding verifier | Claude Code 2.1.212 / Sonnet / high effort | blocker reproduced |
| `z01-finding-verifier-rotation-revocation-87a802e-01` | finding verifier | Codex CLI 0.142.4 / OpenAI `gpt-5.4` / read-only sandbox | `reject` |

## Confirmed findings

### Blocking/major

1. **Mandatory attenuation not verified.** A valid Ed25519 token containing the
   exact authority block but no attenuation block authorized arbitrary
   same-tenant resources for role-allowed operations. A disposable harness
   reproduced the allow twice. Preconditions included access to an active root
   private key, but verifier independence was a locked invariant.
2. **Stale rotation timeline accepted.** `begin_rotation` accepted a new
   `valid_from` and old `valid_until` both already elapsed relative to
   operational time, immediately dropping old-token verification.
3. **Rotation could restart from `Retiring`.** Revoking the new `Current` key
   during overlap left one `Retiring` key; a subsequent `begin_rotation` did not
   require steady-state `Current` status.
4. **Revocation retention caller-controlled.** Public `RevocationRecord` fields
   allowed an expiry shorter than the signed token expiry, enabling premature
   store purge and later replay after cache expiry.

### Minor and test-completeness findings

- Z01 reparsed Biscuit 5.0 printed blocks with direct `biscuit-parser` 0.2.0
  while Biscuit used 0.1.2 internally. No current bypass was reproduced under
  the restricted identifier charset, but the avoidable grammar mismatch was a
  trust-path fragility.
- Named boundaries lacked explicit regressions: divergent
  request/resource-tenant witness, remaining TTL 900/901, cache clock rollback,
  exact rotation overlap, exact key validity, malformed Base64 and
  pre-activation issuance.
- Durable key-ID non-reuse and store-operation timeouts remained correctly
  deferred to future registry/storage adapters.

## Reproduction evidence

```text
cargo test -p libre-ai-authz-biscuit --offline       # 9 passed on target
cargo tree -p libre-ai-authz-biscuit --offline
shasum -a 256 contracts/authz/*.datalog
```

A disposable external Rust harness built an authority-only token with
`biscuit-auth = 5.0.0`, placed the matching public key in the verification ring,
and observed `authorize() -> Ok` for two resources never present in an
attenuation block. No repository file was modified by the harness.

## Required remediation

- validate canonical block 1 independently before policy evaluation;
- align trust-path parsing with Biscuit 5.0's parser grammar;
- bind issuance and rotation to explicit trusted activation/current time;
- require a valid `Current` steady state before rotation;
- derive store records from an opaque verified revocation target;
- add deterministic regressions for every confirmed boundary;
- rerun both specialized review roles on the final immutable remediation SHA.

## Residual risk and verdict

No browser, storage adapter, network capability, real key, user data or
production path existed in the candidate. Those scope controls do not offset
the confirmed verifier and state-machine defects.

**Verdict: `reject`.** This historical result is immutable audit evidence and
must not be reclassified after remediation.
