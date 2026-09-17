# WP-G2-Z01 reverse adversarial review — rejected candidate `fbbe360`

This is an immutable audit record. Do not edit it after creation. It records why
the immutable candidate `fbbe360` was rejected and which findings were confirmed
or refuted by contradictory reproduction before remediation on the successor
commit of the same branch.

## Reviewed commit

- **Reviewed commit:** `fbbe36012222f7d04b992972fcbb51dd3210c1ed`
- **Tree:** `ed3235750eb303f62c70ee237e10a8d2430d1420`
- **Base:** `8ae8abf8302d30bec4bd6232eb2f7276d5e1fb83`
- **Predecessor reject (immutable):** `evidence/reviews/87a802e/REVERSE-ADVERSARIAL-REJECT.md`

## Authority hashes (recomputed, unchanged)

| Authority                              | SHA-256                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| `contracts/authz/authority-v1.datalog` | `eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea` |
| `contracts/authz/sessions-v1.datalog`  | `93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1` |
| `contracts/authz/missions-v1.datalog`  | `9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be` |

The signed Datalog contracts were read-only and are byte-for-byte unchanged from
base through remediation.

## Specialized verdicts on `fbbe360`

| Role                          | Provider / model                       | Verdict                           |
| ----------------------------- | -------------------------------------- | --------------------------------- |
| `authorization-policy-review` | Claude Code / Anthropic Sonnet / high  | `reject`                          |
| `key-rotation-review`         | Codex CLI / OpenAI gpt-5.4 / read-only | `reject`                          |
| `candidate-integration`       | Claude Code / Anthropic Opus / high    | `approve-with-minor-reservations` |

**Global verdict on `fbbe360`: `reject`.**

The historical `87a802e` `reject` remains an immutable audit record and is not
requalified by this pass. No production authorization is granted at any point.

## Findings — contradictory reproduction results

Each alleged finding was reproduced with a disposable harness outside the
repository (never committed), using biscuit-auth 5.0.0 and biscuit-parser 0.1.2,
driving the real crate public API.

### A — print/parse non-injectivity (policy review, alleged Major) — **CONFIRMED**

- `print_block_source` renders `Term::Str`, variable names and predicate names
  verbatim without escaping (`SymbolTable::print_term`, `block::print_source`),
  and biscuit-parser 0.1.2 terminates a string at the first raw `"`, treats `\`
  as an escape and stops an identifier at the first non-identifier byte. So
  `parse(print(x)) != x` for those bytes — confirmed empirically (a two-fact
  reparse of a single poisoned `user(..)` fact).
- **String channel — fail-closed.** A poisoned `Term::Str` carrier reparses to a
  canonical shape but the binary check it belongs to becomes unsatisfiable (the
  giant string can never match a clean ambient fact), so the authorizer denied
  (`auth.operation_denied`). No escalation.
- **Variable-name channel — CONFIRMED bypass (root-key-gated).** A _weak_ binary
  `check if operation($X)` whose variable name embeds `, ["read"].contains($op)`
  reprints as a canonical set-restricted operation check. `validate_initial_attenuation`
  was fooled and `authorize()` **accepted `export`** — an operation outside the
  claimed `["read"]` set, within the role's policy set. The operation attenuation
  invariant that block-1 validation exists to enforce was therefore bypassable by
  a holder of the root key. No cross-role, cross-tenant, cross-resource or
  beyond-role escalation; expiry stays doubly enforced by the lifetime check.

**Remediation:** an injectivity guard (`blocks_roundtrip_safe`, `authorize.rs`)
runs before the structural validation and rejects any decoded `Term::Str`
containing `"`/`\` or any emitted identifier that is not a plain datalog
identifier, making the print/parse round trip faithful. Adversarial regression
tests cover the string and variable-name channels; a resource with `/`, `//`,
`:`, `.`, `-`, `_` still round-trips and is accepted. `SECURITY.md` step 7's
overclaim ("printer and parser use the same pinned grammar") is corrected — the
grammar match does not imply escaping injectivity; the guard now provides it.

### B — negative-cache staleness across verifier instances (rotation review, alleged Blocking) — **CONFIRMED**

- Two `RevocationChecker`s sharing one store: A validated once and cached
  `revoked=false`; B revoked the same root on the shared store; A re-authorized
  within `cache_ttl` and **still accepted** from its fresh negative cache. A
  bounded (≤30 s) cross-instance fail-open window.

**Remediation:** the cache is now positive-only (`revocation.rs`). Only `revoked`
verdicts are cached; every not-revoked check re-consults the store, so a
cross-instance emergency revocation takes effect immediately. Regression test
`cross_instance_revocation_is_immediate_within_cache_ttl`.

### C — sub-second / fractional TTL truncation (rotation review, Minor) — **CONFIRMED**

- `issue()` accepted a 200 ms TTL and silently truncated expiry to whole seconds
  (biscuit `Term::Date` is one-second resolution), which can mint an
  already-expired or unpredictably shortened token.

**Remediation:** issuance, attenuation and issuer construction require a whole,
non-zero number of seconds (`token.rs`, `is_whole_second_ttl`). Real-clock `now`
may still carry nanoseconds and is floored conservatively. Regression test
`subsecond_and_fractional_ttls_are_rejected_whole_seconds_accepted`.

### D — non-transactional `finish_rotation` (integration review, Minor) — **CONFIRMED**

- `finish_rotation` called `retain` (mutation) before validating the
  post-condition; after revoking the new `Current` and advancing past the old
  `Retiring` key's validity, it returned `Err` **and** left the ring emptied.
  Fail-closed, but a silent mutation on the error path.

**Remediation:** `finish_rotation` (`keys.rs`) computes the survivors and
validates exactly one `Current` survivor _before_ mutating, so a rejected finish
preserves the ring byte-for-byte. Regression test
`finish_rotation_preserves_ring_on_error`.

## Scope of remediation

All fixes are confined to `crates/authz-biscuit/**`. No Datalog contract, WIT,
schema, fixture, locked/hashed profile, `Cargo.toml` or `Cargo.lock` was
modified, so no WP-G2-T01 change was required. No browser, network, real
storage, secret, real key, user data, Clever infrastructure or production
enablement is involved. This record does not grant production authorization.
