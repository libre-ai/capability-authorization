# WP-G2-Z01 qualification

> **Historical record (hub era, closed 2026-07).** This document describes the
> crate as qualified at `a6bee98`: `biscuit-auth = 5.0.0`, `biscuit-parser
0.1.2` and "no vendored source". Since the 6.0.0 migration (2026-09-08) those
> statements no longer describe the tree. The current dependency, the vendored
> copy and its provenance gate are documented in
> `third_party/biscuit-auth-6.0.0/PATCH.md`; the current security argument in
> `SECURITY.md`; the current reviewer evidence in `evidence/reviews/81ce4b5/`
> (which supersedes `evidence/reviews/bfc2c0d/`). This file is kept unchanged
> below the banner as the record of the G2-Z01 verdicts.

Status: **complete; merged by PR #101 as `a6bee98`**
Required review passes: `authorization-policy-review` **APPROVE**, `key-rotation-review` **APPROVE**
Final candidate integration: **APPROVE** on evidence-inclusive `22a3bfc`
Production/Clever authorization: **none**

## Delivered boundary

- Ed25519 authority issuance with opaque user/private-tenant/role facts;
- exact resource, operation, tenant and expiry attenuation, independently
  required and shape-validated by the verifier;
- verified-root SHA-256 revocation identifier and opaque verified revocation
  targets retained to root-authority expiry despite shorter child attenuation;
- positive-only bounded revocation cache with fail-closed store errors and no negative-cache acceptance window;
- embedded Sessions/Missions deny-by-default authorizers;
- exact signed-authority shape, issuer activation/TTL enforcement and verifier
  remaining-lifetime bound;
- two-key current/retiring rotation state machine with caller-supplied current
  time, active-state and non-stale timeline checks;
- zeroized/redacted token transport and the five canonical refusal codes;
- adversarial tests and mandatory workspace supply-chain checks.

## Runtime dependency requalification

`WP-G2-T01` remains the sole authority for the root manifest and lockfile. PR
#101 preserved that separation: Z01 code changes stay under
`crates/authz-biscuit/**`, while the exact parser alias and lockfile integration
are isolated in T01 commit `fbbe360`. The resulting workspace pins
`biscuit-auth = 5.0.0` with default features disabled and requalifies that
previously test-only selection for this bounded runtime capability:

- `biscuit-auth` 5.0.0, Apache-2.0, crates.io checksum
  `95490f2c91dc452247d00a2fb4779bcedb7693e669354fa1fe2a96679f4950cc`;
- `biscuit-parser` 0.1.2, Apache-2.0, exposed under the exact
  `biscuit-parser-legacy` workspace alias solely to keep verified block
  print/parse inspection aligned with `biscuit-auth` 5.0.0's internal parser;
- `sha2` 0.11.0 and `zeroize` 1.9.0, already pinned by the workspace.

The Biscuit default feature set is disabled, so the optional Datalog macro,
PEM, WASM, serde-error and full-regex surfaces are absent. The unavoidable
minimal closure includes the same parser 0.1.2 now used by Z01 block inspection
and its bounded standard-regex engine. There is no vendored source, mutable Git dependency,
advisory exception, network call or service SDK. `cargo deny check advisories
licenses sources` remains mandatory. The generated `Cargo.lock` workspace
package entry and parser alias must be integrated under a distinct
`WP-G2-T01`-owned change; they are not part of the Z01 write path.

## Verification commands

```text
cargo test -p libre-ai-authz-biscuit --offline
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check advisories licenses sources
bun run check:contracts
bun run check:work-packages
bun run check
bun test
```

## Final evidence chain

| Evidence                       | Target                                       | Verdict / result                                                                                                                                                                                           |
| ------------------------------ | -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| authorization policy review    | code `bd7baeb`, tree `5ed745d`               | [`APPROVE`](evidence/reviews/bd7baeb/authorization-policy-review.md), SHA-256 `414a0c22947d917b25a1f2504329854dc5573ec9cac7c2ebe1f99b346e745a93`                                                           |
| key rotation/revocation review | code `bd7baeb`, tree `5ed745d`               | [`APPROVE`](evidence/reviews/bd7baeb/key-rotation-review.md), SHA-256 `36ab75267ec5506befc290e9e25bb84d6675c526605b39d9b0cc2f0d2141ef35`; see the [scope notice](evidence/reviews/bd7baeb/SCOPE-NOTICE.md) |
| candidate integration          | evidence-inclusive `22a3bfc`, tree `51a1c5a` | [`APPROVE`](evidence/reviews/22a3bfc/CANDIDATE-INTEGRATION.md), original report SHA-256 `3b58aa38112f81434bd2223e4473ad87bcadbace14e3a76df88c164707026785`                                                 |
| PR required checks             | final head `5b3c220`                         | governance, Bun and Rust `SUCCESS` in run `29637845877`                                                                                                                                                    |
| post-merge checks              | merge `a6bee98`                              | governance, Bun and Rust `SUCCESS` in run `29637997287`                                                                                                                                                    |

The final PR head only adds the non-normative merge of contemporaneous `main`;
the reviewed Z01/T01 scope is byte-identical to `22a3bfc`. Automated success is
evidence, not a substitute for the two specialized verdicts above. Historical
rejects `87a802e` and `fbbe360` remain immutable and are never reclassified.

## Deferred and blocked

- no private key, secret backend, production issuer or infrastructure exists;
- no browser or application integration starts before the dependent packages;
- no Redis/Clever provisioning is performed;
- production remains blocked by the Bun stable qualification and all later G2,
  G3 and G4 gates.
