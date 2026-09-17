# `libre-ai-authz-biscuit`

Specialized Ed25519 Biscuit issuance, attenuation, verification, revocation and two-key rotation.

Security order is fixed: verify signature and key validity, derive the root authority block ID,
reject non-injective decoded terms, check revocation, require the canonical initial attenuation
block, inject authoritative request facts, then execute a bounded deny-by-default policy.
Tokens and private keys have redacted `Debug` implementations and are never returned in errors.

The browser boundary must never receive this crate's serialized tokens.

Security invariants are in [`SECURITY.md`](SECURITY.md); the current reviewer
evidence is [`evidence/reviews/81ce4b5/`](evidence/reviews/81ce4b5/) (earlier
records under [`evidence/`](evidence/) are immutable history, and
[`G2-Z01-QUALIFICATION.md`](G2-Z01-QUALIFICATION.md) is the hub-era 5.0.0
qualification, kept under a historical banner).
The crate pins the exact `biscuit-auth` 6.0.0 release with default features
disabled, resolved through `[patch.crates-io]` to the vendored copy under
[`third_party/biscuit-auth-6.0.0/`](third_party/biscuit-auth-6.0.0/PATCH.md) —
the published archive plus the upstream fix #306 it needs to compile without
`datalog-macro`, bound to that archive by the provenance gate
`scripts/verify-vendored-biscuit-auth.sh` — and the version-matched
`biscuit-parser` 0.2.0 for the print/parse injectivity guard. The vendored copy
is removed as soon as a published version carries the fix (its `PATCH.md`
states the condition).

## État du projet

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Née verte en γ 3.4 ; six politiques datalog vendorées sous gate de dérive contre le pin contracts.
- Maturité : usable
- Exposition : spec-published
- Confiance : medium
- Preuves vérifiées le : 2026-07-30
- Avancement : 50 % du périmètre actuellement déclaré

<!-- libre-ai:project-status:end -->

La fiche [`project.v1.yaml`](./project.v1.yaml) est l'autorité de l'état du projet ; cette section en est générée et le gate de flotte échoue si elles divergent.
