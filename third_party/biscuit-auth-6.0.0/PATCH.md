# Vendored `biscuit-auth 6.0.0` carrying upstream fix #306

This directory is the complete source of the Apache-2.0 licensed
`biscuit-auth 6.0.0` crate, vendored from the crates.io archive, with one
upstream-merged fix applied on top:

- archive: `https://static.crates.io/crates/biscuit-auth/biscuit-auth-6.0.0.crate`;
- archive SHA-256: `d5884fc86b3e21f5649ef4326e17ef729b3096e6502deaf13db7b7fb05bb992b`
  (equal to the crates.io registry checksum of the release);
- upstream repository: `https://github.com/eclipse-biscuit/biscuit-rust`;
- upstream issue: `eclipse-biscuit/biscuit-rust#305` — "Unresolved import
  `super::ToAnyParam` when feature `datalog-macro` disabled";
- upstream fix: `eclipse-biscuit/biscuit-rust#306` — "fix: feature-gate
  `ToAnyParam` imports", merged as `a6b72596ebe5f391b60e9b91c74edca8febdda93`;
  the diff as applied is committed at
  `third_party/patches/biscuit-auth-6.0.0-upstream-306.diff` (`patch -p2`
  from inside the unpacked archive);
- licence: Apache-2.0, retained verbatim in `LICENSE` and declared for this
  tree in the repository `REUSE.toml`;
- provenance gate: `scripts/verify-vendored-biscuit-auth.sh` — downloads the
  archive, checks the SHA-256 above, applies the committed diff and
  `diff -r`s the result against this tree (only `PATCH.md` may differ). It
  runs in CI (`dependency-policy` job, blocking) and locally with that single
  command; any edit under this directory that is not archive + diff is red.

## Why a vendored copy

`authz-biscuit` builds `biscuit-auth` with `default-features = false`: the
`datalog-macro` feature pulls `biscuit-quote`, which pulls the unmaintained
`proc-macro-error2` family (RUSTSEC-2026-0173). The published `6.0.0` archive
does not compile in that configuration — five builder modules import
`ToAnyParam` unconditionally while the trait only exists behind
`datalog-macro`. Upstream fixed it in #306 after the release; no published
version carries the fix yet. Vendoring the exact release plus that diff keeps
the minimal feature set and the supply-chain reduction it buys, without waiting
on an upstream release (ADR-0020 §2.5 vendoring precedent: `notebook`
`third_party/rustcrypto-aes-0.8.4`).

## The only difference from the archive

The five files below differ from the archive, and only by the hunks of #306:
`ToAnyParam` (and `AnyParam`) imports are moved under
`#[cfg(feature = "datalog-macro")]`, and the `uuid` implementation of
`ToAnyParam` is gated on both `uuid` and `datalog-macro`.

- `src/token/builder/check.rs`
- `src/token/builder/fact.rs`
- `src/token/builder/policy.rs`
- `src/token/builder/rule.rs`
- `src/token/builder/term.rs`

No cryptographic, datalog-evaluation, serialization or token-format source is
touched. Every other file — including `Cargo.toml`, `Cargo.toml.orig`,
`Cargo.lock`, `.cargo_vcs_info.json`, `samples/`, `examples/`, `benches/` and
`tests/` — is byte-identical to the archive, and the provenance gate proves it
on every run. `Cargo.toml.orig` is a file common global gitignores exclude
(`*.orig`); it is tracked here with `git add -f` so the tree stays the whole
archive — the gate fails if it is ever dropped again.

## Known upstream warnings under `default-features = false`

Two rustc warnings are emitted by this crate on every build and are visible in
`cargo clippy` output: `unused import: crate::crypto::PublicKey`
(`src/token/builder.rs`) and `function parse_any_algorithm is never used`
(`src/crypto/mod.rs`). Both are upstream dead code under the reduced feature
set, untouched by #306. They are not denied — `-D warnings` applies to the
workspace member only — and they are **not** silenced here: an `#![allow]` in
this tree would make it archive + #306 + a local edit, which the provenance
gate rejects by design. They disappear with the copy.

`Cargo.toml` at the repository root pins this path through
`[patch.crates-io]`; the dependency line still requires `=6.0.0` so the patch
can only ever substitute the version it was written for.

## Qualification requirements for every update

1. `scripts/verify-vendored-biscuit-auth.sh` (exit 0): re-downloads the
   archive, verifies the SHA-256 above, applies the committed diff and diffs
   this tree against the result — only this file may differ.
2. `cargo build` with the workspace feature set (`default-features = false`).
3. The full repository gates: `cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, `cargo test --locked --all-features`,
   `cargo deny check bans licenses sources`, `reuse lint`, `bun run check`.
4. The print/parse injectivity proof (`SECURITY.md`, `evidence/reviews/`) is
   version-bound: any change to the printer (`src/datalog/symbol.rs`,
   `src/datalog/expression.rs`, `src/token/block.rs`) or to the paired
   `biscuit-parser` version invalidates it and requires a new evidence record.

## Removal condition

Remove this directory and the `[patch.crates-io]` entry as soon as the first
published `biscuit-auth` version that includes #306 is qualified — expected to
be the `7.0.0` line, which also breaks the crypto API (`KeyPair` removed,
tokens generic over the key type) and therefore needs its own qualification,
not a drop-in swap.
