<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: EUPL-1.2 -->
# Local development

The Rust crate stays at the repository root with its existing package name, public API and version.

The recovery origin and exact incoming file hashes are recorded in `code-recovery-provenance.json`. Original documentation is retained separately from the public project introduction. No historical deployment workflow is activated.

This migration currently composes neighboring repositories through local `file:` dependencies. This component resolves contracts from the neighboring `schemas-and-contracts` repository; no recovery snapshot directory is required. These links are a local composition arrangement, not portable registry releases. Selective package installation and distinct versions must be preserved when distribution references are finalized; do not replace them with dependencies on every package in this repository.

Use the exact Bun toolchain declared in package manifests. Rust crates additionally declare Rust 1.97.0. Review dependency manifests and scripts before installation. `bun run check` runs the available source checks; `cargo test --locked --all-features` runs each Rust crate's tests. Multi-package roots dispatch checks and tests to their packages. SQL integration tests use the testing package's PGlite fixture, not a production database. WebSocket tests require local socket permission.

A successful source check does not imply a deployed service or completed platform qualification. The sandbox's positive Linux confinement and measured Linux coverage remain separate from macOS refusal tests. The evaluator's `check:coverage` enforces the retained Rust line/function thresholds using cargo-llvm-cov 0.9.1. Tool versions and measurement results must accompany any qualification claim.

The six previously consumed Datalog policies remain byte-identical. The additional `build-brief-v2.datalog` is mirrored for inventory consistency and retains its CANDIDATE notice; no runtime API activates it.
