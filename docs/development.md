<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: EUPL-1.2 -->
# Local development

The Rust crate stays at the repository root with its existing package name, public API and version.

The recovery origin and exact incoming file hashes are recorded in `code-recovery-provenance.json`. Original documentation is retained separately from the public project introduction. No historical deployment workflow is activated.

Use the [shared local composition guide](https://github.com/libre-ai/project-governance/blob/main/docs/LOCAL-COMPOSITION.md) with target `capability-authorization` and the full commit ID to verify. It prepares all pinned sibling sources before ordered installation and builds UI before consumers. Run this component’s commands from its root inside that composition. Packages retain independent names, imports and versions; no registry release is implied.

Use the exact Bun toolchain declared in package manifests. Rust crates additionally declare Rust 1.97.0. Review dependency manifests and scripts before installation. `bun run check` runs the available source checks; `cargo test --locked --all-features` runs each Rust crate's tests. Multi-package roots dispatch checks and tests to their packages. SQL integration tests use the testing package's PGlite fixture, not a production database. WebSocket tests require local socket permission.

A successful source check does not imply a deployed service or completed platform qualification. The sandbox's positive Linux confinement and measured Linux coverage remain separate from macOS refusal tests. The evaluator's `check:coverage` enforces the retained Rust line/function thresholds using cargo-llvm-cov 0.9.1. Tool versions and measurement results must accompany any qualification claim.

The six previously consumed Datalog policies remain byte-identical. The additional `build-brief-v2.datalog` is mirrored for inventory consistency and retains its CANDIDATE notice; no runtime API activates it.
