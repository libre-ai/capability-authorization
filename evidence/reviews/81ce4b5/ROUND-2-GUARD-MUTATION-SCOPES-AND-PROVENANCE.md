# Round 2 — guard mutation replay, block scopes, non-injective operators, provenance gate

This is an immutable audit record. Do not edit it after creation. It records the
remediation of the two independent K4 verdicts on the migration candidate
`81ce4b5` (governance `docs/reviews/biscuit-auth-6/81ce4b5/`: security
**accept** with 3 majors, architecture **reject** with 1 blocking and 4 majors —
no double accept) and supersedes `evidence/reviews/bfc2c0d/` for every claim the
two records share. `bfc2c0d/` stays as written: its finding-C statement that
closure and extern rejection were covered by the two named regressions was false
for closures and for binary extern calls (architecture, blocking), and its
"every construct … either faithful or rejected" was false for `&&!`/`||!`,
`try_or` and out-of-range dates (security, major).

## Reviewed and remediation commits

- **Reviewed candidate (round 1):** `81ce4b579d383f8368f06c8f4e6e3765b518225f`
- **Remediation, same branch, new commits:**
  - `09aae8b` — guard: one test per branch, `And`/`Or`/`TryOr`/`LazyAnd`/`LazyOr`
    and out-of-range dates rejected, block-level scopes checked on the
    structure, Ed25519 enforced at the key entry points, double load measured;
  - `8d493c3` — provenance gate for the vendored copy, committed upstream diff,
    `Cargo.toml.orig` tracked, PATCH.md corrected;
  - `bb32056` — `G2-Z01-QUALIFICATION.md` historical banner, README pointer.
- **Superseded record (immutable):** `evidence/reviews/bfc2c0d/PRINT-PARSE-INJECTIVITY-6-0.md`
- **Predecessor record (immutable):** `evidence/reviews/fbbe360/REVERSE-ADVERSARIAL-REJECT.md`

The printer/parser pair, the printer-source hashes and the six authority hashes
are unchanged from the `bfc2c0d` record (biscuit-auth 6.0.0 archive
`d5884fc86b3e21f5649ef4326e17ef729b3096e6502deaf13db7b7fb05bb992b` + upstream
#306; biscuit-parser 0.2.0 `9d7cafdbc8c30e1f0fb87df7161bec77f6f00da652cc33f102b0f95bd1cbc0fa`).

## Method for the guard (blocking finding)

Attribution rule: every forgery lives in **block 2**, which no structural
validator reads, so `auth.biscuit_invalid` can only be produced by the guard;
with the corresponding branch mutated, the token is either accepted or denied by
evaluation with `auth.operation_denied`. One test per branch of `term_ok` /
`op_ok` and per walk of `blocks_roundtrip_safe`, plus one for the structural
scope check. Mutation replay: 26 mutants, each a textual substitution on a
pristine copy of `src/authorize.rs`, the suite (`cargo test --test authz`, 53
tests + 1 ignored) run per mutant, the file restored (`git diff` empty
afterwards). Script and raw logs were produced in the session scratchpad and are
not committed; the table below is their content.

## Mutant → killing test table

| Mutant | Mutation                             | Verdict                   | Killing test(s)                                                                                                                                                                             |
| ------ | ------------------------------------ | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M01    | `Term::Null` → true                  | KILLED                    | `guard_null`, `datalog_3_3_only_terms_in_any_signed_block_fail_closed`                                                                                                                      |
| M02    | `Term::Array` → true                 | KILLED                    | `guard_array`, `datalog_3_3_only_terms…`                                                                                                                                                    |
| M03    | `Term::Map` → true                   | KILLED                    | `guard_map`, `closure_parameter_and_map_key_injection_channels_fail_closed`, `datalog_3_3_only_terms…`                                                                                      |
| M04    | `Op::Unary(Ffi)` → true              | KILLED                    | `guard_unary_extern`, `datalog_3_3_only_terms…`                                                                                                                                             |
| M05    | checks not walked                    | KILLED                    | 19 tests, among them every `guard_*` expression test                                                                                                                                        |
| M06    | rule expressions not walked          | KILLED                    | 18 tests, among them `guard_rule_expression` and every block-2 expression test                                                                                                              |
| M07    | `Op::Closure` → true                 | KILLED                    | `guard_closure` (`{1}.any($x -> true)`: set + `.any`, no array on the path)                                                                                                                 |
| M08    | `Op::Binary(Ffi)` → true             | KILLED                    | `guard_binary_extern`                                                                                                                                                                       |
| M09    | `Term::Set` without member recursion | KILLED                    | `guard_set_member` (`{"a\""}.length() == 1`)                                                                                                                                                |
| M10    | facts not walked                     | KILLED                    | `guard_fact_predicate_name`, `guard_fact_term`                                                                                                                                              |
| M11    | rules not walked                     | KILLED                    | `guard_rule_head_name`, `guard_rule_body_name`, `guard_rule_expression`                                                                                                                     |
| M12    | predicate name unchecked             | KILLED                    | `guard_fact_predicate_name`, `guard_rule_head_name`, `guard_rule_body_name`, `guard_check_body_name`                                                                                        |
| M13    | rule body not walked                 | KILLED                    | `guard_rule_body_name`, `guard_check_body_name`, `guard_variable_name`                                                                                                                      |
| M14    | rule head not walked                 | KILLED                    | `guard_rule_head_name`                                                                                                                                                                      |
| M15    | `Term::Variable` → true              | KILLED                    | `guard_variable_name`                                                                                                                                                                       |
| M16    | `safe_string` without the `\` rule   | KILLED                    | `guard_str_backslash`                                                                                                                                                                       |
| M17    | `safe_string` without the `"` rule   | KILLED                    | `guard_str_quote`, `guard_fact_term`, `guard_rule_expression`, `guard_set_member`                                                                                                           |
| M18    | `Term::Parameter` → true             | SURVIVED — **equivalent** | unreachable: `term_parameter_never_reaches_a_signed_block` proves `Biscuit::append` fails or panics on a fact term or a check expression carrying a parameter, so no signed block holds one |
| M19    | `Binary::And` → true                 | KILLED                    | `guard_strict_and`                                                                                                                                                                          |
| M20    | `Binary::Or` → true                  | KILLED                    | `guard_strict_or`                                                                                                                                                                           |
| M21    | `Binary::TryOr` → true               | KILLED                    | `guard_try_or`                                                                                                                                                                              |
| M22    | `Binary::LazyAnd` → true             | KILLED                    | `guard_lazy_and`                                                                                                                                                                            |
| M23    | `Binary::LazyOr` → true              | KILLED                    | `guard_lazy_or`                                                                                                                                                                             |
| M24    | `Term::Date` range → true            | KILLED                    | `guard_date_range`                                                                                                                                                                          |
| M25    | block-level scope check → true       | KILLED                    | `block_level_scopes_on_blocks_0_and_1_are_rejected_structurally`                                                                                                                            |
| M26    | policies not walked                  | SURVIVED — **equivalent** | a token-only authorizer (`token.authorizer()`) holds no policy; blocks carry facts, rules and checks only                                                                                   |

Round-1 state for comparison (architecture verdict, 28 tests): M07, M08, M09,
M10, M11, M12, M13, M14, M15, M16, M17 survived; M18 survived as equivalent.
Round 2: 24 killed, 2 equivalent, 0 non-equivalent survivor.

The `denied_by_guard` counter of the byte-class property test
(`every_ascii_byte_in_a_string_term_either_round_trips_or_is_denied`) now
measures a block-2 probe `"<payload>" == "<payload>"`: 126 bytes accepted, `"`
and `\` denied by the guard; the faithfulness half (block-1 reprint/reparse of
the same 128 strings) is kept separate: 126 reparse byte-identical, 2 do not.

## Findings remediated

### MAJOR (security) — block-level scopes on blocks 0 and 1 — **CONFIRMED, closed**

`Block::print_source` never prints `block.scopes`, so `parsed.scopes.is_empty()`
at both structural validators was dead code. Red first, root-key holder forging
a canonical block 1 with `BlockBuilder::scope(..)`: `Scope::Previous` →
**ACCEPTED** (policy 0), `Scope::Authority` → **ACCEPTED**, `Scope::PublicKey`
→ denied with the wrong code (`auth.operation_denied`); a block 0 built with
`BiscuitBuilder::scope(Scope::Previous)` → **ACCEPTED**;
`print_block_source(1).contains("trusting") == false` in every case.
Remediation: `canonical_blocks_have_no_block_scope` reads
`token.authorizer()?.snapshot()?.world.blocks[0..2].scope` — the decoded
structure — before revocation; the dead conditions are removed. Test:
`block_level_scopes_on_blocks_0_and_1_are_rejected_structurally` (all four →
`auth.biscuit_invalid`); mutant M25 killed.

### MAJOR (security) — non-injective operators and dates accepted — **CONFIRMED, closed**

Red first on a holder-appended block 2: `[true, true, And]` → **ACCEPTED**
(prints `true &&! true`, reparses `true && !true`); `[false, true, Or]` →
**ACCEPTED**; `[true, false, TryOr]`, `[true, true, LazyAnd]`,
`[false, true, LazyOr]` → denied by evaluation (`auth.operation_denied`), so
fail-closed but not attributed to the guard while their reprint reparses with a
closure the binary never had; `Term::Date(u64::MAX)`, `Term::Date(1 << 63)`,
`Term::Date(253402300800)` in `d == d` → **ACCEPTED** (print as
`1969-12-31T23:59:59Z` or `<invalid date>`). Remediation: `op_ok` rejects
`Binary::And | Or` (no `&&!` token in the parser) and
`Binary::TryOr | LazyAnd | LazyOr` (closure inserted on reparse); `term_ok`
rejects `Term::Date > 253402300799`; the boundary `9999-12-31T23:59:59Z` is
proved faithful (`guard_date_range`). Mutants M19–M24 killed.

The completeness sentence of the `bfc2c0d` record is withdrawn. `SECURITY.md`
now carries the exact lists — proved faithful (strings over `0x01..=0x7f` minus
`"`/`\` and UTF-8, sets and `{,}`, `===`/`!==` vs `==`/`!=`, dates up to
`253402300799`, rule-level trusted-key scopes) and rejected (each with its
test) — and states that anything outside both lists is not claimed either way.

### MAJOR (security) — vendored-copy integrity — **closed** (`8d493c3`)

`scripts/verify-vendored-biscuit-auth.sh`: download of
`https://static.crates.io/crates/biscuit-auth/biscuit-auth-6.0.0.crate`,
SHA-256 checked against the value declared in `PATCH.md`, unpack, `patch -p2`
with the committed `third_party/patches/biscuit-auth-6.0.0-upstream-306.diff`,
`diff -r --exclude=PATCH.md` against the vendored tree. Blocking step of the
`dependency-policy` CI job; locally the same single command. Red first: one
vendored file altered → exit 1, 7 diff lines shown (the alteration and the
lines a Markdown formatter added on the side — exactly the silent-drift class
the gate exists for); restored → exit 0.

### MAJOR (architecture) — `Cargo.toml.orig` — **closed** (`8d493c3`)

Decision: track it (`git add -f`) rather than declare it excluded. The claim
"the whole archive" stays exact and the gate needs no exclusion list; the gate
now fails if the file is ever dropped again. PATCH.md states the force-add and
its reason.

### MAJOR (architecture) — G2-Z01 record promoted as current — **closed** (`bb32056`)

Historical banner dated 2026-09-08 naming the stale statements (5.0.0, 0.1.2,
"no vendored source") and the current locations; README distinguishes the
current record (`evidence/reviews/81ce4b5/`) from immutable history.

### MAJOR (architecture) — orphan `rev` in ecosystem-engine — **closed there**

`ecosystem-engine` `scripts/check-patch-rev.ts` (`bun run check:patch-rev`, in
`check`): every intra-organisation `[patch.crates-io]` git `rev` must compare
`identical` or `behind` against the producer's `main` (GitHub compare API);
`ahead`/`diverged`/unreachable → red. Executed on the current pin
(`81ce4b5`): **FAIL, status `diverged`** — the intended red until the re-pin
that follows the squash-merge of this pull request. Form ratified by governance
ADR-0031.

### MAJOR (architecture) — double-load cost asserted — **closed** (`09aae8b`)

`double_load_cost_is_measured` (`#[ignore]`, 2000 iterations, macOS arm64):
release — token-only authorizer load 13.872 µs, full `authorize()` 127.192 µs,
share 10.9 %; debug — 59.713 µs vs 1.28078 ms, share 4.7 %. The API constraint
(6.0 exposes decoded terms only on a built `Authorizer`) is the reason for the
second load; the order argument is secondary and stated as such in the code
comment.

### MINOR (security) — Ed25519 asserted, not enforced — **closed** (`09aae8b`)

Red first: a `KeyPair::new_with_algorithm(Algorithm::Secp256r1)` was accepted by
`BiscuitIssuer::new`, `VerificationKeyRing::new` and `begin_rotation`, and
`public_keys()` reported it as `"Ed25519"` from a constant. Now refused with
`auth.key_unavailable` at all three entry points; the metadata algorithm is
derived from the key. Test: `non_ed25519_keys_are_refused_at_every_entry_point`.

### MINOR (security) — 3.3 idioms in holder attenuation undocumented — **closed**

`SECURITY.md`, "Issuance and attenuation": holder blocks written with `&&`,
`||`, `.all`/`.any`, `.try_or`, `.get`, `null`, arrays, maps, `&&!`/`||!` or
out-of-range dates are denied as a class; the only accepted holder attenuation
is the crate's own `attenuate()` shape or a hand-built block restricted to
strings, dates, variables, sets and the pre-3.3 operators.

### MINOR — vendored rustc warnings — **recorded, not silenced**

`unused import: crate::crypto::PublicKey` and `parse_any_algorithm is never
used` are recorded in PATCH.md as known upstream dead code under
`default-features = false`; an `#![allow]` in the tree is forbidden by the
provenance gate.

## Not done in this round, and why

- Nested / mixed-type / variable-bearing sets: refused at load by the block
  decoder before the guard; not tested through the guard, stated in
  `SECURITY.md` as out of the claimed lists.
- Operators the security pass probed as faithful (bitwise, arithmetic, set
  algebra, prefix/suffix/regex, length/type, negate/parens, comparisons,
  `i64::MIN/MAX`, bytes): no test written; `SECURITY.md` claims nothing about
  them.
- The two builder panics reachable through `biscuit_auth::builder` directly
  (`Term::Parameter` in a check expression at `append`; malformed key in a
  `trusting` scope string): upstream behaviour, not reachable from
  `authorize()`; recorded here, not changed (the copy stays archive + #306).
- `Authorizer::dump()`'s `unwrap()` on check conversion: pre-existing in 5.0 and
  6.0, unchanged.
- A token issued by a 5.0.0 build authorizing under 6.0.0: not executed (adding
  5.0.0 as a dev-dependency changes the lock); asserted by reading only.

## Scope

All changes are confined to this repository (plus the companion gate in
`ecosystem-engine` and ADR-0031 in `governance`). No datalog contract, WIT,
schema, fixture or `libre-ai/contracts` revision was modified. No browser,
network, real storage, secret, real key, user data, Clever infrastructure or
production enablement is involved. This record does not grant production
authorization; a mutation of this couche-3 crate requires the two-role human
review and the owner's merge.
