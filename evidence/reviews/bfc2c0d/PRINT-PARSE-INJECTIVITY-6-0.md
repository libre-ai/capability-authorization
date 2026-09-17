# Print/parse injectivity re-qualification — biscuit-auth 6.0.0 / biscuit-parser 0.2.0

This is an immutable audit record. Do not edit it after creation. It replays the
`fbbe360` reverse-adversarial method (finding A, print/parse non-injectivity)
on the printer/parser pair introduced by the migration commit `bfc2c0d`, and
records which of the pair's new constructs were proved faithful, which were
rejected as a class, and what the remediation commit `deccd92` changed.

## Reviewed commits

- **Migration commit (pair changed, guard unchanged):**
  `bfc2c0d08e8f5b3b459b284c459180337d7024dd`, tree
  `a6f6d11d6dd7c34fc77477e63a0cdf59e770d2fd`
- **Remediation commit (guard extended):**
  `deccd92dc3c66120d88505b31367d4395286894f`, tree
  `55e2be794c1a0442d775d22466057cc517613b9d`
- **Vendoring commit:** `496db81803d34e7d3f1a625f2e1ba24c3449d0b1`
- **Base (`main`):** `5ff4c934b784b25e1eaa82aeb2b15c783c0cb075`
- **Predecessor record (immutable):**
  `evidence/reviews/fbbe360/REVERSE-ADVERSARIAL-REJECT.md` (5.0.0 / 0.1.2)

## The pair under proof

| Component                 | Version | Provenance                                                                                                                |
| ------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `biscuit-auth` (printer)  | 6.0.0   | crates.io archive SHA-256 `d5884fc86b3e21f5649ef4326e17ef729b3096e6502deaf13db7b7fb05bb992b`, vendored with upstream #306 |
| `biscuit-parser` (parser) | 0.2.0   | crates.io archive SHA-256 `9d7cafdbc8c30e1f0fb87df7161bec77f6f00da652cc33f102b0f95bd1cbc0fa`                              |

Printer sources the proof depends on, as vendored (unchanged by #306):

| File                                                       | SHA-256                                                            |
| ---------------------------------------------------------- | ------------------------------------------------------------------ |
| `third_party/biscuit-auth-6.0.0/src/datalog/symbol.rs`     | `19c9df2fe3bb2f9fda210c63f835dd3545eb637ec91ee05713d2aa8017d526d9` |
| `third_party/biscuit-auth-6.0.0/src/datalog/expression.rs` | `6d1f2456fdc8ee1e8745af238218cda6b6b059c709070643e42d7310d5017b52` |
| `third_party/biscuit-auth-6.0.0/src/token/block.rs`        | `baaf62dcf176f60dae0ba76605799d11fe4affebb80fc7dc5b9b977edd27f1d6` |

## Authority hashes (recomputed, unchanged)

| Authority                              | SHA-256                                                            |
| -------------------------------------- | ------------------------------------------------------------------ |
| `vendored/authz/authority-v1.datalog`  | `eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea` |
| `vendored/authz/authority-v2.datalog`  | `f5c0648cf0c2ebf43f73a444ca4df0a84a7349c02d7d0cc31cc86c77daf1db58` |
| `vendored/authz/sessions-v1.datalog`   | `93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1` |
| `vendored/authz/missions-v1.datalog`   | `9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be` |
| `vendored/authz/agent-runs-v1.datalog` | `f20dae7884e49fa00982044a51e99b7f09a5598487bc21f222fcb2d692e3126b` |
| `vendored/authz/agent-runs-v2.datalog` | `de119ba6fe0679793403a66e9b5c29f69a781b53d6eb255e17888c8bb6c2cf37` |

`authority-v1`, `sessions-v1` and `missions-v1` carry the same hashes as in the
`fbbe360` record. No contract changed; the `check:schemas` drift gate stays
green.

## Method

The `fbbe360` method, replayed inside the repository's own test suite instead of
a disposable harness so it stays executable on every future pin bump:

1. Read the printer (`SymbolTable::print_term`, `Expression::print`,
   `Block::print_source`) and the parser (`term`, `term_in_fact`, `term_in_set`,
   `parse_string_internal`, `name`, `set`, `array`, `parse_map`, `binary_op`,
   `extern_*`, closure syntax `->`) of the exact pair, and list every construct
   the printer can emit that the 5.0 / 0.1.2 proof did not model.
2. For each construct, forge a token with the real crate API — a root-key
   holder signing block 1, or a plain holder appending a block 2 that the
   structural validators never inspect — and drive `authorize()` on it.
3. Classify: **faithful** (`parse(print(x)) == x`, asserted on the parsed
   structure), **denied by the guard** (`auth.biscuit_invalid` before any
   structural trust), or **CONFIRMED gap** (accepted although the printed source
   would not be a faithful rendering).

## What datalog 3.3 added to the printer (biscuit-auth 6.0 CHANGELOG)

- sets print as `{a, b}`, the empty set as `{,}` (5.0 printed `[a, b]`);
- `[a, b]` now denotes an **array** (ordered, may repeat), a new `Term::Array`;
- `{k: v}` denotes a **map**, a new `Term::Map` whose string keys print
  unescaped;
- `null` is a new `Term::Null`;
- `==` / `!=` are lenient (heterogeneous) equality, `===` / `!==` strict;
- closures `$p -> expr` print their parameter names as identifiers;
- `.extern::name(...)` prints a function name as an identifier;
- trusted keys in scopes print with an algorithm prefix (`ed25519/<hex>`,
  `secp256r1/<hex>`).

## Findings

### A1 — string channel (`"`, `\`) — **still non-injective, still guarded** (unchanged)

The 6.0 printer still emits `Term::Str` verbatim (`format!("\"{}\"")`,
`symbol.rs`), and parser 0.2.0 still terminates a string at a raw `"` and
treats `\` as an escape introducer; it additionally recognises `\n`, so the two
printed bytes `\` `n` reparse to one newline. The existing guard rule (reject
`"` and `\`) covers the new escape. Regression:
`print_parse_string_injection_channels_fail_closed` (payload list extended with
a `{"read"}` 3.3-syntax payload and a `\n` payload).

### A2 — variable-name channel — **still non-injective, still guarded** (unchanged)

Same printer behaviour (`${name}` verbatim), same parser `name` rule
(`[A-Za-z0-9_:]+`). Regression: `print_parse_variable_name_injection_fails_closed`.

### A3 — every byte in a string term — **property holds**

`every_ascii_byte_in_a_string_term_either_round_trips_or_is_denied`: for each
byte `0x01..=0x7f` and a two-byte UTF-8 sequence, a forged canonical block 1
whose resource string carries the byte either reparses to exactly the decoded
string (126 bytes, including C0 controls, `/`, `;`, `,`, `(`, `{`, `[`, `$`,
`#`, `'`) or is denied by the guard (`"` and `\`, 2 bytes). No third outcome.

### B1 — sets — **faithful, relied upon**

Block 1 of every issued token binds `{operations}` to a `Term::Set`. Printed
`{"read", "propose"}` — members in **symbol-table index order**, not lexical —
and reparsed by 0.2.0 to a `BTreeSet<Term::Str>` equal to the issued set. The
ordering carries no information: set equality is order-insensitive. Regression:
`set_terms_print_and_reparse_faithfully_under_parser_0_2`. (Under parser 0.1.2
this block would not parse at all — `{` was not a term — which is why the parser
had to move with the printer.)

### B2 — empty set `{,}` vs empty map `{}` — **faithful, then rejected by shape**

A forged block 1 with an empty operation set prints `{,}.contains($operation)`.
Parser 0.2.0 tries `parse_map` first, fails on the comma without consuming, then
reads `{,}` as the empty set. The canonical operation check requires a
non-empty set, so the token is denied with `auth.biscuit_invalid`. Regression:
`empty_set_prints_as_brace_comma_and_is_rejected_as_non_canonical`.

### B3 — strict vs lenient equality — **faithful**

`==`, `===`, `!=`, `!==` print from `HeterogeneousEqual`, `Equal`,
`HeterogeneousNotEqual`, `NotEqual` and reparse to the same four variants (the
parser tries `===` before `==`). Regression:
`equality_operators_and_key_scopes_print_and_reparse_faithfully`.

### B4 — key-algorithm prefixes in scopes — **faithful**

A `trusting {k}` scope prints `trusting ed25519/<64 hex>` and reparses to
`Scope::PublicKey { algorithm: Ed25519, key }` with the same bytes. Blocks 0
and 1 reject any scope structurally; a scope in a later block narrows trust and
cannot widen it. Same regression test as B3.

### C — arrays, maps, null, closures, extern calls — **CONFIRMED gap on `bfc2c0d`, closed on `deccd92`**

On `bfc2c0d` the guard's `Term` match ended in `_ => true` and its `Op` match
in `_ => true`. A holder (no root key needed) appended a block 2 containing, in
turn, `check if [1, 2].contains(1);`, `check if {"k": 1} == {"k": 1};`,
`check if null == null;`, `check if [1].any($x -> $x == 1);` and
`check if 1.extern::always();`. **`authorize()` accepted the token** for the
first four (`AuthorizationDecision { matched_policy: 0 }`), and accepted a
block whose closure parameter name and map key embedded the `fbbe360` payload
`x), ["read"].contains($op`. The map-key and closure-parameter channels are
printed verbatim exactly like the string and variable-name channels of finding
A, so they are new differential classes. No escalation was demonstrated
through them — block 2 is never structurally validated, and the checks
evaluate on the binary — but the invariant "the reprinted source of every
signed block is a faithful rendering of the binary" was violated.

**Remediation (`deccd92`):** `term_ok` and a new `op_ok` reject
`Term::Null`, `Term::Array`, `Term::Map`, `Term::Parameter`,
`Op::Closure`, `Op::Unary(Unary::Ffi)` and `Op::Binary(Binary::Ffi)` as a
class, with exhaustive matches so a future variant fails compilation. The
issuer never emits these kinds; their presence in any signed block is
non-canonical and denies with `auth.biscuit_invalid`. This keeps the proof
obligation at the 5.0 set (strings, variables, predicate names) instead of
adding three identifier channels to it. Regressions:
`datalog_3_3_only_terms_in_any_signed_block_fail_closed`,
`closure_parameter_and_map_key_injection_channels_fail_closed`.

### D — guard placement under the split `AuthorizerBuilder` — **order preserved**

6.0 exposes decoded terms only through `Authorizer::dump()`, on a built
authorizer. The guard now runs on `token.authorizer()` — a token-only
authorizer with no ambient fact and no policy, never executed — before
revocation, structural validation and the decision authorizer's construction.
The alternative (dump the decision authorizer) would have run the guard over
the contract policies, whose `[...]` array literals finding C now rejects, and
would have reordered steps 5–10 of `SECURITY.md`.

## Test evidence

| Commit    | `cargo test` (tests/authz.rs) | Notes                                                                                           |
| --------- | ----------------------------- | ----------------------------------------------------------------------------------------------- |
| `5ff4c93` | 20 passed                     | baseline, 5.0.0 / 0.1.2                                                                         |
| `496db81` | does not build                | vendoring only; 8 × E0599 on the 5.0 API, as predicted by the spike                             |
| `bfc2c0d` | 20 passed                     | API migration; the finding-C tests, added afterwards, fail on this tree (2 red: token accepted) |
| `deccd92` | 25 passed                     | guard extended; finding-C tests green                                                           |
| this tree | 26 passed                     | + byte-class property (A3) and the `{"read"}` / `\n` payloads                                   |

## Scope

All changes are confined to this repository. No datalog contract, WIT, schema,
fixture or `libre-ai/contracts` revision was modified. The vendored copy of
`biscuit-auth` differs from the published archive only by the upstream #306
hunks (`third_party/biscuit-auth-6.0.0/PATCH.md`). No browser, network, real
storage, secret, real key, user data, Clever infrastructure or production
enablement is involved. This record does not grant production authorization;
a mutation of this couche-3 crate requires the two-role human review and the
owner's merge.
