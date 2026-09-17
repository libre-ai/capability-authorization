# Round 3 addendum — 2026-09-08

Dated addendum to `ROUND-2-GUARD-MUTATION-SCOPES-AND-PROVENANCE.md`, which
stays as written (immutable record). It records the remediation of the two
independent K4 verdicts on the round-2 candidate `d65e877` (governance
`docs/reviews/biscuit-auth-6/d65e877/`: security **accept** with 1 major and
3 minors, architecture **reject** with 1 blocking, 2 majors and 4 minors) and
the owner decisions of 2026-09-08 that framed this round. Where this addendum
and the round-2 record disagree, this addendum is the current claim.

## Reviewed and remediation commits

- **Reviewed candidate (round 2):** `d65e877f1430b1791955ac29cfafffc50f574176`
- **Remediation, same branch, new commits:**
  - `2812844` — `begin_rotation` Ed25519 refusal reached by the test (blocking);
  - `d763703` — holder-block expressions bound to one operation, no `Parens` (major);
  - `f25c7be` — SECURITY.md: step 5 bounded by its lists, `contains`/`<`/`<=`
    round-trip, three UTF-8 lengths, `.all`/`.any`/`.get` attribution (minors);
  - `61007c5` — guard pass timed in full, three runs, median (minor);
  - this addendum.

The printer/parser pair, the vendored archive, the committed upstream diff and
the six authority hashes are unchanged from the round-2 record
(`git diff d65e877..HEAD -- third_party/ vendored/` is empty).

## What the round-2 record claimed that was not held, and is now

### BLOCKING (architecture) — `begin_rotation` refusal never reached — **closed** (`2812844`)

Round-2 record, §"MINOR (security) — Ed25519 asserted, not enforced":
"refused with `auth.key_unavailable` at all three entry points; test
`non_ed25519_keys_are_refused_at_every_entry_point`". For `begin_rotation`
the test handed a P-256 key with `valid_from = now - 1 s`, refused by
`new_key.valid_from < now` (`keys.rs:87`) before the algorithm term
(`keys.rs:79`) was evaluated; mutant **M28** (the `!is_ed25519(...) ||` term
removed) survived the 53-test suite. That sentence of the record is withdrawn
for `begin_rotation`: the branch was correct by reading and unproved by test.

Now: the rotation probe holds every other precondition (`valid_from = now +
1 s`, later than the current key's; fresh key ID 3; old key valid until `now +
2000 s`, overlap above the 900 s maximum TTL; unused public key) and an
Ed25519 control runs the identical rotation and is accepted, so the algorithm
is the only reason for the refusal. Red first, replayed in this round:

| step                       | result                                              |
| -------------------------- | --------------------------------------------------- |
| M28 applied, round-2 test  | `1 passed` (survival reproduced)                    |
| M28 applied, round-3 test  | `FAILED` — `unwrap_err` on `Ok` at `tests/authz.rs` |
| M28 reverted, round-3 test | `1 passed`                                          |

SECURITY.md's "Trusted inputs" bullet names the test and the precondition
argument; the round-2 commit message `09aae8b` ("Red first … at all three
entry points") is not rewritten, this addendum corrects it.

### MAJOR (security) — compound holder expressions accepted with a divergent reprint — **closed** (`d763703`)

The 6.0 printer emits no parenthesis (only an explicit `Unary::Parens` op
prints `(...)`), so a holder-block expression with two or more operations
reprints as a flat string that parser 0.2.0 reads back under its own
precedence: `[1, 2, Add, 3, Mul]` → `1 + 2 * 3` → `1 + (2 * 3)`;
`[true, false, Equal, Negate]` → `!true === false` → `(!true) === false`;
`[1, 2, LessThan, true, Equal]` → `1 < 2 === true` → no parse. The round-2
record's "CONFIRMED, closed" for the non-injective operator class is
downgraded to "four instances closed" for round 2; the class is closed here.

Owner decision of 2026-09-08: fail-closed guard rather than a shape-by-shape
proof. In a holder block (index ≥ 2) an expression admits **one unary or
binary operation** and **never `Parens`**; blocks 0 and 1 stay held by their
exact op sequences. Implementation: `holder_expressions_carry_at_most_one_operation`
(`src/authorize.rs`) reads the snapshot's proto structure (the only view that
keeps the per-block boundary `dump()` merges away); the snapshot is taken once
and shared with the block-scope check, and a failed `snapshot()` denies.

Interpretation recorded: the decision text says "at most one binary
operation"; the implementation counts unary operations as well (so
`$x.starts_with("a").length()` and `!true === false`, both listed or
demonstrated as divergent, are refused). The narrower reading — one binary
plus any unaries — would have accepted `[true, false, Equal, Negate]`, whose
reprint diverges. This is the stricter of the two readings.

Red first: `guard_holder_expression_with_two_operations` (`1 + 2 * 3`,
`!true === false`, `$x.starts_with("a").length()`, `$x.length() === 4`,
`1 < 2 === true`, `true && true || false`) and
`guard_holder_expression_with_parens` (`(1 + 2) * 3`, `(1)`) were denied by
evaluation with `auth.operation_denied`, i.e. the guard passed them.

Mutants on the new rule (each applied alone, suite run, reverted):

| mutant | mutation                                                         | result | killed by                                             |
| ------ | ---------------------------------------------------------------- | ------ | ----------------------------------------------------- |
| M31    | call to `holder_expressions_carry_at_most_one_operation` removed | killed | both `guard_holder_*` tests (`auth.operation_denied`) |
| M32    | bound `operations <= 1` → `<= 2`                                 | killed | `guard_holder_expression_with_two_operations`         |
| M33    | `Parens` refusal removed                                         | killed | `guard_holder_expression_with_parens` (via `(1)`)     |

Attribution note: `true && true || false` in binary form is refused by the
`LazyAnd`/`LazyOr` rule first (round-2 mutants M22/M23); it is listed for
completeness and its comment says so. The new rule's attribution rests on the
other five two-operation forgeries and the two `Parens` forgeries.

Accepted forms proved: `{"read"}.contains($operation)`, `$time <= <date>`,
`true`, `!false` (`holder_expressions_with_a_single_operation_stay_accepted`).

Not closed by this rule, stated so it is not read as closed: an empty
`Term::Bytes` prints `hex:` (unparsable) and `.all`/`.any`/`.get` in binary
form print `.any(true)` (unparsable) — each is a single-operation expression,
so the new rule passes it; the former is accepted by the guard, the latter are
denied by the evaluator (`auth.operation_denied`). Both are outside the
faithful list and outside the rejected list of SECURITY.md, i.e. "not claimed
either way". No consumer of a block-2 reprint exists in this crate.

### MINORS on SECURITY.md — **closed** (`f25c7be`)

- Step 5 (formerly :30-31, "Reject any token whose decoded terms would not
  survive the pinned print/parse round trip unchanged") is reworded to the
  exact rejected list, and the coverage bound is stated once; the
  contradiction with :149-150 is gone.
- The "proved faithful and relied upon" list gains `{..}.contains($x)` on a
  set and `<`/`<=` between a variable and a date — the two operators the
  canonical block 1 uses — with `set_contains_and_date_comparisons_round_trip`
  (block-2 expression printed, reparsed with biscuit-parser 0.2.0, matched
  against the built op sequence, then accepted).
- "multi-byte UTF-8" is now one sample per encoded length (`é`, `€`, `😀`)
  in `every_ascii_byte_in_a_string_term_either_round_trips_or_is_denied`;
  counts 126 → 128 faithful and accepted, 2 denied unchanged.
- The holder-attenuation paragraph attributes `.all`/`.any`/`.get` in binary
  form to the evaluator, not to step 5 (round-2 record §"MINOR (security) — 3.3
  idioms" said "denied as a class" without that distinction; the conclusion
  holds, the attribution is corrected).

### MINOR (architecture) — double-load figure measured the load only — **closed** (`61007c5`)

The round-2 figure (release 13.872 µs / 127.192 µs, share 10.9 %) timed
`verified.authorizer()` alone, single run. `double_load_cost_is_measured` now
times the whole guard pass — load + `dump()` + `snapshot()` — against the whole
`authorize()`, three runs of 2000 iterations, median:

```
cargo test --release --locked --all-features --test authz double_load_cost_is_measured -- --ignored --nocapture
double-load: guard pass (load + dump + snapshot) runs = [13.251µs, 13.401µs, 22.795µs],
full authorize() runs = [122.68µs, 123.113µs, 125.372µs];
median guard = 13.401µs, median full = 123.113µs, share = 10.9%
```

macOS arm64, this machine. The round-2 sentence "the double load is measured
instead of asserted" is now true of the guard pass, not only of the load. The
same figure is cited in the `authorize()` code comment. The governance verdict
`docs/reviews/biscuit-auth-6/d65e877/architecture.verdict.json` carries the
old figures as its own measurement; no governance note cites them.

## Gates on this round's head

`cargo fmt --all --check`, `cargo clippy --all-targets --all-features -- -D
warnings` (the two recorded upstream warnings only), `cargo test --locked
--all-features` (**57 passed, 1 ignored**; 53 + 1 before this round: 3 new
guard tests, 1 new round-trip test), `cargo deny check`, `cargo audit`, `reuse
lint`, `scripts/verify-vendored-biscuit-auth.sh` — exit codes are in the
pull-request checks and in the round-3 report.

## Not done in this round, and why

- Empty `Term::Bytes` and `.all`/`.any`/`.get` in binary form: outside the
  owner decision's rule; recorded above as not claimed.
- P-256 external keys on third-party blocks (security minor): not in the
  round-3 obligations; unchanged, no escalation was found by the reviewer.
- Governance `docs/reviews/agent-orchestration-contracts-v1/PROMOTION-PACKAGE.md:73`
  still names `biscuit-auth 5.0.0`: that file is a frozen promotion package of
  another dossier in another repository, out of this round's single-repository
  scope; the recommendation carried to the report is to mark the line
  historical there, not to update it.
- Orphan-rev gate parsing (`ecosystem-engine`), ADR-0031 invariants, cargo deny
  duplicate/unmatched-organization warnings, the removal condition of the
  vendored copy: other repositories or owner decisions, unchanged.
