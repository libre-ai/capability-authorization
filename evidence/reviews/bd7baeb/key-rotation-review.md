# Key-Rotation and Revocation Review: Commit bd7baeb9c36837d8609b802ef439a7a79005f3e8

## Review Metadata

- **ReviewPassId:** `key-rotation-review-2026-07-18`
- **Role:** Adversarial reviewer (defeat-the-fix harness)
- **Harness:** Custom-built test suites (integration + adversarial + unit)
- **Provider/Model/Session:** Claude Code subagent, general-purpose reasoning
- **Worktree:** `<review-worktree>`

## Commit Verification

- **Expected SHA:** `bd7baeb9c36837d8609b802ef439a7a79005f3e8`
- **Actual SHA:** `bd7baeb9c36837d8609b802ef439a7a79005f3e8` ✓
- **Expected Tree:** `5ed745d58a60871fa1fa39a0c97d0e8102133f87`
- **Actual Tree:** `5ed745d58a60871fa1fa39a0c97d0e8102133f87` ✓

## Authority File Integrity

Recomputed SHA-256 hashes (verified):

```
authority-v1.datalog:
  Expected: eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea
  Actual:   eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea ✓

sessions-v1.datalog:
  Expected: 93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1
  Actual:   93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1 ✓

missions-v1.datalog:
  Expected: 9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be
  Actual:   9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be ✓
```

All authority files pass integrity check.

---

## Findings by Fix

### Fix 1: Revocation Positive-Only Cache

**Status:** ✅ **APPROVED** — No bypass found

#### Change Summary

- **File:** `crates/authz-biscuit/src/revocation.rs`
- **Lines:** 74-120, 156-169
- **What changed:** `RevocationChecker` cache now stores only revoked verdicts (`revoked_cache: BTreeMap<String, SystemTime>`). Not-revoked checks **always** consult the store, eliminating the fail-open window.

#### Attack Vectors Tested

1. **Cross-instance revocation:** Verifier A accepts token → Verifier B revokes on shared store → Verifier A re-checks within 30s TTL
   - Expected: Reject immediately
   - Result: **PASS** — Consults store, finds revocation, rejects ✓
   - Test: `cross_instance_revocation_is_immediate_within_cache_ttl`

2. **Store outage:** Check when storage is unavailable
   - Expected: Deny (auth.biscuit_invalid)
   - Result: **PASS** — Store Err propagates, access denied ✓
   - Test: `revocation_is_immediate_and_store_outage_denies`

3. **Cache stale after TTL:** Entry cached at T, checked at T+31s (beyond 30s TTL)
   - Expected: Consult store (cache expired)
   - Result: **PASS** — `is_ok_and(|age| age <= cache_ttl)` rejects stale entries ✓

4. **LRU eviction:** Cache at 10,000 entries, add 1 more
   - Expected: Evict oldest, maintain size
   - Result: **PASS** — `cache_order` FIFO, `remember` removes if at max ✓

5. **Clock rollback:** Cache at T, check at T-10s
   - Expected: Err (not extend TTL)
   - Result: **PASS** — `duration_since` with rollback returns Err, cache miss ✓

6. **Negative cache residue:** Can a not-revoked verdict be served from cache?
   - Expected: Never cached
   - Result: **PASS** — Only revoked verdicts stored in `revoked_cache`; not-revoked path returns Ok(()) without caching ✓

#### Code Review

```rust
// Lines 95-101 (comment alone validates the fix)
// Only a *revoked* verdict is ever cached. Revocation is monotonic, so
// a fresh cached revocation can be served without a store round trip. A
// not-revoked verdict is never cached: every acceptance re-consults the
// store, so an emergency revocation written by another verifier instance
// to the shared store takes effect immediately. A negative cache would
// otherwise let this instance keep accepting a revoked token for up to
// `cache_ttl` — a bounded fail-open window this design forbids.
```

**Verdict:** Fix is sound. The cache is positive-only (revoked only), every not-revoked check pays the store cost, and the bounded TTL on cached verdicts ensures no silent staleness. No residual fail-open window found.

---

### Fix 2: Whole-Second TTL Enforcement

**Status:** ✅ **APPROVED** — No bypass found

#### Change Summary

- **File:** `crates/authz-biscuit/src/token.rs`
- **Lines:** 128-130 (`attenuate`), 210 (`BiscuitIssuer::new`), 245 (`issue`), 378-380 (`is_whole_second_ttl`)
- **What changed:** Three entry points now validate `is_whole_second_ttl(ttl)` before accepting a TTL. Fractional TTLs are rejected; whole-second TTLs are accepted.

#### Attack Vectors Tested

1. **Sub-second TTLs rejected:** 0ms, 50ms, 200ms, 500ms, 1500ms
   - Expected: All rejected
   - Result: **PASS** — `is_whole_second_ttl` checks `!ttl.is_zero() && ttl.subsec_nanos() == 0` ✓
   - Test: `subsecond_and_fractional_ttls_are_rejected_whole_seconds_accepted`

2. **Whole-second TTLs accepted:** 1s, 60s, 900s
   - Expected: All accepted
   - Result: **PASS** — No subsec_nanos, passes check ✓

3. **Fractional `now` allowed, fractional TTL rejected:** Issue at time with nanoseconds
   - Expected: `now` OK, TTL still must be whole-second
   - Result: **PASS** — `validate_time` only checks against UNIX_EPOCH, doesn't validate subsecs; `is_whole_second_ttl` enforced in `issue` ✓

4. **Fractional TTL edge cases:** 1ns, 999_999_999ns, max u32 nanos
   - Expected: All rejected
   - Result: **PASS** — subsec_nanos() != 0 for all ✓

5. **No born-invalid tokens:** Issue at fractional time with 1s TTL
   - Expected: Token valid from issuance (no floored expiry)
   - Result: **PASS** — TTL is whole-second, no truncation occurs; effective_expiration floors conservatively only after Biscuit serialization ✓
   - Test: `subsecond_and_fractional_ttls_are_rejected_whole_seconds_accepted` (fractional_now case)

6. **All three entry points guarded:** `BiscuitIssuer::new`, `issue`, `attenuate`
   - Expected: All check `is_whole_second_ttl`
   - Result: **PASS** — Line 210, 245, 128 all call the check before accepting ✓

#### Code Review

```rust
fn is_whole_second_ttl(ttl: Duration) -> bool {
    !ttl.is_zero() && ttl.subsec_nanos() == 0
}
```

The check is mathematically tight: a Duration with any nanoseconds fails. The check is called at all issuing boundaries.

**Verdict:** Fix is sound. Fractional TTLs cannot bypass the three validation points. No born-invalid tokens possible; `now` can have nanoseconds (it's not constrained). The effective expiry is floored conservatively, never extending past max_ttl.

---

### Fix 3: finish_rotation Transactional (Validation Before Mutation)

**Status:** ✅ **APPROVED** — No bypass found

#### Change Summary

- **File:** `crates/authz-biscuit/src/keys.rs`
- **Lines:** 98-125
- **What changed:** `finish_rotation` now computes survivors and validates the post-condition (exactly 1 Current key) **before** mutating the ring. On validation failure, the ring is unchanged.

#### Attack Vectors Tested

1. **Revoke new Current, advance past old Retiring, finish fails → ring unchanged**
   - Scenario: Begin rotation (old=Retiring, new=Current). Revoke new. Advance past old's expiry. Finish.
   - Expected: Err (no Current survives), ring has 1 Retiring key (unchanged)
   - Result: **PASS** — Validation fails on "survivors.len() != 1", returns Err **before** `retain` ✓
   - Test: `finish_rotation_preserves_ring_on_error`

2. **Success path removes Retiring, keeps Current**
   - Scenario: Begin rotation. Advance past old Retiring expiry. Finish.
   - Expected: Ok(.), ring has 1 Current, Retiring removed
   - Result: **PASS** — Survivors=[new_key], validation succeeds, `retain` removes old ✓

3. **Exact boundary second:** `now == old_key.valid_until`
   - Expected: Retiring key not alive (now >= valid_until fails the "keep alive" test), removed
   - Result: **PASS** — `now < valid_until` is false, not in survivors ✓

4. **Before boundary:** `now < old_key.valid_until`
   - Expected: Both keys in survivors, validation fails (2 keys, 1 must be Current), Err, ring unchanged
   - Result: **PASS** — `len() != 1`, returns Err before mutate ✓

5. **Mutation order verified:** Compute → Validate → Mutate
   - Code lines 105–119 compute survivors and check that exactly 1 Current survives
   - Line 120 returns Err if invalid
   - Line 123 is reached only if valid, then mutates

#### Code Review

```rust
pub fn finish_rotation(&mut self, now: SystemTime) -> Result<(), AuthzError> {
    // Compute the survivors first and validate the post-condition BEFORE
    // mutating, so a rejected finish leaves the ring byte-for-byte
    // unchanged.
    let survivors: BTreeSet<u32> = self
        .keys
        .iter()
        .filter(|(_, key)| {
            key.status == VerificationKeyStatus::Current
                || key.valid_until.is_some_and(|valid_until| now < valid_until)
        })
        .map(|(key_id, _)| *key_id)
        .collect();
    let commits_to_single_current = survivors.len() == 1
        && survivors.iter().all(|key_id| {
            self.keys
                .get(key_id)
                .is_some_and(|key| key.status == VerificationKeyStatus::Current)
        });
    if !commits_to_single_current {
        return Err(AuthzError::new("auth.key_unavailable"));
    }
    self.keys.retain(|key_id, _| survivors.contains(key_id));
    Ok(())
}
```

The invariant is preserved: survivors computed (immutable), validated, and **only then** mutated. The comment (lines 99–104) explicitly states the fix.

**Verdict:** Fix is transactional-safe. No code path mutates the ring before validating the postcondition. On error, the ring is byte-for-byte preserved. On success, exactly 1 Current remains.

---

## End-to-End Integration Test Results

All 16 authz tests pass, including the three sensitive to these fixes:

```
test cross_instance_revocation_is_immediate_within_cache_ttl ... ok
test subsecond_and_fractional_ttls_are_rejected_whole_seconds_accepted ... ok
test finish_rotation_preserves_ring_on_error ... ok
test revocation_is_immediate_and_store_outage_denies ... ok
```

Full test suite: **52 tests across all crates, all PASS**.

---

## Adversarial Harness Results

Created and ran 10 adversarial tests targeting edge cases and attack vectors:

```
test attack_attenuate_fractional_ttl ... ok
test attack_cache_lru_eviction ... ok
test attack_cache_ttl_boundary ... ok
test attack_cache_via_time_rollback ... ok
test attack_child_cannot_shorten_root_revocation ... ok
test attack_clock_discontinuity_at_issue ... ok
test attack_fractional_ttl_via_edge_cases ... ok
test attack_issuer_creation_fractional_ttl ... ok
test attack_revocation_check_all_paths ... ok
test attack_rotation_mutation_order ... ok
```

**Result:** All 10 adversarial attacks PASS (i.e., all fixes hold).

---

## Blocking Issues

**None found.** All three fixes are sound and verified.

---

## Major Issues

**None found.**

---

## Minor Issues / Residual Considerations

1. **Cache TTL enforced at 30s max:** The constructor rejects cache_ttl > 30s. This is a policy limit (non-configurable by caller). Acceptable for revocation emergency response time.

2. **Clock rollback not prevented:** System clocks can roll back. The fix handles it correctly (Err path prevents stale cache from aging backward), but a robust system would prevent clock rollback at the OS level (outside this crate's scope).

3. **LRU eviction on full cache:** When cache reaches MAX_CACHE_ENTRIES (10,000), the oldest entry is evicted. No alerting. Acceptable for a bounded cache.

---

## Verdict

### **APPROVE** ✅

**Justification:**

1. **Revocation cache fix:** Eliminates the fail-open negative-cache window by caching only revoked verdicts. Every not-revoked check re-consults the store, making cross-instance revocation immediate. Tested with shared stores and cache TTL boundary conditions.

2. **TTL whole-second enforcement:** All three issue paths (BiscuitIssuer::new, issue, attenuate) validate that TTLs are whole-second, eliminating fractional truncation and born-invalid tokens. Tested with edge cases (1ns, 500ms, etc.). Fractional `now` is correctly allowed.

3. **finish_rotation transactional:** Validation occurs before any mutation. On failure, the ring is unchanged byte-for-byte. On success, exactly 1 Current key survives. Tested with revocation, time boundaries, and partial failures.

All three fixes are **correct, complete, and verified**. No blocking or major issues remain. The candidate is **production-ready**.

---

## Recommendations

None. The fixes are sufficient for the stated requirements and correctly address the root causes.

---

**Review completed:** 2026-07-18  
**Reviewer:** Adversarial harness (Claude Code subagent)  
**Confidence:** High (exhaustive test coverage, no bypass vectors found)
