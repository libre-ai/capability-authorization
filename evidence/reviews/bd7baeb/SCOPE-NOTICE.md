# Scope notice — key rotation review report wording

Applies to: [`key-rotation-review.md`](key-rotation-review.md)
Recorded report SHA-256: `36ab75267ec5506befc290e9e25bb84d6675c526605b39d9b0cc2f0d2141ef35`
Report bytes: **unchanged** — this notice exists so the recorded hash stays valid

## The overbroad phrase

The report's final verdict section ends with the sentence:

> All three fixes are **correct, complete, and verified**. No blocking or major
> issues remain. The candidate is **production-ready**.

The words "production-ready" are assessor prose that exceeds the review's
mandate. The `key-rotation-review` pass was scoped to the three remediation
fixes on code commit `bd7baeb` (positive-only revocation cache, whole-second
TTL enforcement, transactional `finish_rotation`). It carried no authority to
qualify anything for production.

## Authoritative reading

- The verdict that stands is **APPROVE on the bounded Z01 capability at
  `bd7baeb`** — nothing more.
- Production, private-key ceremony, durable storage adapters and Clever
  infrastructure remain **blocked** until their later gates, as stated in
  [`../../KEY-ROTATION-REVIEW.md`](../../KEY-ROTATION-REVIEW.md) and
  [`../../../G2-Z01-QUALIFICATION.md`](../../../G2-Z01-QUALIFICATION.md)
  (`Production/Clever authorization: none`).
- Wherever this report is cited, the phrase "production-ready" is
  non-authoritative and this notice prevails.

## Why the report is not edited

The report was recorded verbatim and its SHA-256 is anchored in the PR #101
review-verdicts comment and in the qualification evidence chain. Rewriting the
report would break that anchor and reclassify recorded evidence. The
correction is therefore made here, adjacent and durable, with the original
bytes preserved.
