# WP-G2-Z01 key rotation review

Status: **APPROVE on code commit `bd7baeb`**
Recorded verdict: [`reviews/bd7baeb/key-rotation-review.md`](reviews/bd7baeb/key-rotation-review.md), SHA-256 `36ab75267ec5506befc290e9e25bb84d6675c526605b39d9b0cc2f0d2141ef35`
Scope correction: [`reviews/bd7baeb/SCOPE-NOTICE.md`](reviews/bd7baeb/SCOPE-NOTICE.md)
Final candidate integration: **APPROVE on evidence-inclusive `22a3bfc`**
Production authorization: **not granted**

## Implemented state machine

- steady state: exactly one `Current` Ed25519 public key;
- overlap: exactly one `Retiring` old key and one `Current` new key;
- a third key or nested rotation is rejected;
- the sole steady-state key must be active `Current`, and caller-supplied
  trusted current time rejects a stale or already expired rotation timeline;
- a new key must have a later `valid_from`, a distinct in-process key ID/public
  key and at least 900 seconds of old/new verification overlap;
- the issuer refuses to sign before its configured `valid_from`;
- key IDs are explicit `u32` selectors and unknown IDs deny;
- `valid_from` and `valid_until` are checked before signature verification;
- emergency key revocation removes the selected verification key immediately;
- public metadata exposes only key ID, Ed25519 algorithm, public-key hex,
  validity and status.

## Required ceremony (G4, not performed)

1. Generate a new Ed25519 key in approved EU-resident secret storage; never
   print or export the private value to GitHub or application configuration.
2. Allocate a never-reused key ID and publish the new public metadata.
3. Deploy the two-key verification ring with `valid_from` set no earlier than
   the trusted current ceremony time and before issuer switch. Set old
   `valid_until` later than switch + 900 seconds + accepted clock/deployment
   tolerance.
4. Confirm both old and new test tokens verify, then atomically switch the sole
   issuer to the new private key.
5. Wait until every old token is expired and all instances observe the new key.
6. Call `finish_rotation`; prove old key IDs deny and new issuance still allows.
7. Retain the ceremony receipt, public metadata and aggregate outcome under the
   future security retention policy. Never retain private key material.

Emergency compromise skips the overlap guarantee: remove the compromised key,
revoke known roots where useful, deploy replacement verification metadata and
accept temporary denial rather than fallback verification.

## Automated evidence

`two_key_rotation_has_a_bounded_overlap` proves:

- old and new tokens verify during overlap;
- exact 900-second overlap is accepted while short overlap, stale/backdated
  activation, third key, reused ID and reused public key are rejected;
- pre-activation issuance, restart from a surviving `Retiring` key and early
  retirement are rejected;
- old key ID fails after retirement;
- the current key still issues and verifies after retirement.

The code does not provision a KMS, secret, environment or Clever Cloud
resource. Those operations remain prohibited before G4.

## Reviewer questions

- Is the enforced 900-second overlap plus the ceremony's additional deployment
  and clock tolerance operationally sufficient?
- Must durable key-ID non-reuse and emergency compromise maintain a separate
  deny list across process restarts or configuration rollback?
- Which independent roles may generate, activate, retire and audit keys?
- What G4 secret backend and backup policy satisfy EU residency and separation
  of duties?

The completed review-only pass bound this file, code commit `bd7baeb`, its tree
and the three unchanged authority hashes under
`docs/reviews/AGENT-REVIEW-PROTOCOL.md`. It approved the positive-only revocation
cache, whole-second TTL handling, transactional rotation completion and the
root-family retention invariants with no blocking or major finding.

Its approval qualifies only the bounded Z01 capability. The report's final
phrase "production-ready" is overbroad assessor prose and is explicitly
non-authoritative; the adjacent scope notice preserves the report bytes while
confirming that production, private-key ceremony, durable adapters and Clever
infrastructure remain blocked until their later gates.
