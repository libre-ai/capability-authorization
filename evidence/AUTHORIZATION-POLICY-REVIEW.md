# WP-G2-Z01 authorization policy review

Status: **APPROVE on code commit `bd7baeb`**
Recorded verdict: [`reviews/bd7baeb/authorization-policy-review.md`](reviews/bd7baeb/authorization-policy-review.md), SHA-256 `414a0c22947d917b25a1f2504329854dc5573ec9cac7c2ebe1f99b346e745a93`
Final candidate integration: **APPROVE on evidence-inclusive `22a3bfc`**
Production authorization: **not granted**

## Authorities reviewed by the implementation

| Authority | SHA-256 |
| --- | --- |
| `contracts/authz/authority-v1.datalog` | `eb88b62cd252414bf80089f9be7478475310b3b25d88da528d389a4971e310ea` |
| `contracts/authz/sessions-v1.datalog` | `93bc93e9a4c7b17716787bc9b56df592652b1df0f02d581765cc61010ecaefe1` |
| `contracts/authz/missions-v1.datalog` | `9bfa33eda5e34b8a8d1262881fc951e2455c47769ccaf48d0359bed14a20d2be` |

The contract files are read-only in `Z01`; policy sources are embedded directly
from them. The verifier independently checks the signed authority shape, the
mandatory canonical first attenuation block and the 15-minute maximum remaining
lifetime before executing an authorizer.

## Evidence vectors

| Vector | Expected result |
| --- | --- |
| requester + same tenant + mission read | allow |
| unknown operation | deny |
| missing authority tenant | deny |
| missing authority expiry check | deny |
| canonical signed authority without initial attenuation | deny |
| malformed/non-canonical initial attenuation | deny |
| cross-tenant resource or divergent resource-tenant witness | deny |
| role not recognized by mission policy | deny |
| participant private read without matching ownership | deny |
| participant private read with authoritative ownership | allow |
| expired authority | deny |
| operation added after attenuation | deny |
| resource, tenant or expiry expansion | rejected before serialization |
| holder-appended approver role | deny |
| unknown key ID | deny before policy |
| revoked verified root block | deny before policy |
| unavailable revocation store without fresh cache | deny before policy |
| cache TTL expiry or clock rollback with unavailable store | deny before policy |
| malformed or oversized revocation root ID | reject before store access |
| shorter child attenuation targets the same root family | retain revocation to authority expiry |
| token/principal debug formatting | redacted |

Tests: `crates/authz-biscuit/tests/authz.rs`.

## Final review disposition

The dedicated review-only pass bound code commit `bd7baeb`, its tree and all
three authority hashes. It found no blocking, major or minor issue and approved
the mandatory attenuation shape, print/parse injectivity guard, trusted-origin
role isolation, tenant/resource/operation/expiry bindings, five refusal codes
and deny-by-default policies. The positive-only revocation cache now forces a
store read before every non-revoked acceptance; there is no accepted 30-second
negative-cache window.

Exact resource binding is sufficient for this bounded capability. Any future
worker needing job, source or budget predicates requires a separate contract
and review before integration. The approval grants no production, application,
secret, infrastructure or release authority.
