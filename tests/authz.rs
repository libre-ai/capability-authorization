use biscuit_auth::builder::{BlockBuilder, Term, date, fact, string};
use biscuit_auth::{Biscuit, KeyPair};
use libre_ai_authz_biscuit::{
    AgentRevocationStore, AttenuationRequest, AuthorizationContext, BiscuitIssuer, CanonicalPolicy,
    IssuanceRequest, RevocationChecker, RevocationRecord, RevocationStore,
    RevocationStoreUnavailable, SensitiveToken, VerificationKey, VerificationKeyRing,
    VerificationKeyStatus, authorize,
};
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const USER: &str = "usr_0123456789abcdef";
const OTHER_USER: &str = "usr_fedcba9876543210";
const TENANT: &str = "ten_0123456789abcdef";
const OTHER_TENANT: &str = "ten_fedcba9876543210";
const RESOURCE: &str = "mission:0123456789abcdef";
const AUTHORITY_TEMPLATE: &str = include_str!("../vendored/authz/authority-v1.datalog");

#[derive(Default)]
struct MemoryRevocations {
    revoked: BTreeSet<String>,
    unavailable: bool,
    checks: usize,
    fail_after_checks: Option<usize>,
}

impl RevocationStore for MemoryRevocations {
    fn is_revoked(&mut self, root_block_id: &str) -> Result<bool, RevocationStoreUnavailable> {
        self.checks += 1;
        if self.unavailable
            || self
                .fail_after_checks
                .is_some_and(|allowed| self.checks > allowed)
        {
            return Err(RevocationStoreUnavailable);
        }
        Ok(self.revoked.contains(root_block_id))
    }

    fn revoke(&mut self, record: RevocationRecord) -> Result<(), RevocationStoreUnavailable> {
        if self.unavailable {
            return Err(RevocationStoreUnavailable);
        }
        self.revoked.insert(record.root_block_id().to_owned());
        Ok(())
    }
}

#[derive(Default)]
struct MemoryAgentRevocations {
    revoked: BTreeSet<String>,
    unavailable: bool,
}

impl libre_ai_authz_biscuit::AgentRevocationStore for MemoryAgentRevocations {
    fn is_agent_revoked(&mut self, agent_id: &str) -> Result<bool, RevocationStoreUnavailable> {
        if self.unavailable {
            return Err(RevocationStoreUnavailable);
        }
        Ok(self.revoked.contains(agent_id))
    }

    fn revoke_agent(
        &mut self,
        record: libre_ai_authz_biscuit::AgentRevocationRecord,
    ) -> Result<(), RevocationStoreUnavailable> {
        if self.unavailable {
            return Err(RevocationStoreUnavailable);
        }
        self.revoked.insert(record.agent_id().to_owned());
        Ok(())
    }
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_900_000_000 + seconds)
}

fn operations(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn issuer_and_ring(key_id: u32, now: SystemTime) -> (BiscuitIssuer, VerificationKeyRing) {
    let key_pair = KeyPair::new();
    let public_key = key_pair.public();
    let issuer = BiscuitIssuer::new(
        key_id,
        key_pair,
        Duration::from_secs(900),
        now - Duration::from_secs(1),
    )
    .unwrap();
    let ring = VerificationKeyRing::new(VerificationKey {
        key_id,
        public_key,
        valid_from: now.checked_sub(Duration::from_secs(1)).unwrap(),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    })
    .unwrap();
    (issuer, ring)
}

fn issue(
    issuer: &BiscuitIssuer,
    now: SystemTime,
    role: &str,
    allowed_operations: &[&str],
    ttl: u64,
) -> libre_ai_authz_biscuit::BoundedBiscuit {
    issuer
        .issue(
            IssuanceRequest {
                user_id: USER.to_owned(),
                tenant_id: TENANT.to_owned(),
                role: role.to_owned(),
                resource: RESOURCE.to_owned(),
                operations: operations(allowed_operations),
                ttl: Duration::from_secs(ttl),
            },
            now,
        )
        .unwrap()
}

fn mission_context(now: SystemTime, operation: &str) -> AuthorizationContext {
    AuthorizationContext {
        policy: CanonicalPolicy::Missions,
        resource: RESOURCE.to_owned(),
        operation: operation.to_owned(),
        request_tenant: TENANT.to_owned(),
        resource_tenant: TENANT.to_owned(),
        audience: None,
        contribution_owner_user_id: None,
        now,
    }
}

fn checker() -> RevocationChecker<MemoryRevocations> {
    RevocationChecker::new(MemoryRevocations::default(), Duration::from_secs(30)).unwrap()
}

#[test]
fn minimal_mission_authorization_is_verified_and_deny_by_default() {
    let now = at(0);
    let (issuer, ring) = issuer_and_ring(1, now);
    let token = issue(&issuer, now, "requester", &["read", "propose"], 300)
        .serialize()
        .unwrap();
    let mut revocations = checker();

    let decision = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();
    assert_eq!(decision.principal.user_id, USER);
    assert_eq!(decision.principal.tenant_id, TENANT);
    assert_eq!(decision.principal.role, "requester");
    assert_eq!(decision.root_block_id, token.root_block_id());

    let error = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(2), "delete"),
        &ring,
        &mut revocations,
    )
    .unwrap_err();
    assert_eq!(error.code, "auth.operation_denied");
    assert_eq!(error.root_block_id.as_deref(), Some(token.root_block_id()));

    let wrong_role = issue(&issuer, now, "observer", &["read"], 300)
        .serialize()
        .unwrap();
    assert_eq!(
        authorize(
            &wrong_role.token,
            mission_context(now + Duration::from_secs(2), "read"),
            &ring,
            &mut revocations,
        )
        .unwrap_err()
        .code,
        "auth.operation_denied"
    );
}

#[test]
fn tenant_role_owner_and_expiration_fail_closed() {
    let now = at(100);
    let (issuer, ring) = issuer_and_ring(2, now);
    let token = issue(&issuer, now, "participant", &["read"], 60)
        .serialize()
        .unwrap();
    let mut revocations = checker();

    let mut cross_tenant = mission_context(now + Duration::from_secs(1), "read");
    cross_tenant.policy = CanonicalPolicy::Sessions;
    cross_tenant.audience = Some("private".to_owned());
    cross_tenant.contribution_owner_user_id = Some(USER.to_owned());
    cross_tenant.request_tenant = OTHER_TENANT.to_owned();
    cross_tenant.resource_tenant = OTHER_TENANT.to_owned();
    assert_eq!(
        authorize(&token.token, cross_tenant, &ring, &mut revocations)
            .unwrap_err()
            .code,
        "auth.tenant_mismatch"
    );

    let mut not_owner = mission_context(now + Duration::from_secs(2), "read");
    not_owner.policy = CanonicalPolicy::Sessions;
    not_owner.audience = Some("private".to_owned());
    not_owner.contribution_owner_user_id = Some(OTHER_USER.to_owned());
    assert_eq!(
        authorize(&token.token, not_owner, &ring, &mut revocations)
            .unwrap_err()
            .code,
        "auth.operation_denied"
    );

    let mut owner = mission_context(now + Duration::from_secs(3), "read");
    owner.policy = CanonicalPolicy::Sessions;
    owner.audience = Some("private".to_owned());
    owner.contribution_owner_user_id = Some(USER.to_owned());
    authorize(&token.token, owner, &ring, &mut revocations).unwrap();

    assert_eq!(
        authorize(
            &token.token,
            AuthorizationContext {
                policy: CanonicalPolicy::Sessions,
                resource: RESOURCE.to_owned(),
                operation: "read".to_owned(),
                request_tenant: TENANT.to_owned(),
                resource_tenant: TENANT.to_owned(),
                audience: Some("private".to_owned()),
                contribution_owner_user_id: Some(USER.to_owned()),
                now: now + Duration::from_secs(61),
            },
            &ring,
            &mut revocations,
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

#[test]
fn tenant_witness_lifetime_and_transport_boundaries_fail_closed() {
    let now = at(150);
    let (issuer, ring) = issuer_and_ring(22, now);
    let token = issue(&issuer, now, "requester", &["read"], 900)
        .serialize()
        .unwrap();

    authorize(
        &token.token,
        mission_context(now, "read"),
        &ring,
        &mut checker(),
    )
    .unwrap();
    assert_eq!(
        authorize(
            &token.token,
            mission_context(now - Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );

    let mut divergent_tenant_witness = mission_context(now + Duration::from_secs(1), "read");
    divergent_tenant_witness.resource_tenant = OTHER_TENANT.to_owned();
    let mismatch = authorize(
        &token.token,
        divergent_tenant_witness,
        &ring,
        &mut checker(),
    )
    .unwrap_err();
    assert_eq!(mismatch.code, "auth.tenant_mismatch");
    assert!(mismatch.root_block_id.is_none());

    let malformed = SensitiveToken::from_transport("not-base64".to_owned()).unwrap();
    assert_eq!(
        authorize(
            &malformed,
            mission_context(now, "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

#[test]
fn offline_attenuation_can_only_reduce_authority() {
    let now = at(200);
    let (issuer, ring) = issuer_and_ring(3, now);
    let parent = issue(&issuer, now, "requester", &["read", "propose"], 300);
    let parent_serialized = parent.serialize().unwrap();
    let parent_root = parent_serialized.root_block_id().to_owned();
    let root_family_expires_at = parent_serialized.revocation_target().expires_at();
    assert_eq!(
        parent
            .attenuate(
                AttenuationRequest {
                    tenant_id: TENANT.to_owned(),
                    resource: RESOURCE.to_owned(),
                    operations: operations(&["read"]),
                    ttl: Duration::ZERO,
                },
                now + Duration::from_secs(1),
            )
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );
    let child = parent
        .attenuate(
            AttenuationRequest {
                tenant_id: TENANT.to_owned(),
                resource: RESOURCE.to_owned(),
                operations: operations(&["read"]),
                ttl: Duration::from_secs(120),
            },
            now + Duration::from_secs(1),
        )
        .unwrap();

    assert_eq!(
        child
            .attenuate(
                AttenuationRequest {
                    tenant_id: TENANT.to_owned(),
                    resource: RESOURCE.to_owned(),
                    operations: operations(&["read", "propose"]),
                    ttl: Duration::from_secs(100),
                },
                now + Duration::from_secs(2),
            )
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );
    for request in [
        AttenuationRequest {
            tenant_id: OTHER_TENANT.to_owned(),
            resource: RESOURCE.to_owned(),
            operations: operations(&["read"]),
            ttl: Duration::from_secs(100),
        },
        AttenuationRequest {
            tenant_id: TENANT.to_owned(),
            resource: "mission:fedcba9876543210".to_owned(),
            operations: operations(&["read"]),
            ttl: Duration::from_secs(100),
        },
        AttenuationRequest {
            tenant_id: TENANT.to_owned(),
            resource: RESOURCE.to_owned(),
            operations: operations(&["read"]),
            ttl: Duration::from_secs(300),
        },
    ] {
        assert_eq!(
            parent
                .attenuate(request, now + Duration::from_secs(2))
                .unwrap_err()
                .code,
            "auth.biscuit_invalid"
        );
    }

    let child = child.serialize().unwrap();
    assert_eq!(child.root_block_id(), parent_root);
    assert!(child.expires_at() < child.revocation_target().expires_at());
    assert_eq!(
        child.revocation_target().expires_at(),
        root_family_expires_at
    );
    let mut revocations = checker();
    authorize(
        &child.token,
        mission_context(now + Duration::from_secs(3), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();
    assert_eq!(
        authorize(
            &child.token,
            mission_context(now + Duration::from_secs(4), "propose"),
            &ring,
            &mut revocations,
        )
        .unwrap_err()
        .code,
        "auth.operation_denied"
    );
}

#[test]
fn holder_appended_role_fact_cannot_expand_authority() {
    let now = at(250);
    let (issuer, ring) = issuer_and_ring(31, now);
    let token = issue(&issuer, now, "requester", &["approve"], 300)
        .serialize()
        .unwrap();
    let verified = Biscuit::from_base64(token.token.expose(), issuer.public_key()).unwrap();
    let forged_block = BlockBuilder::new()
        .fact(fact("role", &[string(USER), string("approver")]))
        .unwrap();
    let forged = verified.append(forged_block).unwrap().to_base64().unwrap();
    let forged = SensitiveToken::from_transport(forged).unwrap();

    assert_eq!(
        authorize(
            &forged,
            mission_context(now + Duration::from_secs(1), "approve"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.operation_denied"
    );
}

#[test]
fn revocation_is_immediate_and_store_outage_denies() {
    let now = at(300);
    let (issuer, ring) = issuer_and_ring(4, now);
    let token = issue(&issuer, now, "requester", &["read"], 300)
        .serialize()
        .unwrap();
    let mut revocations = checker();
    let decision = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();

    revocations
        .revoke(
            decision.revocation_target(),
            "session.logout".to_owned(),
            now + Duration::from_secs(2),
        )
        .unwrap();
    let error = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(2), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap_err();
    assert_eq!(error.code, "auth.biscuit_revoked");

    let mut unavailable = RevocationChecker::new(
        MemoryRevocations {
            unavailable: true,
            ..MemoryRevocations::default()
        },
        Duration::from_secs(30),
    )
    .unwrap();
    let error = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(3), "read"),
        &ring,
        &mut unavailable,
    )
    .unwrap_err();
    assert_eq!(error.code, "auth.biscuit_invalid");
}

#[test]
fn two_key_rotation_has_a_bounded_overlap() {
    let now = at(400);
    let (old_issuer, mut ring) = issuer_and_ring(10, now);
    let old_token = issue(&old_issuer, now, "requester", &["read"], 900)
        .serialize()
        .unwrap();

    let mut short_overlap_ring = ring.clone();
    let short_overlap_pair = KeyPair::new();
    assert_eq!(
        short_overlap_ring
            .begin_rotation(
                VerificationKey {
                    key_id: 11,
                    public_key: short_overlap_pair.public(),
                    valid_from: now + Duration::from_secs(10),
                    valid_until: None,
                    status: VerificationKeyStatus::Current,
                },
                now + Duration::from_secs(909),
                now,
            )
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );

    let mut backdated_ring = ring.clone();
    let backdated_pair = KeyPair::new();
    assert_eq!(
        backdated_ring
            .begin_rotation(
                VerificationKey {
                    key_id: 11,
                    public_key: backdated_pair.public(),
                    valid_from: now - Duration::from_secs(2),
                    valid_until: None,
                    status: VerificationKeyStatus::Current,
                },
                now + Duration::from_secs(920),
                now,
            )
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );

    let mut exact_overlap_ring = ring.clone();
    let exact_overlap_pair = KeyPair::new();
    exact_overlap_ring
        .begin_rotation(
            VerificationKey {
                key_id: 11,
                public_key: exact_overlap_pair.public(),
                valid_from: now + Duration::from_secs(10),
                valid_until: None,
                status: VerificationKeyStatus::Current,
            },
            now + Duration::from_secs(910),
            now,
        )
        .unwrap();

    let stale_current_pair = KeyPair::new();
    let mut stale_ring = VerificationKeyRing::new(VerificationKey {
        key_id: 20,
        public_key: stale_current_pair.public(),
        valid_from: now - Duration::from_secs(2_000),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    })
    .unwrap();
    let stale_new_pair = KeyPair::new();
    assert_eq!(
        stale_ring
            .begin_rotation(
                VerificationKey {
                    key_id: 21,
                    public_key: stale_new_pair.public(),
                    valid_from: now - Duration::from_secs(1_000),
                    valid_until: None,
                    status: VerificationKeyStatus::Current,
                },
                now - Duration::from_secs(100),
                now,
            )
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );

    let new_pair = KeyPair::new();
    let new_public = new_pair.public();
    let new_issuer = BiscuitIssuer::new(
        11,
        new_pair,
        Duration::from_secs(900),
        now + Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        new_issuer
            .issue(
                IssuanceRequest {
                    user_id: USER.to_owned(),
                    tenant_id: TENANT.to_owned(),
                    role: "requester".to_owned(),
                    resource: RESOURCE.to_owned(),
                    operations: operations(&["read"]),
                    ttl: Duration::from_secs(300),
                },
                now,
            )
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );
    ring.begin_rotation(
        VerificationKey {
            key_id: 11,
            public_key: new_public,
            valid_from: now + Duration::from_secs(10),
            valid_until: None,
            status: VerificationKeyStatus::Current,
        },
        now + Duration::from_secs(920),
        now,
    )
    .unwrap();
    assert_eq!(ring.public_keys().len(), 2);

    let mut retiring_survivor = ring.clone();
    retiring_survivor.revoke_key(11);
    let replacement_pair = KeyPair::new();
    assert_eq!(
        retiring_survivor
            .begin_rotation(
                VerificationKey {
                    key_id: 12,
                    public_key: replacement_pair.public(),
                    valid_from: now + Duration::from_secs(20),
                    valid_until: None,
                    status: VerificationKeyStatus::Current,
                },
                now + Duration::from_secs(920),
                now + Duration::from_secs(20),
            )
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );

    let new_token = issue(
        &new_issuer,
        now + Duration::from_secs(10),
        "requester",
        &["read"],
        900,
    )
    .serialize()
    .unwrap();
    let mut revocations = checker();
    authorize(
        &new_token.token,
        mission_context(now + Duration::from_secs(10), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();
    authorize(
        &old_token.token,
        mission_context(now + Duration::from_secs(20), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();
    authorize(
        &new_token.token,
        mission_context(now + Duration::from_secs(20), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();

    let third_pair = KeyPair::new();
    assert_eq!(
        ring.begin_rotation(
            VerificationKey {
                key_id: 12,
                public_key: third_pair.public(),
                valid_from: now + Duration::from_secs(20),
                valid_until: None,
                status: VerificationKeyStatus::Current,
            },
            now + Duration::from_secs(930),
            now + Duration::from_secs(20),
        )
        .unwrap_err()
        .code,
        "auth.key_unavailable"
    );
    assert_eq!(
        ring.finish_rotation(now + Duration::from_secs(919))
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );
    ring.finish_rotation(now + Duration::from_secs(920))
        .unwrap();

    assert_eq!(
        authorize(
            &old_token.token,
            mission_context(now + Duration::from_secs(920), "read"),
            &ring,
            &mut revocations,
        )
        .unwrap_err()
        .code,
        "auth.key_unavailable"
    );
    let post_rotation = issue(
        &new_issuer,
        now + Duration::from_secs(920),
        "requester",
        &["read"],
        300,
    )
    .serialize()
    .unwrap();
    authorize(
        &post_rotation.token,
        mission_context(now + Duration::from_secs(921), "read"),
        &ring,
        &mut revocations,
    )
    .unwrap();

    for (key_id, public_key) in [(10, KeyPair::new().public()), (13, new_issuer.public_key())] {
        assert_eq!(
            ring.begin_rotation(
                VerificationKey {
                    key_id,
                    public_key,
                    valid_from: now + Duration::from_secs(922),
                    valid_until: None,
                    status: VerificationKeyStatus::Current,
                },
                now + Duration::from_secs(1_300),
                now + Duration::from_secs(922),
            )
            .unwrap_err()
            .code,
            "auth.key_unavailable"
        );
    }
}

#[test]
fn malformed_signed_authority_without_tenant_or_expiry_is_denied() {
    let now = at(500);
    let key_pair = KeyPair::new();
    let public_key = key_pair.public();
    let ring = VerificationKeyRing::new(VerificationKey {
        key_id: 20,
        public_key,
        valid_from: now - Duration::from_secs(1),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    })
    .unwrap();

    let mut parameters = HashMap::<String, Term>::new();
    parameters.insert("user".to_owned(), USER.into());
    parameters.insert("tenant".to_owned(), TENANT.into());
    parameters.insert("role".to_owned(), "requester".into());
    parameters.insert(
        "expires_at".to_owned(),
        (now + Duration::from_secs(300)).into(),
    );
    let authority_only = Biscuit::builder()
        .root_key_id(20)
        .code_with_params(AUTHORITY_TEMPLATE, parameters, HashMap::new())
        .unwrap()
        .build(&key_pair)
        .unwrap();
    let root_only = authority_only.to_base64().unwrap();
    let empty_attenuation = authority_only
        .append(BlockBuilder::new())
        .unwrap()
        .to_base64()
        .unwrap();
    for malformed in [root_only, empty_attenuation] {
        let malformed = SensitiveToken::from_transport(malformed).unwrap();
        assert_eq!(
            authorize(
                &malformed,
                mission_context(now + Duration::from_secs(1), "export"),
                &ring,
                &mut checker(),
            )
            .unwrap_err()
            .code,
            "auth.biscuit_invalid"
        );
    }

    let without_expiry = Biscuit::builder()
        .root_key_id(20)
        .fact(fact("user", &[string(USER)]))
        .unwrap()
        .fact(fact("tenant", &[string(TENANT)]))
        .unwrap()
        .fact(fact("role", &[string(USER), string("requester")]))
        .unwrap()
        .build(&key_pair)
        .unwrap();

    let without_tenant = Biscuit::builder()
        .root_key_id(20)
        .fact(fact("user", &[string(USER)]))
        .unwrap()
        .fact(fact("role", &[string(USER), string("requester")]))
        .unwrap()
        .fact(fact(
            "expires_at",
            &[date(&(now + Duration::from_secs(300)))],
        ))
        .unwrap()
        .build(&key_pair)
        .unwrap();

    for malformed in [without_expiry, without_tenant] {
        let token = SensitiveToken::from_transport(malformed.to_base64().unwrap()).unwrap();
        let mut revocations = checker();
        assert_eq!(
            authorize(
                &token,
                mission_context(now + Duration::from_secs(1), "read"),
                &ring,
                &mut revocations,
            )
            .unwrap_err()
            .code,
            "auth.biscuit_invalid"
        );
    }
}

#[test]
fn session_audience_is_required_and_debug_output_is_redacted() {
    let now = at(600);
    let (issuer, ring) = issuer_and_ring(30, now);
    let token = issue(&issuer, now, "participant", &["read"], 300)
        .serialize()
        .unwrap();
    let mut context = mission_context(now + Duration::from_secs(1), "read");
    context.policy = CanonicalPolicy::Sessions;
    context.resource = RESOURCE.to_owned();
    let mut revocations = checker();
    assert_eq!(
        authorize(&token.token, context.clone(), &ring, &mut revocations)
            .unwrap_err()
            .code,
        "auth.operation_denied"
    );
    context.audience = Some("session".to_owned());
    let decision = authorize(&token.token, context, &ring, &mut revocations).unwrap();

    let token_debug = format!("{:?}", token.token);
    let decision_debug = format!("{decision:?}");
    let issuer_debug = format!("{issuer:?}");
    for debug in [&token_debug, &decision_debug, &issuer_debug] {
        assert!(!debug.contains(USER));
        assert!(!debug.contains(TENANT));
        assert!(!debug.contains(token.token.expose()));
    }
    assert_eq!(token.root_block_id().len(), 64);
}

#[test]
fn cache_ttl_and_input_bounds_are_enforced() {
    // biscuit-auth 6.0 keys are algorithm-tagged (Ed25519 or P-256); every
    // key entry point of this crate refuses a non-Ed25519 key
    // (`non_ed25519_keys_are_refused_at_every_entry_point`).
    assert_eq!(
        RevocationChecker::new(MemoryRevocations::default(), Duration::from_secs(31))
            .err()
            .unwrap()
            .code,
        "auth.biscuit_invalid"
    );
    assert_eq!(
        SensitiveToken::from_transport("x".repeat(16_385))
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );
    assert_eq!(
        SensitiveToken::from_transport(String::new())
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );
    assert_eq!(
        BiscuitIssuer::new(39, KeyPair::new(), Duration::from_secs(901), UNIX_EPOCH,)
            .err()
            .unwrap()
            .code,
        "auth.biscuit_invalid"
    );

    let now = at(700);
    let mut revocations = checker();
    assert_eq!(
        revocations
            .check(&"a".repeat(16_385), now)
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );

    // Positive-only cache: a not-revoked verdict is never cached, so every
    // check re-consults the store within the same TTL window (no negative
    // cache to serve a stale accept). A store that starts failing after the
    // first check therefore makes the very next check fail closed.
    let root_block_id = "b".repeat(64);
    let mut positive_only = RevocationChecker::new(
        MemoryRevocations {
            fail_after_checks: Some(1),
            ..MemoryRevocations::default()
        },
        Duration::from_secs(30),
    )
    .unwrap();
    positive_only.check(&root_block_id, now).unwrap();
    for consult_now in [
        now,
        now + Duration::from_secs(1),
        now + Duration::from_secs(30),
    ] {
        assert_eq!(
            positive_only
                .check(&root_block_id, consult_now)
                .unwrap_err()
                .code,
            "auth.biscuit_invalid"
        );
    }

    let (issuer, ring) = issuer_and_ring(40, now);
    let bounded_target = issue(&issuer, now, "requester", &["read"], 900)
        .serialize()
        .unwrap();
    for invalid_now in [now - Duration::from_secs(1), now + Duration::from_secs(901)] {
        assert_eq!(
            revocations
                .revoke(
                    bounded_target.revocation_target(),
                    "test.invalid-retention".to_owned(),
                    invalid_now,
                )
                .unwrap_err()
                .code,
            "auth.biscuit_invalid"
        );
    }
    let mut exact_retention = checker();
    exact_retention
        .revoke(
            bounded_target.revocation_target(),
            "test.exact-retention".to_owned(),
            now,
        )
        .unwrap();
    assert!(
        exact_retention
            .into_store()
            .revoked
            .contains(bounded_target.root_block_id())
    );
    assert_eq!(
        issuer
            .issue(
                IssuanceRequest {
                    user_id: USER.to_owned(),
                    tenant_id: TENANT.to_owned(),
                    role: "requester".to_owned(),
                    resource: RESOURCE.to_owned(),
                    operations: operations(&["read"]),
                    ttl: Duration::from_secs(901),
                },
                now,
            )
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );
    assert_eq!(
        issuer
            .issue(
                IssuanceRequest {
                    user_id: USER.to_owned(),
                    tenant_id: "public".to_owned(),
                    role: "requester".to_owned(),
                    resource: RESOURCE.to_owned(),
                    operations: operations(&["read"]),
                    ttl: Duration::from_secs(60),
                },
                now,
            )
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );

    assert_eq!(
        issuer
            .issue(
                IssuanceRequest {
                    user_id: USER.to_owned(),
                    tenant_id: TENANT.to_owned(),
                    role: "requester".to_owned(),
                    resource: "mission/INVALID".to_owned(),
                    operations: operations(&["read"]),
                    ttl: Duration::from_secs(60),
                },
                now,
            )
            .unwrap_err()
            .code,
        "auth.biscuit_invalid"
    );

    let (unknown_issuer, _) = issuer_and_ring(41, now);
    let unknown_key_token = issue(&unknown_issuer, now, "requester", &["read"], 60)
        .serialize()
        .unwrap();
    assert_eq!(
        authorize(
            &unknown_key_token.token,
            mission_context(now + Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.key_unavailable"
    );

    let valid = issue(&issuer, now, "requester", &["read"], 60)
        .serialize()
        .unwrap();
    let mut tampered = valid.token.expose().as_bytes().to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
    let tampered = SensitiveToken::from_transport(String::from_utf8(tampered).unwrap()).unwrap();
    assert_eq!(
        authorize(
            &tampered,
            mission_context(now + Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

// --- Print/parse injectivity guard: adversarial regressions (finding A) ------

fn authority_only(kp: &KeyPair, key_id: u32, expiry: SystemTime, role: &str) -> Biscuit {
    let mut params = HashMap::<String, Term>::new();
    params.insert("user".to_owned(), string(USER));
    params.insert("tenant".to_owned(), string(TENANT));
    params.insert("role".to_owned(), string(role));
    params.insert("expires_at".to_owned(), Term::from(expiry));
    Biscuit::builder()
        .root_key_id(key_id)
        .code_with_params(AUTHORITY_TEMPLATE, params, HashMap::new())
        .unwrap()
        .build(kp)
        .unwrap()
}

fn ring_for(
    key_id: u32,
    public_key: biscuit_auth::PublicKey,
    now: SystemTime,
) -> VerificationKeyRing {
    VerificationKeyRing::new(VerificationKey {
        key_id,
        public_key,
        valid_from: now - Duration::from_secs(1),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    })
    .unwrap()
}

#[test]
fn print_parse_string_injection_channels_fail_closed() {
    // A holder of the root key forges block 1 as a single real check
    // `check if resource(<payload>)` whose Term::Str embeds quotes, backslashes,
    // comments, semicolons and a closing-string sequence. Unescaped printing
    // would let the reprinted source reparse to a canonical 4-check shape, but
    // the round-trip guard rejects the decoded poisoned string first.
    let now = at(800);
    let expiry = now + Duration::from_secs(300);
    let kp = KeyPair::new();
    let ring = ring_for(60, kp.public(), now);
    for payload in [
        format!("{RESOURCE}\"); check if operation($o), [\"read\"].contains($o); //"),
        format!("{RESOURCE}\"); check if operation($o), {{\"read\"}}.contains($o); //"),
        format!("{RESOURCE}\\evil"),
        // `\n` is an escape sequence for parser 0.2.0: the two printed bytes
        // reparse to one newline, so the string is not a fixed point either.
        format!("{RESOURCE}\\n"),
        format!("{RESOURCE}\"); check if tenant(\"{TENANT}\"); //"),
    ] {
        let mut params = HashMap::<String, Term>::new();
        params.insert("p".to_owned(), Term::Str(payload));
        let block = BlockBuilder::new()
            .code_with_params("check if resource({p});", params, HashMap::new())
            .unwrap();
        let forged = authority_only(&kp, 60, expiry, "requester")
            .append(block)
            .unwrap();
        let token = SensitiveToken::from_transport(forged.to_base64().unwrap()).unwrap();
        assert_eq!(
            authorize(
                &token,
                mission_context(now + Duration::from_secs(1), "read"),
                &ring,
                &mut checker(),
            )
            .unwrap_err()
            .code,
            "auth.biscuit_invalid"
        );
    }
}

#[test]
fn print_parse_variable_name_injection_fails_closed() {
    use biscuit_auth::builder::{Check, CheckKind, Predicate, Rule};
    // The confirmed exploit: a WEAK binary operation check `check if operation($X)`
    // whose variable NAME injects `, ["read"].contains($op)` so the reprinted
    // source reparses to a canonical set-restricted op check. Without the guard,
    // authorize() accepted "export" (outside the claimed ["read"]). The guard
    // now rejects the non-identifier variable name before any structural trust.
    let now = at(810);
    let expiry = now + Duration::from_secs(300);
    let kp = KeyPair::new();
    let ring = ring_for(61, kp.public(), now);
    let op_check = Check {
        queries: vec![Rule {
            head: Predicate {
                name: "query".to_owned(),
                terms: vec![],
            },
            body: vec![Predicate {
                name: "operation".to_owned(),
                terms: vec![Term::Variable("op), [\"read\"].contains($op".to_owned())],
            }],
            expressions: vec![],
            parameters: None,
            scopes: vec![],
            scope_parameters: None,
        }],
        kind: CheckKind::One,
    };
    let mut resource_param = HashMap::<String, Term>::new();
    resource_param.insert("resource".to_owned(), string(RESOURCE));
    let mut tail = HashMap::<String, Term>::new();
    tail.insert("tenant".to_owned(), string(TENANT));
    tail.insert("expires_at".to_owned(), Term::from(expiry));
    let block = BlockBuilder::new()
        .code_with_params(
            "check if resource({resource});",
            resource_param,
            HashMap::new(),
        )
        .unwrap()
        .check(op_check)
        .unwrap()
        .code_with_params(
            "check if tenant({tenant});\ncheck if time($time), $time < {expires_at};",
            tail,
            HashMap::new(),
        )
        .unwrap();
    let forged = authority_only(&kp, 61, expiry, "requester")
        .append(block)
        .unwrap();
    let token = SensitiveToken::from_transport(forged.to_base64().unwrap()).unwrap();
    assert_eq!(
        authorize(
            &token,
            mission_context(now + Duration::from_secs(1), "export"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

#[test]
fn resources_with_slashes_still_authorize() {
    // The guard rejects only the round-trip-unsafe bytes " and \. A resource
    // carrying '/', '//', ':', '.', '-', '_' round-trips faithfully and is
    // accepted, so the guard does not false-reject legitimate resources.
    let now = at(820);
    let (issuer, ring) = issuer_and_ring(62, now);
    let resource = "mission:a//b.c-d_e";
    let token = issuer
        .issue(
            IssuanceRequest {
                user_id: USER.to_owned(),
                tenant_id: TENANT.to_owned(),
                role: "requester".to_owned(),
                resource: resource.to_owned(),
                operations: operations(&["read"]),
                ttl: Duration::from_secs(300),
            },
            now,
        )
        .unwrap()
        .serialize()
        .unwrap();
    let mut context = mission_context(now + Duration::from_secs(1), "read");
    context.resource = resource.to_owned();
    authorize(&token.token, context, &ring, &mut checker()).unwrap();
}

// --- Cross-instance revocation is immediate (finding B) ----------------------

#[derive(Clone, Default)]
struct SharedRevocations {
    inner: std::sync::Arc<std::sync::Mutex<BTreeSet<String>>>,
}

impl RevocationStore for SharedRevocations {
    fn is_revoked(&mut self, root_block_id: &str) -> Result<bool, RevocationStoreUnavailable> {
        Ok(self.inner.lock().unwrap().contains(root_block_id))
    }
    fn revoke(&mut self, record: RevocationRecord) -> Result<(), RevocationStoreUnavailable> {
        self.inner
            .lock()
            .unwrap()
            .insert(record.root_block_id().to_owned());
        Ok(())
    }
}

#[test]
fn cross_instance_revocation_is_immediate_within_cache_ttl() {
    let now = at(830);
    let (issuer, ring) = issuer_and_ring(63, now);
    let token = issue(&issuer, now, "requester", &["read"], 300)
        .serialize()
        .unwrap();
    let shared = SharedRevocations::default();
    let mut checker_a = RevocationChecker::new(shared.clone(), Duration::from_secs(30)).unwrap();
    let mut checker_b = RevocationChecker::new(shared.clone(), Duration::from_secs(30)).unwrap();

    // Verifier A accepts once. With a negative cache this would poison A for up
    // to 30 s; the positive-only cache leaves nothing to serve stale.
    let decision = authorize(
        &token.token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut checker_a,
    )
    .unwrap();

    // Verifier B performs the emergency revocation on the shared store.
    checker_b
        .revoke(
            decision.revocation_target(),
            "emergency.logout".to_owned(),
            now + Duration::from_secs(2),
        )
        .unwrap();

    // Verifier A must fail closed immediately, well inside the cache TTL.
    assert_eq!(
        authorize(
            &token.token,
            mission_context(now + Duration::from_secs(3), "read"),
            &ring,
            &mut checker_a,
        )
        .unwrap_err()
        .code,
        "auth.biscuit_revoked"
    );
}

// --- Whole-second TTL enforcement (finding C) --------------------------------

#[test]
fn subsecond_and_fractional_ttls_are_rejected_whole_seconds_accepted() {
    let now = at(850);
    let (issuer, ring) = issuer_and_ring(64, now);
    for bad in [
        Duration::ZERO,
        Duration::from_millis(50),
        Duration::from_millis(200),
        Duration::from_millis(1_500),
    ] {
        assert_eq!(
            issuer
                .issue(
                    IssuanceRequest {
                        user_id: USER.to_owned(),
                        tenant_id: TENANT.to_owned(),
                        role: "requester".to_owned(),
                        resource: RESOURCE.to_owned(),
                        operations: operations(&["read"]),
                        ttl: bad,
                    },
                    now,
                )
                .unwrap_err()
                .code,
            "auth.biscuit_invalid"
        );
    }

    // A whole-second TTL issued at a fractional real-clock `now` is accepted and
    // authorizes at issue time (no born-invalid truncation).
    let fractional_now = now + Duration::from_millis(900);
    let token = issuer
        .issue(
            IssuanceRequest {
                user_id: USER.to_owned(),
                tenant_id: TENANT.to_owned(),
                role: "requester".to_owned(),
                resource: RESOURCE.to_owned(),
                operations: operations(&["read"]),
                ttl: Duration::from_secs(1),
            },
            fractional_now,
        )
        .unwrap()
        .serialize()
        .unwrap();
    authorize(
        &token.token,
        mission_context(fractional_now, "read"),
        &ring,
        &mut checker(),
    )
    .unwrap();
}

// --- Transactional finish_rotation (finding D) -------------------------------

#[test]
fn finish_rotation_preserves_ring_on_error() {
    let now = at(860);
    let current = KeyPair::new();
    let mut ring = VerificationKeyRing::new(VerificationKey {
        key_id: 1,
        public_key: current.public(),
        valid_from: now - Duration::from_secs(1),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    })
    .unwrap();
    let next = KeyPair::new();
    ring.begin_rotation(
        VerificationKey {
            key_id: 2,
            public_key: next.public(),
            valid_from: now + Duration::from_secs(10),
            valid_until: None,
            status: VerificationKeyStatus::Current,
        },
        now + Duration::from_secs(920),
        now,
    )
    .unwrap();

    // Revoke the new Current, leaving one Retiring key, then advance past its
    // validity. finish_rotation must Err WITHOUT emptying the ring.
    ring.revoke_key(2);
    assert_eq!(ring.public_keys().len(), 1);
    assert_eq!(
        ring.finish_rotation(now + Duration::from_secs(921))
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );
    assert_eq!(
        ring.public_keys().len(),
        1,
        "the ring must be preserved on a rejected finish_rotation"
    );
    assert_eq!(
        ring.public_keys()[0].status,
        VerificationKeyStatus::Retiring
    );
}

// Part b1: the issuer mints agent-fleet tokens carrying the K1 identity facts,
// and the agent-runs-v2 authorizer enforces the fleet boundary end-to-end.
#[test]
fn agent_token_carries_k1_facts_and_agent_runs_v2_denies_cross_fleet() {
    use biscuit_auth::builder::{date, fact, string};
    use biscuit_auth::datalog::RunLimits;

    let now = at(0);
    let (issuer, _ring) = issuer_and_ring(1, now);
    let public_key = issuer.public_key();
    let serialized = issuer
        .issue_agent(
            IssuanceRequest {
                user_id: USER.to_owned(),
                tenant_id: TENANT.to_owned(),
                role: "author-agent".to_owned(),
                resource: RESOURCE.to_owned(),
                operations: operations(&["submit-plan"]),
                ttl: Duration::from_secs(300),
            },
            libre_ai_authz_biscuit::AgentIdentity {
                fleet: "forge".to_owned(),
                mission: "mission-alpha".to_owned(),
                capability: "invoke-planned-tool".to_owned(),
            },
            now,
            &mut MemoryAgentRevocations::default(),
        )
        .unwrap()
        .serialize()
        .unwrap();
    let policy = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("vendored/authz/agent-runs-v2.datalog"),
    )
    .unwrap();

    let authorizes = |resource_fleet: &str| -> bool {
        let biscuit = Biscuit::from_base64(serialized.token.expose(), public_key).unwrap();
        let mut builder = biscuit_auth::AuthorizerBuilder::new();
        for injected in [
            fact("time", &[date(&(now + Duration::from_secs(1)))]),
            fact("resource", &[string(RESOURCE)]),
            fact("operation", &[string("submit-plan")]),
            fact("resource_tenant", &[string(TENANT)]),
            fact("resource_fleet", &[string(resource_fleet)]),
            fact("resource_mission", &[string("mission-alpha")]),
            fact("subject_type", &[string("execution-plan")]),
        ] {
            builder = builder.fact(injected).unwrap();
        }
        let mut authorizer = builder
            .code(policy.as_str())
            .unwrap()
            .build(&biscuit)
            .unwrap();
        authorizer
            .authorize_with_limits(RunLimits {
                max_facts: 256,
                max_iterations: 32,
                max_time: Duration::from_millis(50),
            })
            .is_ok()
    };

    assert!(
        authorizes("forge"),
        "an agent token whose fleet matches the resource must authorize"
    );
    assert!(
        !authorizes("product-ops"),
        "a cross-fleet agent token must be denied by agent-runs-v2"
    );
}

// Part b1: issue_agent rejects a malformed agent identity (grammar proof).
#[test]
fn issue_agent_rejects_malformed_identity() {
    let now = at(0);
    let (issuer, _ring) = issuer_and_ring(1, now);
    let base = || IssuanceRequest {
        user_id: USER.to_owned(),
        tenant_id: TENANT.to_owned(),
        role: "author-agent".to_owned(),
        resource: RESOURCE.to_owned(),
        operations: operations(&["submit-plan"]),
        ttl: Duration::from_secs(300),
    };
    let agent =
        |fleet: &str, mission: &str, capability: &str| libre_ai_authz_biscuit::AgentIdentity {
            fleet: fleet.to_owned(),
            mission: mission.to_owned(),
            capability: capability.to_owned(),
        };
    for (fleet, mission, capability) in [
        ("Forge", "mission-alpha", "invoke-planned-tool"), // uppercase start
        ("forge", "x", "invoke-planned-tool"),             // too short
        ("forge\") allow if true; //", "mission-alpha", "cap"), // datalog metachars
        ("forge", "mission_alpha", "cap"),                 // underscore forbidden
    ] {
        assert_eq!(
            issuer
                .issue_agent(
                    base(),
                    agent(fleet, mission, capability),
                    now,
                    &mut MemoryAgentRevocations::default(),
                )
                .unwrap_err()
                .code,
            "auth.biscuit_invalid",
        );
    }
    assert!(
        issuer
            .issue_agent(
                base(),
                agent("forge", "mission-alpha", "invoke-planned-tool"),
                now,
                &mut MemoryAgentRevocations::default(),
            )
            .is_ok()
    );
}

// Part b1/revocation: issue_agent is fail-closed on per-agent revocation.
#[test]
fn issue_agent_is_fail_closed_on_agent_revocation() {
    let now = at(0);
    let (issuer, _ring) = issuer_and_ring(1, now);
    let request = || IssuanceRequest {
        user_id: USER.to_owned(),
        tenant_id: TENANT.to_owned(),
        role: "author-agent".to_owned(),
        resource: RESOURCE.to_owned(),
        operations: operations(&["submit-plan"]),
        ttl: Duration::from_secs(300),
    };
    let identity = || libre_ai_authz_biscuit::AgentIdentity {
        fleet: "forge".to_owned(),
        mission: "mission-alpha".to_owned(),
        capability: "invoke-planned-tool".to_owned(),
    };

    // A healthy store with no revocation mints normally.
    let mut store = MemoryAgentRevocations::default();
    assert!(
        issuer
            .issue_agent(request(), identity(), now, &mut store)
            .is_ok()
    );

    // Once the agent is revoked, no new token is minted.
    store
        .revoke_agent(
            libre_ai_authz_biscuit::AgentRevocationRecord::new(
                USER.to_owned(),
                "compromise.suspected".to_owned(),
                now,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(
        issuer
            .issue_agent(request(), identity(), now, &mut store)
            .unwrap_err()
            .code,
        "auth.agent_revoked",
    );

    // An unavailable revocation store fails closed (refuses issuance).
    let mut unavailable = MemoryAgentRevocations {
        unavailable: true,
        ..MemoryAgentRevocations::default()
    };
    assert_eq!(
        issuer
            .issue_agent(request(), identity(), now, &mut unavailable)
            .unwrap_err()
            .code,
        "auth.biscuit_invalid",
    );

    // A different, non-revoked agent still mints under the same store.
    let mut store2 = MemoryAgentRevocations::default();
    store2
        .revoke_agent(
            libre_ai_authz_biscuit::AgentRevocationRecord::new(
                OTHER_USER.to_owned(),
                "policy.rotation".to_owned(),
                now,
            )
            .unwrap(),
        )
        .unwrap();
    assert!(
        issuer
            .issue_agent(request(), identity(), now, &mut store2)
            .is_ok()
    );
}

// Part b1/revocation: an agent revocation record preserves its audit reason.
#[test]
fn agent_revocation_record_preserves_reason_for_audit() {
    let now = at(0);
    let record = libre_ai_authz_biscuit::AgentRevocationRecord::new(
        USER.to_owned(),
        "policy.rotation".to_owned(),
        now,
    )
    .unwrap();
    assert_eq!(record.agent_id(), USER);
    assert_eq!(record.reason_code(), "policy.rotation");
    assert_eq!(record.revoked_at(), now);
    // A malformed agent_id or empty reason is rejected.
    assert!(
        libre_ai_authz_biscuit::AgentRevocationRecord::new(
            "not-a-user".to_owned(),
            "policy.rotation".to_owned(),
            now,
        )
        .is_err()
    );
    assert!(
        libre_ai_authz_biscuit::AgentRevocationRecord::new(USER.to_owned(), String::new(), now,)
            .is_err()
    );
}

// --- biscuit-auth 6.0 / biscuit-parser 0.2.0: datalog 3.3 printer surface ----
//
// The injectivity proof is bound to the exact printer/parser pair. The tests in
// this section replay the fbbe360 method on that pair: every construct the 6.0
// printer can emit is either proved to reparse faithfully (sets, `{,}`, `==`
// vs `===`, key-algorithm scope prefixes) or rejected up front by the guard
// (arrays, maps, null, closures, extern calls), so no new differential class
// reaches the structural validators.

fn issued_token_and_key(
    key_id: u32,
    now: SystemTime,
) -> (BiscuitIssuer, VerificationKeyRing, Biscuit) {
    let (issuer, ring) = issuer_and_ring(key_id, now);
    let serialized = issue(&issuer, now, "requester", &["read", "propose"], 300)
        .serialize()
        .unwrap();
    let verified = Biscuit::from_base64(serialized.token.expose(), issuer.public_key()).unwrap();
    (issuer, ring, verified)
}

fn authorize_appended(
    verified: &Biscuit,
    block: BlockBuilder,
    ring: &VerificationKeyRing,
    now: SystemTime,
) -> Result<libre_ai_authz_biscuit::AuthorizationDecision, libre_ai_authz_biscuit::AuthzError> {
    let token = verified.append(block).unwrap().to_base64().unwrap();
    let token = SensitiveToken::from_transport(token).unwrap();
    authorize(
        &token,
        mission_context(now + Duration::from_secs(1), "read"),
        ring,
        &mut checker(),
    )
}

#[test]
fn set_terms_print_and_reparse_faithfully_under_parser_0_2() {
    // Block 1 of every issued token binds `{operations}` to a Term::Set. The
    // 6.0 printer renders it with the datalog 3.3 `{..}` syntax; parser 0.2.0
    // must read it back as the same set, or every issued token would be denied
    // by the structural validator (parser 0.1.2 only knew `[..]` for sets).
    let now = at(900);
    let (_issuer, ring, verified) = issued_token_and_key(70, now);
    let source = verified.print_block_source(1).unwrap();
    // The printer orders set members by symbol-table index, not lexically
    // (`{"read", "propose"}` here); the reparsed BTreeSet compares by value, so
    // the order carries no information and the round trip is still faithful.
    assert!(
        source.contains("{\"read\", \"propose\"}.contains($operation)")
            || source.contains("{\"propose\", \"read\"}.contains($operation)"),
        "6.0 printer must render the operation set with the 3.3 syntax: {source}"
    );
    let parsed = biscuit_parser::parser::parse_source(&source).unwrap();
    let expected: BTreeSet<biscuit_parser::builder::Term> = ["propose", "read"]
        .into_iter()
        .map(|value| biscuit_parser::builder::Term::Str(value.to_owned()))
        .collect();
    assert!(matches!(
        parsed.checks[1].1.queries[0].expressions[0].ops.as_slice(),
        [biscuit_parser::builder::Op::Value(biscuit_parser::builder::Term::Set(set)), ..]
            if *set == expected
    ));
    let token = SensitiveToken::from_transport(verified.to_base64().unwrap()).unwrap();
    authorize(
        &token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut checker(),
    )
    .unwrap();
}

#[test]
fn empty_set_prints_as_brace_comma_and_is_rejected_as_non_canonical() {
    // A forged block 1 whose operation set is empty prints as `{,}` (the 3.3
    // empty-set literal, distinct from the empty map `{}`), reparses to an
    // empty set, and is then rejected by the non-empty bound of the canonical
    // operation check — never accepted, never mis-read as a map.
    let now = at(910);
    let expiry = now + Duration::from_secs(300);
    let kp = KeyPair::new();
    let ring = ring_for(71, kp.public(), now);
    let mut params = HashMap::<String, Term>::new();
    params.insert("resource".to_owned(), string(RESOURCE));
    params.insert("operations".to_owned(), Term::Set(BTreeSet::new()));
    params.insert("tenant".to_owned(), string(TENANT));
    params.insert("expires_at".to_owned(), Term::from(expiry));
    let block = BlockBuilder::new()
        .code_with_params(
            "check if resource({resource});\ncheck if operation($operation), {operations}.contains($operation);\ncheck if tenant({tenant});\ncheck if time($time), $time < {expires_at};",
            params,
            HashMap::new(),
        )
        .unwrap();
    let forged = authority_only(&kp, 71, expiry, "requester")
        .append(block)
        .unwrap();
    let source = forged.print_block_source(1).unwrap();
    assert!(source.contains("{,}.contains($operation)"), "{source}");
    let parsed = biscuit_parser::parser::parse_source(&source).unwrap();
    assert!(matches!(
        parsed.checks[1].1.queries[0].expressions[0].ops.as_slice(),
        [biscuit_parser::builder::Op::Value(biscuit_parser::builder::Term::Set(set)), ..]
            if set.is_empty()
    ));
    let token = SensitiveToken::from_transport(forged.to_base64().unwrap()).unwrap();
    assert_eq!(
        authorize(
            &token,
            mission_context(now + Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

#[test]
fn datalog_3_3_only_terms_in_any_signed_block_fail_closed() {
    // Arrays, maps, null, closures and extern calls are new to the 6.0 printer
    // and are never emitted by this issuer. They are appended here by a holder
    // in a block the structural validators never inspect (block 2), with an
    // expression that evaluates to true — so without the guard the token is
    // accepted. The guard rejects them as a class: no injectivity obligation
    // is taken on map keys (printed unescaped), closure parameter names
    // (printed as identifiers) or extern names.
    let now = at(920);
    let (_issuer, ring, verified) = issued_token_and_key(72, now);
    for (name, source) in [
        ("array", "check if [1, 2].contains(1);"),
        ("map", "check if {\"k\": 1} == {\"k\": 1};"),
        ("null", "check if null == null;"),
        ("closure", "check if [1].any($x -> $x == 1);"),
        ("extern", "check if 1.extern::always();"),
    ] {
        let block = BlockBuilder::new().code(source).unwrap();
        let error = authorize_appended(&verified, block, &ring, now).expect_err(&format!(
            "{name}: a 3.3-only term in a signed block must deny"
        ));
        assert_eq!(error.code, "auth.biscuit_invalid", "{name}");
    }
}

#[test]
fn closure_parameter_and_map_key_injection_channels_fail_closed() {
    use biscuit_auth::builder::{
        Binary, Check, CheckKind, Expression, MapKey, Op, Predicate, Rule,
    };
    // Two channels that did not exist in 5.0: a closure parameter NAME and a
    // map KEY are both printed verbatim. The poisoned block below evaluates to
    // true, so only the guard's class-level rejection stands between it and an
    // accepted token.
    let now = at(930);
    let (_issuer, ring, verified) = issued_token_and_key(73, now);
    let poison = "x), [\"read\"].contains($op".to_owned();
    let closure_check = Check {
        queries: vec![Rule {
            head: Predicate {
                name: "query".to_owned(),
                terms: vec![],
            },
            body: vec![],
            expressions: vec![Expression {
                ops: vec![
                    Op::Value(Term::Array(vec![Term::Integer(1)])),
                    Op::Closure(vec![poison.clone()], vec![Op::Value(Term::Bool(true))]),
                    Op::Binary(Binary::Any),
                ],
            }],
            parameters: None,
            scopes: vec![],
            scope_parameters: None,
        }],
        kind: CheckKind::One,
    };
    let mut map = std::collections::BTreeMap::new();
    map.insert(MapKey::Str(format!("{poison}\"")), Term::Integer(1));
    let map_check = Check {
        queries: vec![Rule {
            head: Predicate {
                name: "query".to_owned(),
                terms: vec![],
            },
            body: vec![],
            expressions: vec![Expression {
                ops: vec![
                    Op::Value(Term::Map(map.clone())),
                    Op::Value(Term::Map(map)),
                    Op::Binary(Binary::HeterogeneousEqual),
                ],
            }],
            parameters: None,
            scopes: vec![],
            scope_parameters: None,
        }],
        kind: CheckKind::One,
    };
    for (name, check) in [("closure parameter", closure_check), ("map key", map_check)] {
        let block = BlockBuilder::new().check(check).unwrap();
        let error = authorize_appended(&verified, block, &ring, now)
            .expect_err(&format!("{name}: poisoned identifier channel must deny"));
        assert_eq!(error.code, "auth.biscuit_invalid", "{name}");
    }
}

#[test]
fn equality_operators_and_key_scopes_print_and_reparse_faithfully() {
    // datalog 3.3 distinguishes strict (`===`, `!==`) from lenient (`==`, `!=`)
    // equality, and prints trusted keys with an algorithm prefix
    // (`ed25519/<hex>`). Each must reparse to the same operator and the same
    // key: a swap between strict and lenient equality, or a key that reprints
    // as another, would be a differential between the binary and the source.
    use biscuit_parser::builder::{Algorithm as ParsedAlgorithm, Binary, Op, Scope as ParsedScope};
    let now = at(940);
    let (_issuer, ring, verified) = issued_token_and_key(74, now);
    let trusted = KeyPair::new().public();
    let mut scope_params = HashMap::<String, biscuit_auth::PublicKey>::new();
    scope_params.insert("k".to_owned(), trusted);
    let block = BlockBuilder::new()
        .code_with_params(
            "check if 1 == 1;\ncheck if 1 === 1;\ncheck if \"a\" != \"b\";\ncheck if \"a\" !== \"b\";\ncheck if true trusting {k};",
            HashMap::new(),
            scope_params,
        )
        .unwrap();
    let appended = verified.append(block).unwrap();
    let source = appended.print_block_source(2).unwrap();
    let parsed = biscuit_parser::parser::parse_source(&source).unwrap();
    let last_op = |index: usize| {
        parsed.checks[index].1.queries[0].expressions[0]
            .ops
            .last()
            .cloned()
    };
    assert_eq!(
        last_op(0),
        Some(Op::Binary(Binary::HeterogeneousEqual)),
        "{source}"
    );
    assert_eq!(last_op(1), Some(Op::Binary(Binary::Equal)), "{source}");
    assert_eq!(
        last_op(2),
        Some(Op::Binary(Binary::HeterogeneousNotEqual)),
        "{source}"
    );
    assert_eq!(last_op(3), Some(Op::Binary(Binary::NotEqual)), "{source}");
    assert!(source.contains("trusting ed25519/"), "{source}");
    match parsed.checks[4].1.queries[0].scopes.as_slice() {
        [ParsedScope::PublicKey(key)] => {
            assert_eq!(key.algorithm, ParsedAlgorithm::Ed25519);
            assert_eq!(key.key, trusted.to_bytes());
        }
        other => panic!("scope must reparse to the same trusted key: {other:?}"),
    }
    // Every construct above is faithful and satisfiable, so the appended block
    // attenuates nothing and the token is still accepted.
    let token = SensitiveToken::from_transport(appended.to_base64().unwrap()).unwrap();
    authorize(
        &token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut checker(),
    )
    .unwrap();
}

#[test]
fn every_ascii_byte_in_a_string_term_either_round_trips_or_is_denied() {
    // Property replayed from the fbbe360 method on the 6.0 / 0.2.0 pair, in two
    // halves so each counter measures one thing. Faithfulness: a forged
    // canonical block 1 whose resource string carries the byte is reprinted and
    // reparsed — the string comes back byte-identical, or it does not. Guard
    // attribution: the same string sits in a block-2 check `"s" == "s"`, which
    // is true on the binary and which no structural validator reads, so the
    // token is either accepted or denied by the guard alone. There is no third
    // outcome — no byte lets the reprinted source diverge from the binary and
    // still reach the validators.
    use biscuit_auth::builder::{Binary, Op};
    let now = at(950);
    let expiry = now + Duration::from_secs(300);
    let kp = KeyPair::new();
    let (_issuer, ring, verified) = issued_token_and_key(75, now);
    let mut faithful = 0usize;
    let mut accepted = 0usize;
    let mut denied_by_guard = 0usize;
    // Every ASCII byte, then one UTF-8 sample per encoded length: two bytes
    // (`é`), three (`€`), four (`😀`).
    let samples = (0x01u8..=0x7f)
        .map(|byte| char::from(byte).to_string())
        .chain(["é", "€", "😀"].into_iter().map(str::to_owned));
    for injected in samples {
        let payload = format!("{RESOURCE}{injected}x");
        let mut params = HashMap::<String, Term>::new();
        params.insert("resource".to_owned(), Term::Str(payload.clone()));
        params.insert(
            "operations".to_owned(),
            Term::Set([string("read")].into_iter().collect()),
        );
        params.insert("tenant".to_owned(), string(TENANT));
        params.insert("expires_at".to_owned(), Term::from(expiry));
        let block = BlockBuilder::new()
            .code_with_params(
                "check if resource({resource});\ncheck if operation($operation), {operations}.contains($operation);\ncheck if tenant({tenant});\ncheck if time($time), $time < {expires_at};",
                params,
                HashMap::new(),
            )
            .unwrap();
        let forged = authority_only(&kp, 75, expiry, "requester")
            .append(block)
            .unwrap();
        let source = forged.print_block_source(1).unwrap();
        let reparsed_resource =
            biscuit_parser::parser::parse_source(&source)
                .ok()
                .and_then(|parsed| {
                    parsed.checks.first().and_then(|(_, check)| {
                        match check.queries[0].body[0].terms.as_slice() {
                            [biscuit_parser::builder::Term::Str(value)] => Some(value.clone()),
                            _ => None,
                        }
                    })
                });
        // Guard attribution half: the byte in a satisfiable block-2 check.
        let probe = expression_check(vec![
            Op::Value(Term::Str(payload.clone())),
            Op::Value(Term::Str(payload.clone())),
            Op::Binary(Binary::HeterogeneousEqual),
        ]);
        let outcome = authorize_appended(&verified, probe, &ring, now).map(|_| ());
        if injected == "\"" || injected == "\\" {
            assert_ne!(
                reparsed_resource.as_deref(),
                Some(payload.as_str()),
                "sample {injected:?} must not be a fixed point of print/parse"
            );
            assert_eq!(
                outcome.unwrap_err().code,
                "auth.biscuit_invalid",
                "sample {injected:?} must be denied by the guard"
            );
            denied_by_guard += 1;
        } else {
            assert_eq!(
                reparsed_resource.as_deref(),
                Some(payload.as_str()),
                "sample {injected:?} must reparse to the decoded string: {source}"
            );
            faithful += 1;
            assert!(
                outcome.is_ok(),
                "sample {injected:?} is faithful and must pass the guard"
            );
            accepted += 1;
        }
    }
    assert_eq!(denied_by_guard, 2);
    assert_eq!(faithful, 128);
    assert_eq!(accepted, 128);
}

// --- Contracts under datalog 3.3: `[...]` is now an array, membership holds --

fn vendored_policy(name: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("vendored/authz")
            .join(name),
    )
    .unwrap()
}

#[test]
fn every_vendored_policy_parses_under_parser_0_2_and_contains_is_an_array_membership() {
    use biscuit_parser::builder::{Binary, Op, Term as ParsedTerm};
    // datalog 3.3 re-typed the `[a, b]` literal from set to array. The six
    // vendored contracts are byte-identical to the contracts authority (the
    // drift gate proves it); this test proves what the new grammar makes of
    // them: every file parses, and every `[...].contains($op)` clause is now an
    // array-membership test — same allow/deny surface, different term kind.
    let mut array_contains = 0usize;
    for name in [
        "authority-v1.datalog",
        "authority-v2.datalog",
        "sessions-v1.datalog",
        "missions-v1.datalog",
        "agent-runs-v1.datalog",
        "agent-runs-v2.datalog",
    ] {
        let source = vendored_policy(name);
        let parsed = biscuit_parser::parser::parse_source(&source).unwrap_or_else(|errors| {
            panic!("{name} must parse under biscuit-parser 0.2.0: {errors:?}")
        });
        for (_, policy) in &parsed.policies {
            for rule in &policy.queries {
                for expression in &rule.expressions {
                    if let [
                        Op::Value(ParsedTerm::Array(members)),
                        Op::Value(ParsedTerm::Variable(_)),
                        Op::Binary(Binary::Contains),
                    ] = expression.ops.as_slice()
                    {
                        assert!(!members.is_empty(), "{name}");
                        assert!(
                            members
                                .iter()
                                .all(|member| matches!(member, ParsedTerm::Str(_))),
                            "{name}: operation lists are string arrays"
                        );
                        array_contains += 1;
                    } else {
                        assert!(
                            !expression.ops.iter().any(|op| matches!(
                                op,
                                Op::Value(ParsedTerm::Array(_)) | Op::Value(ParsedTerm::Set(_))
                            )),
                            "{name}: the only collection literal in a contract is an operation list"
                        );
                    }
                }
            }
        }
    }
    // sessions 3 + missions 5 + agent-runs-v1 3 + agent-runs-v2 3 operation lists.
    assert_eq!(array_contains, 14);
}

#[test]
fn canonical_policies_allow_and_deny_as_before_under_the_6_0_evaluator() {
    // One positive and one negative case per authorizer contract, through the
    // public API for the two embedded policies and through the raw 6.0
    // authorizer for the two agent-run policies this crate does not embed.
    let now = at(960);

    // sessions-v1: owner may create-space (array membership); nobody may
    // "archive" (absent from every list).
    let (issuer, ring) = issuer_and_ring(80, now);
    let owner = issue(&issuer, now, "owner", &["create-space", "archive"], 300)
        .serialize()
        .unwrap();
    let mut allowed = mission_context(now + Duration::from_secs(1), "create-space");
    allowed.policy = CanonicalPolicy::Sessions;
    authorize(&owner.token, allowed, &ring, &mut checker()).unwrap();
    let mut denied = mission_context(now + Duration::from_secs(1), "archive");
    denied.policy = CanonicalPolicy::Sessions;
    assert_eq!(
        authorize(&owner.token, denied, &ring, &mut checker())
            .unwrap_err()
            .code,
        "auth.operation_denied"
    );

    // missions-v1: requester may propose but not approve (in another role's
    // list only).
    let requester = issue(&issuer, now, "requester", &["propose", "approve"], 300)
        .serialize()
        .unwrap();
    authorize(
        &requester.token,
        mission_context(now + Duration::from_secs(1), "propose"),
        &ring,
        &mut checker(),
    )
    .unwrap();
    assert_eq!(
        authorize(
            &requester.token,
            mission_context(now + Duration::from_secs(1), "approve"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.operation_denied"
    );

    // agent-runs-v1 / v2: operator may pause (array membership) but not
    // submit-plan (an author-agent operation).
    for policy in ["agent-runs-v1.datalog", "agent-runs-v2.datalog"] {
        let source = vendored_policy(policy);
        let operator = issue(&issuer, now, "operator", &["pause", "submit-plan"], 300)
            .serialize()
            .unwrap();
        let biscuit = Biscuit::from_base64(operator.token.expose(), issuer.public_key()).unwrap();
        let evaluate = |operation: &str| -> bool {
            let mut builder = biscuit_auth::AuthorizerBuilder::new();
            for injected in [
                fact("time", &[date(&(now + Duration::from_secs(1)))]),
                fact("resource", &[string(RESOURCE)]),
                fact("operation", &[string(operation)]),
                fact("resource_tenant", &[string(TENANT)]),
            ] {
                builder = builder.fact(injected).unwrap();
            }
            builder
                .code(source.as_str())
                .unwrap()
                .build(&biscuit)
                .unwrap()
                .authorize_with_limits(biscuit_auth::AuthorizerLimits {
                    max_facts: 256,
                    max_iterations: 32,
                    max_time: Duration::from_millis(50),
                })
                .is_ok()
        };
        assert!(
            evaluate("pause"),
            "{policy}: operator pause must be allowed"
        );
        assert!(
            !evaluate("submit-plan"),
            "{policy}: operator submit-plan must be denied"
        );
    }
}

// --- Round 2: one test per guard branch, attributable to the guard alone ------
//
// Every forgery below lives in block 2, which the structural validators never
// read, so `auth.biscuit_invalid` can only come from the injectivity guard:
// with the corresponding branch mutated, the token is either accepted or
// denied by evaluation with `auth.operation_denied`. The mutant -> killing
// test table is in evidence/reviews/81ce4b5/.

fn query_rule(
    body: Vec<biscuit_auth::builder::Predicate>,
    ops: Vec<biscuit_auth::builder::Op>,
) -> biscuit_auth::builder::Rule {
    use biscuit_auth::builder::{Expression, Predicate, Rule};
    Rule {
        head: Predicate {
            name: "query".to_owned(),
            terms: vec![],
        },
        body,
        expressions: if ops.is_empty() {
            vec![]
        } else {
            vec![Expression { ops }]
        },
        parameters: None,
        scopes: vec![],
        scope_parameters: None,
    }
}

fn check_of(rule: biscuit_auth::builder::Rule) -> biscuit_auth::builder::Check {
    biscuit_auth::builder::Check {
        queries: vec![rule],
        kind: biscuit_auth::builder::CheckKind::One,
    }
}

fn expression_check(ops: Vec<biscuit_auth::builder::Op>) -> BlockBuilder {
    BlockBuilder::new()
        .check(check_of(query_rule(vec![], ops)))
        .unwrap()
}

/// Deny code of a holder-appended block 2 on an otherwise valid token.
fn block2_outcome(block: BlockBuilder) -> Result<(), &'static str> {
    let now = at(1000);
    let (_issuer, ring, verified) = issued_token_and_key(90, now);
    authorize_appended(&verified, block, &ring, now)
        .map(|_| ())
        .map_err(|error| error.code)
}

fn assert_guard_denies(name: &str, block: BlockBuilder) {
    assert_eq!(
        block2_outcome(block),
        Err("auth.biscuit_invalid"),
        "{name}: only the guard denies a block-2 forgery with auth.biscuit_invalid"
    );
}

const POISON: &str = "x); check if true; //";

#[test]
fn guard_str_quote() {
    use biscuit_auth::builder::{Binary, Op};
    let value = format!("{RESOURCE}\"");
    assert_guard_denies(
        "string term with a raw quote",
        expression_check(vec![
            Op::Value(Term::Str(value.clone())),
            Op::Value(Term::Str(value)),
            Op::Binary(Binary::HeterogeneousEqual),
        ]),
    );
}

#[test]
fn guard_str_backslash() {
    use biscuit_auth::builder::{Binary, Op};
    let value = format!("{RESOURCE}\\n");
    assert_guard_denies(
        "string term with a backslash",
        expression_check(vec![
            Op::Value(Term::Str(value.clone())),
            Op::Value(Term::Str(value)),
            Op::Binary(Binary::HeterogeneousEqual),
        ]),
    );
}

#[test]
fn guard_variable_name() {
    use biscuit_auth::builder::Predicate;
    // `resource($poison)` unifies with the ambient resource fact, so the check
    // is satisfiable and only the variable-name rule denies.
    assert_guard_denies(
        "variable name that is not an identifier",
        BlockBuilder::new()
            .check(check_of(query_rule(
                vec![Predicate {
                    name: "resource".to_owned(),
                    terms: vec![Term::Variable(POISON.to_owned())],
                }],
                vec![],
            )))
            .unwrap(),
    );
}

#[test]
fn guard_fact_predicate_name() {
    use biscuit_auth::builder::{Fact, Predicate};
    // A fact imposes nothing on the decision: without the facts walk (or the
    // predicate-name rule) the token is accepted.
    assert_guard_denies(
        "fact whose predicate name is not an identifier",
        BlockBuilder::new()
            .fact(Fact {
                predicate: Predicate {
                    name: POISON.to_owned(),
                    terms: vec![string("a")],
                },
                parameters: None,
            })
            .unwrap(),
    );
}

#[test]
fn guard_fact_term() {
    // Same walk, string channel inside a fact term.
    assert_guard_denies(
        "fact whose term carries a raw quote",
        BlockBuilder::new()
            .fact(fact("note", &[string("a\"b")]))
            .unwrap(),
    );
}

#[test]
fn guard_rule_head_name() {
    use biscuit_auth::builder::{Predicate, Rule};
    // A rule whose head never fires imposes nothing; only the rules walk on
    // the head predicate denies.
    assert_guard_denies(
        "rule head whose name is not an identifier",
        BlockBuilder::new()
            .rule(Rule {
                head: Predicate {
                    name: POISON.to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                },
                body: vec![Predicate {
                    name: "resource".to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                }],
                expressions: vec![],
                parameters: None,
                scopes: vec![],
                scope_parameters: None,
            })
            .unwrap(),
    );
}

#[test]
fn guard_rule_body_name() {
    use biscuit_auth::builder::{Predicate, Rule};
    assert_guard_denies(
        "rule body predicate whose name is not an identifier",
        BlockBuilder::new()
            .rule(Rule {
                head: Predicate {
                    name: "derived".to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                },
                body: vec![Predicate {
                    name: POISON.to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                }],
                expressions: vec![],
                parameters: None,
                scopes: vec![],
                scope_parameters: None,
            })
            .unwrap(),
    );
}

#[test]
fn guard_rule_expression() {
    use biscuit_auth::builder::{Binary, Expression, Op, Predicate, Rule};
    assert_guard_denies(
        "rule expression carrying a raw quote",
        BlockBuilder::new()
            .rule(Rule {
                head: Predicate {
                    name: "derived".to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                },
                body: vec![Predicate {
                    name: "resource".to_owned(),
                    terms: vec![Term::Variable("x".to_owned())],
                }],
                expressions: vec![Expression {
                    ops: vec![
                        Op::Value(Term::Str("a\"".to_owned())),
                        Op::Value(Term::Str("a\"".to_owned())),
                        Op::Binary(Binary::HeterogeneousEqual),
                    ],
                }],
                parameters: None,
                scopes: vec![],
                scope_parameters: None,
            })
            .unwrap(),
    );
}

#[test]
fn guard_check_body_name() {
    use biscuit_auth::builder::Predicate;
    assert_guard_denies(
        "check body predicate whose name is not an identifier",
        BlockBuilder::new()
            .check(check_of(query_rule(
                vec![Predicate {
                    name: POISON.to_owned(),
                    terms: vec![string(RESOURCE)],
                }],
                vec![],
            )))
            .unwrap(),
    );
}

#[test]
fn guard_set_member() {
    use biscuit_auth::builder::{Binary, Op, Unary};
    // The poisoned string sits only inside the set: without member recursion
    // `{"a\""}.length() == 1` evaluates true and the token is accepted.
    let members: BTreeSet<Term> = [Term::Str("a\"".to_owned())].into_iter().collect();
    assert_guard_denies(
        "set member carrying a raw quote",
        expression_check(vec![
            Op::Value(Term::Set(members)),
            Op::Unary(Unary::Length),
            Op::Value(Term::Integer(1)),
            Op::Binary(Binary::HeterogeneousEqual),
        ]),
    );
}

#[test]
fn guard_null() {
    assert_guard_denies(
        "null",
        BlockBuilder::new().code("check if null == null;").unwrap(),
    );
}

#[test]
fn guard_array() {
    assert_guard_denies(
        "array",
        BlockBuilder::new()
            .code("check if [1, 2].contains(1);")
            .unwrap(),
    );
}

#[test]
fn guard_map() {
    assert_guard_denies(
        "map",
        BlockBuilder::new()
            .code("check if {\"k\": 1} == {\"k\": 1};")
            .unwrap(),
    );
}

#[test]
fn guard_closure() {
    // A closure over a SET with `.any` (an allowed operator): the only
    // rejected kind on the path is the closure itself.
    assert_guard_denies(
        "closure",
        BlockBuilder::new()
            .code("check if {1}.any($x -> true);")
            .unwrap(),
    );
}

#[test]
fn guard_unary_extern() {
    assert_guard_denies(
        "unary extern call",
        BlockBuilder::new()
            .code("check if 1.extern::always();")
            .unwrap(),
    );
}

#[test]
fn guard_binary_extern() {
    assert_guard_denies(
        "binary extern call",
        BlockBuilder::new()
            .code("check if 1.extern::always(2);")
            .unwrap(),
    );
}

#[test]
fn guard_strict_and() {
    use biscuit_auth::builder::{Binary, Op};
    // Prints `true &&! true`, which parser 0.2.0 reads as `true && !true`.
    assert_guard_denies(
        "strict And",
        expression_check(vec![
            Op::Value(Term::Bool(true)),
            Op::Value(Term::Bool(true)),
            Op::Binary(Binary::And),
        ]),
    );
}

#[test]
fn guard_strict_or() {
    use biscuit_auth::builder::{Binary, Op};
    assert_guard_denies(
        "strict Or",
        expression_check(vec![
            Op::Value(Term::Bool(false)),
            Op::Value(Term::Bool(true)),
            Op::Binary(Binary::Or),
        ]),
    );
}

#[test]
fn guard_try_or() {
    use biscuit_auth::builder::{Binary, Op};
    // The binary form has no closure; its reprint reparses with one.
    assert_guard_denies(
        "try_or",
        expression_check(vec![
            Op::Value(Term::Bool(true)),
            Op::Value(Term::Bool(false)),
            Op::Binary(Binary::TryOr),
        ]),
    );
}

#[test]
fn guard_lazy_and() {
    use biscuit_auth::builder::{Binary, Op};
    assert_guard_denies(
        "lazy And without closure",
        expression_check(vec![
            Op::Value(Term::Bool(true)),
            Op::Value(Term::Bool(true)),
            Op::Binary(Binary::LazyAnd),
        ]),
    );
}

#[test]
fn guard_lazy_or() {
    use biscuit_auth::builder::{Binary, Op};
    assert_guard_denies(
        "lazy Or without closure",
        expression_check(vec![
            Op::Value(Term::Bool(false)),
            Op::Value(Term::Bool(true)),
            Op::Binary(Binary::LazyOr),
        ]),
    );
}

#[test]
fn guard_date_range() {
    use biscuit_auth::builder::{Binary, Op};
    // The printer renders Term::Date through `as i64` + RFC 3339, which is
    // only faithful for 0 ..= 9999-12-31T23:59:59Z (253402300799).
    for (name, date) in [
        ("u64::MAX (prints as 1969)", u64::MAX),
        ("1 << 63 (prints <invalid date>)", 1u64 << 63),
        ("year 10000 (prints <invalid date>)", 253_402_300_800),
    ] {
        assert_guard_denies(
            name,
            expression_check(vec![
                Op::Value(Term::Date(date)),
                Op::Value(Term::Date(date)),
                Op::Binary(Binary::HeterogeneousEqual),
            ]),
        );
    }
    // Boundary: the last printable second is faithful and accepted.
    let now = at(1000);
    let (_issuer, ring, verified) = issued_token_and_key(91, now);
    let block = expression_check(vec![
        Op::Value(Term::Date(253_402_300_799)),
        Op::Value(Term::Date(253_402_300_799)),
        Op::Binary(Binary::HeterogeneousEqual),
    ]);
    let appended = verified.append(block).unwrap();
    let source = appended.print_block_source(2).unwrap();
    assert!(source.contains("9999-12-31T23:59:59Z"), "{source}");
    let parsed = biscuit_parser::parser::parse_source(&source).unwrap();
    assert!(matches!(
        parsed.checks[0].1.queries[0].expressions[0].ops.first(),
        Some(biscuit_parser::builder::Op::Value(
            biscuit_parser::builder::Term::Date(253_402_300_799)
        ))
    ));
    let token = SensitiveToken::from_transport(appended.to_base64().unwrap()).unwrap();
    authorize(
        &token,
        mission_context(now + Duration::from_secs(1), "read"),
        &ring,
        &mut checker(),
    )
    .unwrap();
}

#[test]
fn term_parameter_never_reaches_a_signed_block() {
    use biscuit_auth::builder::{Binary, Fact, Op, Predicate};
    // Equivalence proof for the `Term::Parameter -> false` arm: the builder
    // accepts an unbound parameter in a fact term or a check expression, but
    // `Biscuit::append` fails or panics on it before anything is signed (the
    // wire format has no parameter kind). No signed block can carry the
    // variant, so the arm is unreachable from authorize() and its mutant is
    // equivalent by construction.
    let now = at(1000);
    let (_issuer, _ring, verified) = issued_token_and_key(92, now);
    let fact_block = BlockBuilder::new()
        .fact(Fact {
            predicate: Predicate {
                name: "p".to_owned(),
                terms: vec![Term::Parameter("p".to_owned())],
            },
            parameters: None,
        })
        .unwrap();
    let check_block = expression_check(vec![
        Op::Value(Term::Parameter("p".to_owned())),
        Op::Value(Term::Integer(1)),
        Op::Binary(Binary::HeterogeneousEqual),
    ]);
    for (name, block) in [("fact term", fact_block), ("check expression", check_block)] {
        let appended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verified.append(block).map(|_| ())
        }));
        assert!(
            !matches!(appended, Ok(Ok(()))),
            "{name}: a block with an unbound parameter must not be signable"
        );
    }
}

// --- Round 2: block-level scopes are checked on the structure -----------------

#[test]
fn block_level_scopes_on_blocks_0_and_1_are_rejected_structurally() {
    use biscuit_auth::builder::Scope;
    // `Block::print_source` never prints block-level scopes, so the reprinted
    // source cannot reveal them; the check reads the decoded block structure.
    let now = at(1010);
    let expiry = now + Duration::from_secs(300);
    let kp = KeyPair::new();
    let ring = ring_for(93, kp.public(), now);
    let canonical_block1 = || {
        let mut params = HashMap::<String, Term>::new();
        params.insert("resource".to_owned(), string(RESOURCE));
        params.insert(
            "operations".to_owned(),
            Term::Set([string("read")].into_iter().collect()),
        );
        params.insert("tenant".to_owned(), string(TENANT));
        params.insert("expires_at".to_owned(), Term::from(expiry));
        BlockBuilder::new()
            .code_with_params(
                "check if resource({resource});\ncheck if operation($operation), {operations}.contains($operation);\ncheck if tenant({tenant});\ncheck if time($time), $time < {expires_at};",
                params,
                HashMap::new(),
            )
            .unwrap()
    };
    for (name, scope) in [
        ("previous", Scope::Previous),
        ("authority", Scope::Authority),
        ("public key", Scope::PublicKey(KeyPair::new().public())),
    ] {
        let forged = authority_only(&kp, 93, expiry, "requester")
            .append(canonical_block1().scope(scope))
            .unwrap();
        let source = forged.print_block_source(1).unwrap();
        assert!(
            !source.contains("trusting"),
            "{name}: the printer must not reveal a block-level scope: {source}"
        );
        let token = SensitiveToken::from_transport(forged.to_base64().unwrap()).unwrap();
        assert_eq!(
            authorize(
                &token,
                mission_context(now + Duration::from_secs(1), "read"),
                &ring,
                &mut checker(),
            )
            .unwrap_err()
            .code,
            "auth.biscuit_invalid",
            "{name}: a block-level scope on block 1 must be rejected"
        );
    }
    // Block 0 (root-key holder) as well.
    let mut params = HashMap::<String, Term>::new();
    params.insert("user".to_owned(), string(USER));
    params.insert("tenant".to_owned(), string(TENANT));
    params.insert("role".to_owned(), string("requester"));
    params.insert("expires_at".to_owned(), Term::from(expiry));
    let scoped_authority = Biscuit::builder()
        .root_key_id(93)
        .code_with_params(AUTHORITY_TEMPLATE, params, HashMap::new())
        .unwrap()
        .scope(Scope::Previous)
        .build(&kp)
        .unwrap()
        .append(canonical_block1())
        .unwrap();
    let token = SensitiveToken::from_transport(scoped_authority.to_base64().unwrap()).unwrap();
    assert_eq!(
        authorize(
            &token,
            mission_context(now + Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_err()
        .code,
        "auth.biscuit_invalid"
    );
}

// --- Round 3: a holder-block expression carries at most one operation --------
//
// The 6.0 printer emits no parenthesis (only an explicit `Unary::Parens` op
// prints `(...)`), so a compound expression prints as a flat `a op b op c`
// string that parser 0.2.0 reads back under its own precedence layers — a
// different tree, or none at all. Blocks 0 and 1 are matched on exact op
// sequences, so the divergence cannot reach the validators there; for holder
// blocks (index >= 2) the guard is fail-closed instead: one unary or binary
// operation per expression, and never `Parens`. Owner decision of 2026-09-08
// on the governance security verdict for d65e877.

#[test]
fn guard_holder_expression_with_two_operations() {
    use biscuit_auth::builder::{Binary, Op, Unary};
    let int = |value: i64| Op::Value(Term::Integer(value));
    for (name, ops) in [
        (
            "1 + 2 * 3 (reparses as 1 + (2 * 3))",
            vec![
                int(1),
                int(2),
                Op::Binary(Binary::Add),
                int(3),
                Op::Binary(Binary::Mul),
            ],
        ),
        (
            "!true === false (reparses as (!true) === false)",
            vec![
                Op::Value(Term::Bool(true)),
                Op::Value(Term::Bool(false)),
                Op::Binary(Binary::HeterogeneousEqual),
                Op::Unary(Unary::Negate),
            ],
        ),
        (
            "$x.starts_with(\"a\").length() (two operations)",
            vec![
                Op::Value(Term::Variable("x".to_owned())),
                Op::Value(string("a")),
                Op::Binary(Binary::Prefix),
                Op::Unary(Unary::Length),
            ],
        ),
        // Reparses faithfully (methods bind tightest); still two operations,
        // refused fail-closed rather than proved case by case.
        (
            "$x.length() === 4 (faithful, still two operations)",
            vec![
                Op::Value(Term::Variable("x".to_owned())),
                Op::Unary(Unary::Length),
                int(4),
                Op::Binary(Binary::HeterogeneousEqual),
            ],
        ),
        (
            "1 < 2 === true (comparisons are non-associative: no reparse)",
            vec![
                int(1),
                int(2),
                Op::Binary(Binary::LessThan),
                Op::Value(Term::Bool(true)),
                Op::Binary(Binary::HeterogeneousEqual),
            ],
        ),
        // Already refused by the `LazyAnd`/`LazyOr` rule (mutants M22/M23):
        // listed for completeness, its denial is attributed there, not here.
        (
            "true && true || false (lazy operators, refused before this rule)",
            vec![
                Op::Value(Term::Bool(true)),
                Op::Value(Term::Bool(true)),
                Op::Binary(Binary::LazyAnd),
                Op::Value(Term::Bool(false)),
                Op::Binary(Binary::LazyOr),
            ],
        ),
    ] {
        assert_guard_denies(name, expression_check(ops));
    }
}

#[test]
fn guard_holder_expression_with_parens() {
    use biscuit_auth::builder::{Binary, Op, Unary};
    let int = |value: i64| Op::Value(Term::Integer(value));
    for (name, ops) in [
        (
            "(1 + 2) * 3",
            vec![
                int(1),
                int(2),
                Op::Binary(Binary::Add),
                Op::Unary(Unary::Parens),
                int(3),
                Op::Binary(Binary::Mul),
            ],
        ),
        ("(1) alone", vec![int(1), Op::Unary(Unary::Parens)]),
    ] {
        assert_guard_denies(name, expression_check(ops));
    }
}

#[test]
fn holder_expressions_with_a_single_operation_stay_accepted() {
    use biscuit_auth::builder::{Binary, Op, Predicate, Unary};
    let now = at(1040);
    let (_issuer, ring, verified) = issued_token_and_key(95, now);
    let variable = |name: &str| Op::Value(Term::Variable(name.to_owned()));
    let predicate = |name: &str, var: &str| Predicate {
        name: name.to_owned(),
        terms: vec![Term::Variable(var.to_owned())],
    };
    let cases: Vec<(&str, Vec<Predicate>, Vec<Op>)> = vec![
        (
            "{\"read\"}.contains($operation)",
            vec![predicate("operation", "operation")],
            vec![
                Op::Value(Term::Set([string("read")].into_iter().collect())),
                variable("operation"),
                Op::Binary(Binary::Contains),
            ],
        ),
        (
            "$time <= <date>",
            vec![predicate("time", "time")],
            vec![
                variable("time"),
                Op::Value(Term::from(now + Duration::from_secs(100))),
                Op::Binary(Binary::LessOrEqual),
            ],
        ),
        (
            "true (no operation)",
            vec![],
            vec![Op::Value(Term::Bool(true))],
        ),
        (
            "!false (one unary operation)",
            vec![],
            vec![Op::Value(Term::Bool(false)), Op::Unary(Unary::Negate)],
        ),
    ];
    for (name, body, ops) in cases {
        let block = BlockBuilder::new()
            .check(check_of(query_rule(body, ops)))
            .unwrap();
        let outcome = authorize_appended(&verified, block, &ring, now).map(|_| ());
        assert!(
            outcome.is_ok(),
            "{name}: single-operation expression must be accepted: {outcome:?}"
        );
    }
}

#[test]
fn set_contains_and_date_comparisons_round_trip() {
    // The two operators the canonical block 1 relies on
    // (`{operations}.contains($operation)`, `$time < <expiry>`), plus `<=`:
    // each prints and reparses to the same op sequence, and the token is
    // accepted. Round 3: the faithful list in SECURITY.md names them.
    use biscuit_auth::builder::{Binary, Op, Predicate};
    use biscuit_parser::builder as parsed;
    let now = at(1050);
    let (_issuer, ring, verified) = issued_token_and_key(96, now);
    let deadline = now + Duration::from_secs(100);
    let deadline_seconds = deadline.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let predicate = |name: &str| Predicate {
        name: name.to_owned(),
        terms: vec![Term::Variable(name.to_owned())],
    };
    type SameOps = Box<dyn Fn(&[parsed::Op]) -> bool>;
    let cases: Vec<(&str, Predicate, Vec<Op>, SameOps)> = vec![
        (
            "{\"read\"}.contains($operation)",
            predicate("operation"),
            vec![
                Op::Value(Term::Set([string("read")].into_iter().collect())),
                Op::Value(Term::Variable("operation".to_owned())),
                Op::Binary(Binary::Contains),
            ],
            Box::new(|ops| {
                matches!(
                    ops,
                    [
                        parsed::Op::Value(parsed::Term::Set(members)),
                        parsed::Op::Value(parsed::Term::Variable(variable)),
                        parsed::Op::Binary(parsed::Binary::Contains),
                    ] if variable == "operation"
                        && members.len() == 1
                        && members.contains(&parsed::Term::Str("read".to_owned()))
                )
            }),
        ),
        (
            "$time < <date>",
            predicate("time"),
            vec![
                Op::Value(Term::Variable("time".to_owned())),
                Op::Value(Term::Date(deadline_seconds)),
                Op::Binary(Binary::LessThan),
            ],
            Box::new(move |ops| {
                matches!(
                    ops,
                    [
                        parsed::Op::Value(parsed::Term::Variable(variable)),
                        parsed::Op::Value(parsed::Term::Date(date)),
                        parsed::Op::Binary(parsed::Binary::LessThan),
                    ] if variable == "time" && *date == deadline_seconds
                )
            }),
        ),
        (
            "$time <= <date>",
            predicate("time"),
            vec![
                Op::Value(Term::Variable("time".to_owned())),
                Op::Value(Term::Date(deadline_seconds)),
                Op::Binary(Binary::LessOrEqual),
            ],
            Box::new(move |ops| {
                matches!(
                    ops,
                    [
                        parsed::Op::Value(parsed::Term::Variable(variable)),
                        parsed::Op::Value(parsed::Term::Date(date)),
                        parsed::Op::Binary(parsed::Binary::LessOrEqual),
                    ] if variable == "time" && *date == deadline_seconds
                )
            }),
        ),
    ];
    for (name, body, ops, same_ops) in cases {
        let block = BlockBuilder::new()
            .check(check_of(query_rule(vec![body], ops)))
            .unwrap();
        let appended = verified.append(block).unwrap();
        let source = appended.print_block_source(2).unwrap();
        let reparsed = biscuit_parser::parser::parse_source(&source).unwrap();
        let (_, check) = &reparsed.checks[0];
        assert!(
            same_ops(&check.queries[0].expressions[0].ops),
            "{name}: reparsed ops differ from the built ops: {source}"
        );
        let token = SensitiveToken::from_transport(appended.to_base64().unwrap()).unwrap();
        authorize(
            &token,
            mission_context(now + Duration::from_secs(1), "read"),
            &ring,
            &mut checker(),
        )
        .unwrap_or_else(|error| panic!("{name}: must be accepted, got {}", error.code));
    }
}

// --- Round 2: Ed25519 is enforced at the key entry points --------------------

#[test]
fn non_ed25519_keys_are_refused_at_every_entry_point() {
    use biscuit_auth::builder::Algorithm;
    let now = at(1020);
    let p256 = KeyPair::new_with_algorithm(Algorithm::Secp256r1);
    assert_eq!(
        BiscuitIssuer::new(
            1,
            KeyPair::new_with_algorithm(Algorithm::Secp256r1),
            Duration::from_secs(900),
            now
        )
        .unwrap_err()
        .code,
        "auth.key_unavailable"
    );
    assert_eq!(
        VerificationKeyRing::new(VerificationKey {
            key_id: 1,
            public_key: p256.public(),
            valid_from: now - Duration::from_secs(1),
            valid_until: None,
            status: VerificationKeyStatus::Current,
        })
        .unwrap_err()
        .code,
        "auth.key_unavailable"
    );
    // begin_rotation: every other precondition of the rotation must hold
    // (future `valid_from` later than the current key's, fresh key ID, overlap
    // above the 900 s maximum TTL), so that the algorithm is the only reason
    // for the refusal. Round 2 handed it a backdated key, which `valid_from <
    // now` refused before the algorithm was looked at (governance
    // architecture verdict on d65e877, mutant M28). The Ed25519 control below
    // proves the preconditions hold: the same rotation with an Ed25519 key is
    // accepted.
    let rotation_key = |public_key: biscuit_auth::PublicKey| VerificationKey {
        key_id: 3,
        public_key,
        valid_from: now + Duration::from_secs(1),
        valid_until: None,
        status: VerificationKeyStatus::Current,
    };
    let old_key_valid_until = now + Duration::from_secs(2000);
    let (_issuer, mut ring) = issuer_and_ring(2, now);
    assert_eq!(
        ring.begin_rotation(rotation_key(p256.public()), old_key_valid_until, now)
            .unwrap_err()
            .code,
        "auth.key_unavailable"
    );
    assert_eq!(
        ring.public_keys()
            .iter()
            .map(|key| key.algorithm)
            .collect::<Vec<_>>(),
        ["Ed25519"],
        "a refused rotation leaves the ring unchanged"
    );
    let mut control = ring.clone();
    control
        .begin_rotation(
            rotation_key(KeyPair::new().public()),
            old_key_valid_until,
            now,
        )
        .expect("the same rotation with an Ed25519 key is accepted");
    assert_eq!(
        control
            .public_keys()
            .iter()
            .map(|key| key.algorithm)
            .collect::<Vec<_>>(),
        ["Ed25519", "Ed25519"]
    );
}

// --- Round 2: the double load is measured, not asserted ----------------------

#[test]
#[ignore = "timing measurement; run with --ignored --nocapture and record in evidence"]
fn double_load_cost_is_measured() {
    // The guard pass is the token-only load plus what authorize() reads on
    // it: the `dump()` walk (blocks_roundtrip_safe) and the `snapshot()`
    // (block scopes, holder operation bound). Round 2 timed the load alone;
    // this times the whole pass against the whole authorize(), three runs,
    // median reported.
    let now = at(1030);
    let (_issuer, ring, verified) = issued_token_and_key(94, now);
    let token = SensitiveToken::from_transport(verified.to_base64().unwrap()).unwrap();
    let iterations = 2_000u32;
    let mut guard_runs = Vec::new();
    let mut full_runs = Vec::new();
    for _ in 0..3 {
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            let signed_blocks = verified.authorizer().unwrap();
            let dumped = signed_blocks.dump();
            let snapshot = signed_blocks.snapshot().unwrap();
            std::hint::black_box((dumped, snapshot));
        }
        guard_runs.push(started.elapsed() / iterations);
        let started = std::time::Instant::now();
        for _ in 0..iterations {
            authorize(
                &token,
                mission_context(now + Duration::from_secs(1), "read"),
                &ring,
                &mut checker(),
            )
            .unwrap();
        }
        full_runs.push(started.elapsed() / iterations);
    }
    guard_runs.sort();
    full_runs.sort();
    let guard = guard_runs[1];
    let full = full_runs[1];
    println!(
        "double-load: guard pass (load + dump + snapshot) runs = {guard_runs:?}, full authorize() runs = {full_runs:?}; median guard = {guard:?}, median full = {full:?}, share = {:.1}%",
        guard.as_secs_f64() / full.as_secs_f64() * 100.0
    );
}
