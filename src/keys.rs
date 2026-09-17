use crate::AuthzError;
use biscuit_auth::PublicKey;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MIN_ROTATION_OVERLAP: Duration = Duration::from_secs(900);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationKeyStatus {
    Current,
    Retiring,
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    pub key_id: u32,
    pub public_key: PublicKey,
    pub valid_from: SystemTime,
    pub valid_until: Option<SystemTime>,
    pub status: VerificationKeyStatus,
}

#[derive(Clone, Debug)]
pub struct PublicKeyMetadata {
    pub key_id: u32,
    pub algorithm: &'static str,
    pub public_key_hex: String,
    pub valid_from: SystemTime,
    pub valid_until: Option<SystemTime>,
    pub status: VerificationKeyStatus,
}

#[derive(Clone, Debug)]
pub struct VerificationKeyRing {
    keys: BTreeMap<u32, VerificationKey>,
    used_key_ids: BTreeSet<u32>,
}

/// biscuit-auth 6.0 keys are algorithm-tagged; the security boundary is stated
/// for Ed25519 only, so every key entry point refuses anything else instead of
/// accepting it and reporting it as Ed25519.
pub(crate) fn is_ed25519(key: &PublicKey) -> bool {
    matches!(
        key.algorithm(),
        biscuit_auth::format::schema::public_key::Algorithm::Ed25519
    )
}

impl VerificationKeyRing {
    pub fn new(current: VerificationKey) -> Result<Self, AuthzError> {
        if !is_ed25519(&current.public_key)
            || current.status != VerificationKeyStatus::Current
            || current.valid_until.is_some()
            || current.valid_from.duration_since(UNIX_EPOCH).is_err()
        {
            return Err(AuthzError::new("auth.key_unavailable"));
        }
        let key_id = current.key_id;
        Ok(Self {
            keys: BTreeMap::from([(key_id, current)]),
            used_key_ids: BTreeSet::from([key_id]),
        })
    }

    pub fn begin_rotation(
        &mut self,
        new_key: VerificationKey,
        old_key_valid_until: SystemTime,
        now: SystemTime,
    ) -> Result<(), AuthzError> {
        let current = self
            .keys
            .values()
            .next()
            .ok_or_else(|| AuthzError::new("auth.key_unavailable"))?;
        let overlap_covers_max_ttl = old_key_valid_until
            .duration_since(new_key.valid_from)
            .is_ok_and(|overlap| overlap >= MIN_ROTATION_OVERLAP);
        if !is_ed25519(&new_key.public_key)
            || self.keys.len() != 1
            || now.duration_since(UNIX_EPOCH).is_err()
            || current.status != VerificationKeyStatus::Current
            || current.valid_until.is_some()
            || now < current.valid_from
            || new_key.status != VerificationKeyStatus::Current
            || new_key.valid_until.is_some()
            || new_key.valid_from < now
            || new_key.valid_from <= current.valid_from
            || !overlap_covers_max_ttl
            || self.used_key_ids.contains(&new_key.key_id)
            || self
                .keys
                .values()
                .any(|key| key.public_key == new_key.public_key)
        {
            return Err(AuthzError::new("auth.key_unavailable"));
        }
        let current = self
            .keys
            .values_mut()
            .next()
            .ok_or_else(|| AuthzError::new("auth.key_unavailable"))?;
        current.status = VerificationKeyStatus::Retiring;
        current.valid_until = Some(old_key_valid_until);
        self.used_key_ids.insert(new_key.key_id);
        self.keys.insert(new_key.key_id, new_key);
        Ok(())
    }

    pub fn finish_rotation(&mut self, now: SystemTime) -> Result<(), AuthzError> {
        // Compute the survivors first and validate the post-condition BEFORE
        // mutating, so a rejected finish leaves the ring byte-for-byte
        // unchanged. Retaining in place and validating afterwards could empty
        // the ring on the error path (e.g. after the new Current was revoked and
        // the old Retiring key has expired) — fail-closed, but a silent
        // mutation the caller did not ask for.
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

    pub fn revoke_key(&mut self, key_id: u32) {
        self.keys.remove(&key_id);
    }

    pub(crate) fn select(&self, key_id: u32, now: SystemTime) -> Result<PublicKey, AuthzError> {
        let key = self
            .keys
            .get(&key_id)
            .ok_or_else(|| AuthzError::new("auth.key_unavailable"))?;
        if now < key.valid_from
            || key
                .valid_until
                .is_some_and(|valid_until| now >= valid_until)
        {
            return Err(AuthzError::new("auth.key_unavailable"));
        }
        Ok(key.public_key)
    }

    pub fn public_keys(&self) -> Vec<PublicKeyMetadata> {
        self.keys
            .values()
            .map(|key| PublicKeyMetadata {
                key_id: key.key_id,
                // Every entry point refuses non-Ed25519 keys, so this is the
                // only value the ring can hold; derived rather than assumed so a
                // relaxed entry point would misreport nothing.
                algorithm: match key.public_key.algorithm() {
                    biscuit_auth::format::schema::public_key::Algorithm::Ed25519 => "Ed25519",
                    biscuit_auth::format::schema::public_key::Algorithm::Secp256r1 => "P-256",
                },
                public_key_hex: key.public_key.to_bytes_hex(),
                valid_from: key.valid_from,
                valid_until: key.valid_until,
                status: key.status,
            })
            .collect()
    }
}
