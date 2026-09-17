#![forbid(unsafe_code)]

mod authorize;
mod error;
mod keys;
mod revocation;
mod token;

pub use authorize::{
    AuthorizationContext, AuthorizationDecision, CanonicalPolicy, VerifiedPrincipal, authorize,
};
pub use error::AuthzError;
pub use keys::{PublicKeyMetadata, VerificationKey, VerificationKeyRing, VerificationKeyStatus};
pub use revocation::{
    AgentRevocationRecord, AgentRevocationStore, RevocationChecker, RevocationRecord,
    RevocationStore, RevocationStoreUnavailable, RevocationTarget,
};
pub use token::{
    AgentIdentity, AttenuationRequest, BiscuitIssuer, BoundedBiscuit, IssuanceRequest,
    SensitiveToken, SerializedBiscuit, TokenBounds,
};
