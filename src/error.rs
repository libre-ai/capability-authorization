use std::error::Error;
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthzError {
    pub code: &'static str,
    pub root_block_id: Option<String>,
}

impl AuthzError {
    pub(crate) fn new(code: &'static str) -> Self {
        assert!(
            canonical_code(code),
            "non-canonical authorization refusal code"
        );
        Self {
            code,
            root_block_id: None,
        }
    }

    pub(crate) fn for_root(code: &'static str, root_block_id: &str) -> Self {
        assert!(
            canonical_code(code),
            "non-canonical authorization refusal code"
        );
        Self {
            code,
            root_block_id: Some(root_block_id.to_owned()),
        }
    }
}

fn canonical_code(code: &str) -> bool {
    matches!(
        code,
        "auth.tenant_mismatch"
            | "auth.biscuit_invalid"
            | "auth.biscuit_revoked"
            | "auth.agent_revoked"
            | "auth.operation_denied"
            | "auth.key_unavailable"
    )
}

impl Display for AuthzError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)?;
        if let Some(root_block_id) = &self.root_block_id {
            write!(formatter, " ({root_block_id})")?;
        }
        Ok(())
    }
}

impl Error for AuthzError {}
