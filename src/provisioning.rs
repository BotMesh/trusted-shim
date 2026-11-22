//! Private provisioning envelope, never an App spec or a heartbeat payload.
//! Only the owning node agent may submit this to the same-UID daemon socket.
use crate::{
    admission::execution_digest,
    ledger_transport::{grant_from_wire, grant_to_wire, wire},
    runtime::LaunchRequest,
    Error, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use prost::Message;
use serde::{Deserialize, Serialize};
use trusted_rail::{EvaluationRequest, ExecutionGrant};

pub const MAX_PROVISION_BYTES: usize = 4 * 1024 * 1024;

/// Serialize is provided only for this private transport. No Debug: native bytes
/// contain split launch credentials, and both the
/// ledger token and grant are secrets. Nothing here belongs in a status record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub request: LaunchRequest,
    pub native_create_base64: String,
    pub native_policy_sha256: String,
    pub authorization: EvaluationRequest,
    pub grant_base64: String,
    pub ledger_token: String,
}

impl ProvisionRequest {
    pub fn new(
        request: LaunchRequest,
        native: &[u8],
        native_policy_sha256: String,
        authorization: EvaluationRequest,
        grant: ExecutionGrant,
        ledger_token: String,
    ) -> Result<Self> {
        let grant = grant_to_wire(grant).map_err(|_| Error::InvalidContract)?;
        let result = Self {
            request,
            native_create_base64: STANDARD.encode(native),
            native_policy_sha256,
            authorization,
            grant_base64: STANDARD.encode(grant.encode_to_vec()),
            ledger_token,
        };
        result.validate()?;
        Ok(result)
    }

    /// Checks the transport's identity, bounds and exact grant/request binding.
    /// This is not proof verification: only central Consume authorizes dispatch.
    pub fn validate(&self) -> Result<()> {
        if self.request.driver != "openshell"
            || self.request.execution != self.authorization.execution
            || self.authorization.operation != "runtime.create"
            || self.ledger_token.len() != 64
            || !self
                .ledger_token
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || self.native_policy_sha256.len() != 64
            || !self
                .native_policy_sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            || serde_json::to_vec(self)
                .map_err(|_| Error::InvalidContract)?
                .len()
                > MAX_PROVISION_BYTES
        {
            return Err(Error::InvalidContract);
        }
        self.native_bytes()?;
        execution_digest(&self.authorization, &self.grant()?)?;
        Ok(())
    }

    pub(crate) fn native_bytes(&self) -> Result<Vec<u8>> {
        if self.native_create_base64.is_empty() || self.native_create_base64.len() > 1_398_104 {
            return Err(Error::InvalidContract);
        }
        let bytes = STANDARD
            .decode(&self.native_create_base64)
            .map_err(|_| Error::InvalidContract)?;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::InvalidContract);
        }
        Ok(bytes)
    }

    pub(crate) fn grant(&self) -> Result<ExecutionGrant> {
        if self.grant_base64.len() > 32 * 1024 {
            return Err(Error::InvalidContract);
        }
        let bytes = STANDARD
            .decode(&self.grant_base64)
            .map_err(|_| Error::InvalidContract)?;
        let grant = wire::Grant::decode(bytes.as_slice()).map_err(|_| Error::InvalidContract)?;
        grant_from_wire(grant).map_err(|_| Error::InvalidContract)
    }
}
