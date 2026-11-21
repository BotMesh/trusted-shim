use crate::{attestation::AttestationRequirement, proof::ProofRequirement, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trusted_contracts::{ExecutionIdentity, PolicyRef};
use trusted_data_router::ServiceSpec;
use trusted_rail::{EvaluationRequest, ExecutionGrant};

/// Hard limits, not merely Ray admission resources. An unsupported explicit
/// limit must fail; implementations must report effective values after launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu_millicores: Option<u64>,
    pub memory_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRequirements {
    pub attestation: AttestationRequirement,
    pub policy_proof: ProofRequirement,
    pub attestation_proof: ProofRequirement,
}

/// Built from existing app manifests by an authorized control-plane adapter.
/// `driver` identifies runtime infrastructure, not agent business logic. Environment
/// may contain credentials, so the launch request deliberately has no Debug impl.
pub struct LaunchRequest {
    pub execution: ExecutionIdentity,
    pub driver: String,
    pub image: String,
    pub command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub limits: ResourceLimits,
    pub policy: PolicyRef,
    pub trust: TrustRequirements,
    pub services: Vec<ServiceSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

#[derive(Clone, Debug)]
pub struct RuntimeStatus {
    pub execution: ExecutionIdentity,
    pub runtime_id: String,
    pub state: RuntimeState,
    pub effective_limits: ResourceLimits,
}

/// One machine, with no node selection or cluster resource allocator.
/// Each call must verify full execution ownership. Replayed launches are
/// idempotent for the same authorized request; divergent requests are rejected.
#[async_trait]
pub trait RuntimeDriver: Send + Sync {
    async fn launch(&self, request: &LaunchRequest) -> Result<RuntimeStatus>;
    async fn inspect(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus>;
    async fn stop(&self, execution: &ExecutionIdentity) -> Result<()>;
    /// Success means cleanup is confirmed, so Fleet may release reservations.
    /// Correctly owned cleanup must remain possible after trust credentials expire.
    async fn delete(&self, execution: &ExecutionIdentity) -> Result<()>;
}

/// A non-bypassable action boundary. The implementation checks/consumes the
/// central single-use grant against this exact request before invoking upstream
/// enforcement. Network connection authorization alone is not an execution grant.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// Returns a bounded application result. Streaming operations need a separate
    /// data-plane adapter; they must not tunnel payloads through the control gateway.
    async fn execute(&self, request: &EvaluationRequest, grant: &ExecutionGrant)
        -> Result<Vec<u8>>;
}
