use crate::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use trusted_contracts::ProofKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRequirement {
    NotRequired,
    Required,
}

/// The control plane approves both program identity and verifying-key identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramRef {
    pub kind: ProofKind,
    pub program_sha256: String,
    pub verifying_key_sha256: String,
}

/// No Debug/Serialize impl: witnesses must not accidentally enter logs.
pub struct ProofRequest {
    pub request_id: String,
    pub program: ProgramRef,
    pub witness: Vec<u8>,
    pub expected_public_values: Vec<u8>,
}

pub struct ProofReceipt {
    pub job_id: String,
    pub encoded_receipt: Vec<u8>,
}

pub enum ProofStatus {
    Pending,
    Complete(ProofReceipt),
    Failed,
}

/// Remote proving only. Implement through the approved proof-network API; no
/// local CPU/GPU prover fallback. Persist request/job identity to survive retries.
#[async_trait]
pub trait ProofNetwork: Send + Sync {
    async fn submit(&self, request: &ProofRequest) -> Result<String>;
    async fn status(&self, job_id: &str) -> Result<ProofStatus>;
}

/// Verify cryptography, pinned program/key and exact authenticated public values.
/// Success must never mean only a completed network job or a matching JSON hash.
pub trait ReceiptVerifier: Send + Sync {
    fn verify(
        &self,
        program: &ProgramRef,
        receipt: &ProofReceipt,
        expected_public_values: &[u8],
    ) -> Result<()>;
}
