use crate::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use trusted_contracts::{ExecutionIdentity, PolicyRef, Validity};

/// Docker/non-TEE runs explicitly skip attestation; skip never means verified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttestationRequirement {
    SkipNonTee,
    Required { profile: String },
}

/// Challenge creation, freshness and single-use consumption are trusted verifier
/// responsibilities. The endpoint key must belong to the measured trust boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationBinding {
    pub execution: ExecutionIdentity,
    pub challenge_id: String,
    pub nonce: Vec<u8>,
    pub endpoint_key_sha256: String,
    pub policy: PolicyRef,
    pub validity: Validity,
}

pub struct Evidence {
    pub profile: String,
    pub quote: Vec<u8>,
    pub endorsements: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationStatement {
    pub binding: AttestationBinding,
    pub profile: String,
    pub evidence_sha256: String,
    pub verifier_profile_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationOutcome {
    SkippedNonTee,
    Verified(Box<AttestationStatement>),
}

/// Reuse platform evidence verifiers (e.g. Trustee). A signed appraisal alone
/// must not be represented as a proof of the full hardware verification process.
#[async_trait]
pub trait AttestationVerifier: Send + Sync {
    async fn verify(
        &self,
        evidence: &Evidence,
        expected: &AttestationBinding,
    ) -> Result<AttestationStatement>;
}
