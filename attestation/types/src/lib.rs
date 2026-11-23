//! Shared encoding only. Computing expected public values never authenticates evidence.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trusted_contracts::ExecutionIdentity;
pub const MAX_WITNESS_BYTES: usize = 2 * 1024 * 1024;
pub const DCAP_DOMAIN: &str = "trusted-shim.remote-attestation.dcap.v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Hardware,
    Simulation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub domain: String,
    pub mode: Mode,
    pub platform: String,
    pub expected_measurement: String,
    pub init_data_sha256: String,
    pub endpoint_key_sha256: String,
    pub execution: ExecutionIdentity,
    pub request_sha256: String,
    pub nonce: String,
    pub expires_at: u64,
}

pub fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    value.sort_all_objects();
    Ok(serde_json::to_vec(&value)?)
}

/// Collateral is Automata's Solidity ABI encoding, collected outside the guest.
/// Signed JSON is kept intact by the upstream parser; never canonicalize it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcapWitness {
    pub binding: Binding,
    pub evidence: Vec<u8>,
    pub collateral: Vec<u8>,
    pub verification_time: u64,
    pub min_tcb_evaluation_data_number: u32,
}

impl DcapWitness {
    /// A receipt for the approved guest must authenticate these exact bytes.
    /// In particular the TCB floor, clock input and complete launch binding are
    /// committed, so the prover cannot substitute a weaker acceptance policy.
    pub fn expected_public_values(&self) -> Result<Vec<u8>> {
        canonical(&serde_json::json!({
            "domain": DCAP_DOMAIN,
            "witness_sha256": hex::encode(Sha256::digest(canonical(self)?)),
        }))
    }
}
