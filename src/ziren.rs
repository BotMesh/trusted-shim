//! Reuses the upstream Groth16 verifier, including its recursion VK allowlist.
use crate::{proof::*, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zkm_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

pub struct ZirenGroth16Verifier {
    approved: ProgramRef,
    program_vkey_hash: String,
}

/// Public contract-call inputs, exported only after native cryptographic verification.
/// This proves the committed computation; it is not a fresh execution grant.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmProof {
    pub program_vkey: String,
    pub public_values: String,
    pub proof: String,
    pub verifier_hash: String,
    pub program_sha256: String,
}

// The network sends the SDK's externally tagged ZKMProof JSON. Only the
// Groth16 variant is admitted. Public-input strings are never trusted; the
// verifier recomputes them from the approved program key and expected bytes.
#[derive(Deserialize)]
enum NetworkProof {
    Groth16(Groth16Wire),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Groth16Wire {
    public_inputs: Vec<String>,
    encoded_proof: String,
    raw_proof: String,
    groth16_vkey_hash: [u8; 32],
}

impl ZirenGroth16Verifier {
    pub fn evm_proof(&self, receipt: &ProofReceipt, expected: &[u8]) -> Result<EvmProof> {
        self.verify(&self.approved, receipt, expected)?;
        let bytes = proof_bytes(receipt)?;
        Ok(EvmProof {
            program_vkey: self.program_vkey_hash.clone(),
            public_values: format!("0x{}", hex::encode(expected)),
            proof: format!("0x{}", hex::encode(bytes)),
            verifier_hash: format!("0x{}", hex::encode(Sha256::digest(*GROTH16_VK_BYTES))),
            program_sha256: self.approved.program_sha256.clone(),
        })
    }

    /// `program_vkey_hash` is vk.bytes32() from the approved ELF build manifest.
    /// ProgramRef.verifying_key_sha256 commits to its decoded 32 bytes. The
    /// gateway approves the ELF/key mapping; a worker cannot choose this manifest.
    pub fn new(approved: ProgramRef, program_vkey_hash: &str) -> Result<Self> {
        let hash = hex::decode(
            program_vkey_hash
                .strip_prefix("0x")
                .unwrap_or(program_vkey_hash),
        )
        .map_err(|_| Error::InvalidContract)?;
        if hash.len() != 32
            || approved.program_sha256.len() != 64
            || hex::encode(Sha256::digest(&hash)) != approved.verifying_key_sha256
        {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            approved,
            program_vkey_hash: format!("0x{}", hex::encode(hash)),
        })
    }
}
impl ReceiptVerifier for ZirenGroth16Verifier {
    fn verify(&self, program: &ProgramRef, receipt: &ProofReceipt, expected: &[u8]) -> Result<()> {
        if program != &self.approved
            || receipt.encoded_receipt.len() > 1024 * 1024
            || expected.is_empty()
            || expected.len() > trusted_rail::rego::MAX_PUBLIC_BYTES
        {
            return Err(Error::Untrusted);
        }
        let bytes = proof_bytes(receipt)?;
        Groth16Verifier::verify(&bytes, expected, &self.program_vkey_hash, *GROTH16_VK_BYTES)
            .map_err(|_| Error::Untrusted)
    }
}

fn proof_bytes(receipt: &ProofReceipt) -> Result<Vec<u8>> {
    let NetworkProof::Groth16(wire) =
        serde_json::from_slice(&receipt.encoded_receipt).map_err(|_| Error::Untrusted)?;
    let key_hash: [u8; 32] = Sha256::digest(*GROTH16_VK_BYTES).into();
    if wire.groth16_vkey_hash != key_hash
        || wire.public_inputs.len() != 3
        || wire.encoded_proof.len() != 512
        || wire.raw_proof.len() > 64 * 1024
    {
        return Err(Error::Untrusted);
    }
    let proof = hex::decode(&wire.encoded_proof).map_err(|_| Error::Untrusted)?;
    Ok([key_hash[..4].to_vec(), proof].concat())
}
