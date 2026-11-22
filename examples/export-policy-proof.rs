//! Convert an existing remote receipt to verified EVM calldata. No network/prover.
use sha2::{Digest, Sha256};
use std::{error::Error, io::Write, os::unix::fs::OpenOptionsExt};
use trusted_shim::{
    contracts::ProofKind,
    proof::{ProgramRef, ProofReceipt},
    ziren::ZirenGroth16Verifier,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err(
            "usage: export-policy-proof ELF VK_BYTES32 CANONICAL_WITNESS RECEIPT OUTPUT".into(),
        );
    }
    let elf = std::fs::read(&args[1])?;
    let key = hex::decode(args[2].strip_prefix("0x").unwrap_or(&args[2]))?;
    let expected = trusted_rail::rego::evaluate_witness(&std::fs::read(&args[3])?)?;
    let verifier = ZirenGroth16Verifier::new(
        ProgramRef {
            kind: ProofKind::PolicyEvaluation,
            program_sha256: hex::encode(Sha256::digest(&elf)),
            verifying_key_sha256: hex::encode(Sha256::digest(&key)),
        },
        &args[2],
    )?;
    let receipt = ProofReceipt {
        job_id: "offline-export".into(),
        encoded_receipt: std::fs::read(&args[4])?,
    };
    let fixture = verifier.evm_proof(&receipt, &expected)?;
    // Public values can still contain tenant metadata; never overwrite a file or
    // follow an output symlink, and keep generated artifacts private.
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[5])?;
    output.write_all(&serde_json::to_vec_pretty(&fixture)?)?;
    output.sync_all()?;
    println!("Exported verified policy proof for EVM verification");
    Ok(())
}
