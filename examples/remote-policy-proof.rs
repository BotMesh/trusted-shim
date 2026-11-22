//! Explicit remote proof smoke test; never dispatches actions or starts a prover.
use sha2::{Digest, Sha256};
use std::{error::Error, time::Duration};
use trusted_shim::{
    contracts::ProofKind, network::ZirenNetwork, proof::*, ziren::ZirenGroth16Verifier,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(5..=6).contains(&args.len()) {
        return Err(
            "usage: remote-policy-proof ELF VK_BYTES32 CANONICAL_WITNESS JOB_ID [RECEIPT_OUTPUT]"
                .into(),
        );
    }
    let elf = std::fs::read(&args[1])?;
    let key = hex::decode(args[2].strip_prefix("0x").unwrap_or(&args[2]))?;
    let witness = std::fs::read(&args[3])?;
    // Run the actual native engine, rather than trusting a supplied expected result.
    let expected = trusted_rail::rego::evaluate_witness(&witness)?;
    let program = ProgramRef {
        kind: ProofKind::PolicyEvaluation,
        program_sha256: hex::encode(Sha256::digest(&elf)),
        verifying_key_sha256: hex::encode(Sha256::digest(&key)),
    };
    let verifier = ZirenGroth16Verifier::new(program.clone(), &args[2])?;
    let endpoint = std::env::var("TRUSTED_PROOF_ENDPOINT")?;
    let token = std::env::var("TRUSTED_PROOF_TOKEN")?;
    let mut network = ZirenNetwork::connect(&endpoint, &token, program.clone(), elf).await?;
    if let Ok(key) = std::env::var("TRUSTED_PROOF_SIGNER") {
        let key = hex::decode(key.strip_prefix("0x").unwrap_or(&key))?;
        network = network.with_fleet_signer(&key)?;
    }
    let id = network
        .submit(&ProofRequest {
            request_id: args[4].clone(),
            program: program.clone(),
            witness,
            expected_public_values: expected.clone(),
        })
        .await?;
    println!("submitted {id}");
    tokio::time::timeout(Duration::from_secs(1800), async {
        loop {
            match network.status(&id).await? {
                ProofStatus::Pending => tokio::time::sleep(Duration::from_secs(3)).await,
                ProofStatus::Failed => return Err(trusted_shim::Error::Untrusted),
                ProofStatus::Complete(receipt) => {
                    verifier.verify(&program, &receipt, &expected)?;
                    let mut changed = expected.clone();
                    changed[0] ^= 1;
                    if verifier.verify(&program, &receipt, &changed).is_ok() {
                        return Err(trusted_shim::Error::Untrusted);
                    }
                    if let Some(path) = args.get(5) {
                        std::fs::write(path, &receipt.encoded_receipt)
                            .map_err(|_| trusted_shim::Error::Unavailable)?;
                    }
                    println!("verified policy evaluation proof for {id}");
                    println!("rejected substituted public values");
                    return Ok(());
                }
            }
        }
    })
    .await??;
    Ok(())
}
