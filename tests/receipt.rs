#![cfg(feature = "ziren")]
use sha2::{Digest, Sha256};
use trusted_shim::{contracts::ProofKind, proof::*, ziren::ZirenGroth16Verifier};

#[test]
fn real_crypto_verifier_rejects_forged_proofs_and_substituted_programs() {
    let key = [1u8; 32];
    let program = ProgramRef {
        kind: ProofKind::PolicyEvaluation,
        program_sha256: "1".repeat(64),
        verifying_key_sha256: hex::encode(Sha256::digest(key)),
    };
    assert!(ZirenGroth16Verifier::new(program.clone(), &hex::encode([2u8; 32])).is_err());
    let verifier = ZirenGroth16Verifier::new(program.clone(), &hex::encode(key)).unwrap();
    let hash: [u8; 32] = Sha256::digest(*zkm_verifier::GROTH16_VK_BYTES).into();
    let forged = serde_json::json!({"Groth16":{"public_inputs":["0","0","0"],"encoded_proof":"00".repeat(256),"raw_proof":"","groth16_vkey_hash":hash}});
    let receipt = ProofReceipt {
        job_id: "job".into(),
        encoded_receipt: serde_json::to_vec(&forged).unwrap(),
    };
    assert!(verifier.verify(&program, &receipt, b"expected").is_err());
    let mut other = program.clone();
    other.kind = ProofKind::RemoteAttestation;
    assert!(verifier.verify(&other, &receipt, b"expected").is_err());
    let malformed = ProofReceipt {
        job_id: "job".into(),
        encoded_receipt: b"{\"Core\":[]}".to_vec(),
    };
    assert!(verifier.verify(&program, &malformed, b"expected").is_err());
}
