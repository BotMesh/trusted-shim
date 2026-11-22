//! Execution-only compatibility harness. Never approve this ELF for launching.
#![no_main]
zkm_zkvm::entrypoint!(main);
pub fn main() {
    let input = zkm_zkvm::io::read_vec();
    let output = trusted_shim_attestation::verify_quote_vector(&input).expect("invalid quote");
    zkm_zkvm::io::commit_slice(&output);
}
