#![no_main]
zkm_zkvm::entrypoint!(main);

pub fn main() {
    let input = zkm_zkvm::io::read_vec();
    let output = trusted_shim_attestation::evaluate_dcap(&input).expect("invalid DCAP attestation");
    zkm_zkvm::io::commit_slice(&output);
}
