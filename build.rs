fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    // Match Rail's non-Debug ExecutionGrant: accidental request logging must
    // not expose the single-use grant credential.
    config.skip_debug([
        ".trusted.ledger.v1.Grant",
        ".trusted.ledger.v1.ConsumeRequest",
    ]);
    tonic_prost_build::configure()
        .compile_with_config(
            config,
            &[
                "proto/stage.proto",
                "proto/ledger.proto",
                "proto/attestation.proto",
            ],
            &["proto"],
        )
        .expect("compile proof and authorization protocols");
    println!("cargo:rerun-if-changed=proto/stage.proto");
    println!("cargo:rerun-if-changed=proto/ledger.proto");
    println!("cargo:rerun-if-changed=proto/attestation.proto");
}
