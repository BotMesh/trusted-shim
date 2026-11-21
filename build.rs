fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure()
        .compile_with_config(config, &["proto/stage.proto"], &["proto"])
        .expect("compile upstream StageService protocol");
    println!("cargo:rerun-if-changed=proto/stage.proto");
}
