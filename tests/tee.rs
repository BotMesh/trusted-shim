//! Protocol/orchestration simulation. Fake receipts below are NOT ZK proofs.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{atomic::Ordering, Arc};
use trusted_shim::{
    contracts::ProofKind,
    machine::{MachineConfig, TeePlatform},
    runtime::{LaunchRequest, RuntimeDriver, RuntimeState},
    tee::{
        canonical,
        trustee::{wire, Trustee},
        CocoEvidence, Mode, TeeDriver,
    },
};

#[path = "support/tee.rs"]
mod support;
use support::{config, Lab, ProofDouble, ReceiptDouble};

#[path = "tee/tls.rs"]
mod tls;

fn request(id: &str) -> LaunchRequest {
    serde_json::from_value(json!({
        "execution":{"namespace":"simulation","workload":"tee","allocation_id":id,"lease_id":"launch","generation":1,"node_id":"test-node"},
        "driver":"tee-simulation","image":"alpine:3.21","command":["sleep","300"],"environment":{},
        "limits":{"cpu_millicores":250,"memory_bytes":33554432},
        "policy":{"issuer":"test","policy_id":"no-action-policy-claim","version":0,"sha256":""},
        "trust":{"attestation":{"mode":"required","profile":"sample"},"policy_proof":"not_required","attestation_proof":"required"},
        "services":[],"driver_options":{"stop_timeout_s":1}
    })).unwrap()
}

#[test]
fn machine_selection_never_promotes_discovery_or_sample_to_hardware() {
    let mut machine = MachineConfig::default();
    assert_eq!(machine.resolve(vec![]).unwrap().drivers, ["docker"]);
    assert!(machine.resolve(vec![TeePlatform::IntelTdx]).is_err());
    machine.tee = Some(config());
    let profile = machine.resolve(vec![]).unwrap();
    assert_eq!(profile.drivers, ["tee-simulation"]);
    assert!(!profile.attestation_verified);
    assert!(profile.tee_driver_configured);
    machine.labels.insert("runtime.driver".into(), "tee".into());
    assert!(machine.resolve(vec![]).is_err());
    machine.labels.clear();
    for (platform, device) in [
        ("snp", TeePlatform::AmdSevSnp),
        ("tdx", TeePlatform::IntelTdx),
    ] {
        let tee = machine.tee.as_mut().unwrap();
        tee.mode = Mode::Hardware;
        tee.platform = platform.into();
        assert!(machine.resolve(vec![]).is_err());
        assert_eq!(machine.resolve(vec![device]).unwrap().drivers, ["tee"]);
    }
    machine.tee.as_mut().unwrap().platform = "sample".into();
    assert!(machine.resolve(vec![TeePlatform::IntelTdx]).is_err());
    machine.tee.as_mut().unwrap().platform = "sgx".into();
    assert!(machine.resolve(vec![TeePlatform::IntelSgx]).is_err());
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("sev-guest"), b"not a device").unwrap();
    std::os::unix::fs::symlink("/dev/null", root.path().join("tdx_guest")).unwrap();
    assert!(trusted_shim::machine::detect_devices(root.path())
        .unwrap()
        .is_empty());
}

#[test]
fn explicit_contracts_and_canonical_configuration() {
    let mut cfg = config();
    for endpoint in [
        "http://attester/aa/evidence",
        "http://127.0.0.1/aa/evidence?encoding=raw",
        "http://user@127.0.0.1/aa/evidence",
    ] {
        cfg.evidence_endpoint = endpoint.into();
        assert!(cfg.validate().is_err());
    }
    cfg = config();
    cfg.program.kind = ProofKind::PolicyEvaluation;
    assert!(cfg.validate().is_err());
    let a: Value = serde_json::from_str(r#"{"z":{"b":1,"a":2},"a":0}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":0,"z":{"a":2,"b":1}}"#).unwrap();
    assert_eq!(canonical(&a).unwrap(), canonical(&b).unwrap());
}

fn no_container_intent(root: &std::path::Path) {
    assert!(!std::fs::read_dir(root.join("tee/runtime"))
        .unwrap()
        .any(|e| e.unwrap().path().extension().is_some_and(|v| v == "json")));
}

#[tokio::test]
async fn bad_quote_and_bad_proof_cannot_create_runtime() {
    for bad_quote in [true, false] {
        let lab = Lab::start(bad_quote, None).await;
        let root = tempfile::tempdir().unwrap();
        let proof = Arc::new(ProofDouble::default());
        let driver = lab.driver(root.path(), proof.clone(), true).await;
        assert!(driver.launch(&request("rejected")).await.is_err());
        assert_eq!(
            proof.submitted.load(Ordering::SeqCst),
            usize::from(!bad_quote)
        );
        no_container_intent(root.path());
        let mut downgraded = request("downgrade");
        downgraded.driver = "tee".into();
        assert!(driver.launch(&downgraded).await.is_err());
    }
}

#[tokio::test]
async fn ambiguous_submission_is_not_repeated_or_rebound_after_restart() {
    let lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    proof.fail_submit.store(true, Ordering::SeqCst);
    let request = request("restart");
    let driver = lab.driver(root.path(), proof.clone(), true).await;
    assert!(driver.launch(&request).await.is_err());
    drop(driver);
    let driver = lab.driver(root.path(), proof.clone(), true).await;
    let mut changed = request.clone();
    changed.image = "other:tag".into();
    assert!(driver.launch(&changed).await.is_err());
    assert!(driver.launch(&request).await.is_err()); // resumed receipt is rejected
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
    no_container_intent(root.path());
}

#[tokio::test]
#[ignore = "requires local Docker and preloaded alpine:3.21; receipts are orchestration doubles"]
async fn simulated_startup_preserves_runtime_on_restart_and_fences_cleanup() {
    lifecycle(None).await;
}

#[tokio::test]
#[ignore = "requires Docker, alpine:3.21 and TRUSTEE_TEST_ENDPOINT running stock grpc-as; no prover"]
async fn stock_trustee_sample_startup() {
    lifecycle(Some(
        std::env::var("TRUSTEE_TEST_ENDPOINT").expect("explicit test endpoint"),
    ))
    .await;
}

async fn lifecycle(endpoint: Option<String>) {
    let lab = Lab::start(false, endpoint).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    let request = request(root.path().file_name().unwrap().to_str().unwrap());
    let driver = lab.driver(root.path(), proof.clone(), false).await;
    let before = driver.launch(&request).await.unwrap();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .output();
        }
    }
    let _cleanup = Cleanup(before.runtime_id.clone());
    assert_eq!(before.state, RuntimeState::Ready);
    drop(driver);
    let driver = lab.driver(root.path(), proof.clone(), false).await;
    let after = driver.launch(&request).await.unwrap();
    assert_eq!(before.runtime_id, after.runtime_id);
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
    driver.delete(&request.execution).await.unwrap();
    assert!(driver.launch(&request).await.is_err());
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires explicit TRUSTEE_TEST_ENDPOINT running stock grpc-as; no prover"]
async fn stock_trustee_accepts_sample_binding_and_rejects_substitution() {
    use wire::individual_attestation_request::{InitData, RuntimeData};
    let endpoint = std::env::var("TRUSTEE_TEST_ENDPOINT").unwrap();
    let mut client = wire::attestation_service_client::AttestationServiceClient::connect(endpoint)
        .await
        .unwrap();
    let data = b"public simulation challenge";
    let mut request = wire::AttestationRequest {
        policy_ids: vec!["default".into()],
        verification_requests: vec![wire::IndividualAttestationRequest {
            tee: "sample".into(),
            evidence: URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "svn":"1", "report_data":STANDARD.encode(Sha256::digest(data))
                }))
                .unwrap(),
            ),
            runtime_data: Some(RuntimeData::RawRuntimeData(
                URL_SAFE_NO_PAD.encode(Sha256::digest(data)),
            )),
            init_data: Some(InitData::InitDataDigest(URL_SAFE_NO_PAD.encode([0x11; 32]))),
            runtime_data_hash_algorithm: "sha256".into(),
        }],
    };
    let response = client.attestation_evaluate(request.clone()).await;
    if let Err(error) = response {
        panic!("public synthetic sample rejected: {error}");
    }
    request.verification_requests[0].runtime_data = Some(RuntimeData::RawRuntimeData(
        URL_SAFE_NO_PAD.encode(b"substitution"),
    ));
    assert!(client.attestation_evaluate(request).await.is_err());
}

#[tokio::test]
async fn expired_admission_and_changed_profile_do_not_create_a_runtime() {
    let mut lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    proof.fail_submit.store(true, Ordering::SeqCst);
    let request = request("expired");
    let driver = lab.driver(root.path(), proof.clone(), true).await;
    assert!(driver.launch(&request).await.is_err());
    drop(driver);
    let path = std::fs::read_dir(root.path().join("tee"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    let mut pending: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    pending["binding"]["expires_at"] = json!(1);
    for authorized in [false, true] {
        pending["authorized"] = json!(authorized);
        std::fs::write(&path, serde_json::to_vec(&pending).unwrap()).unwrap();
        let driver = lab.driver(root.path(), proof.clone(), true).await;
        assert!(driver.launch(&request).await.is_err());
        no_container_intent(root.path());
    }
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
    lab.config.endpoint_key_sha256 = "33".repeat(32);
    let trustee = Trustee::connect(&lab.config.trustee_endpoint, vec!["default".into()], None)
        .await
        .unwrap();
    assert!(TeeDriver::new(
        root.path(),
        "test-node".into(),
        lab.config.clone(),
        Arc::new(CocoEvidence::new(lab.config.evidence_endpoint.clone()).unwrap()),
        trustee,
        proof,
        Arc::new(ReceiptDouble { reject: true })
    )
    .is_err());
}

#[tokio::test]
async fn disconnected_services_do_not_prevent_constructing_cleanup_adapters() {
    let program = config().program;
    let elf = b"test-only ELF bytes".to_vec();
    let mut program = program;
    program.program_sha256 = hex::encode(Sha256::digest(&elf));
    assert!(trusted_shim::network::ZirenNetwork::connect_lazy(
        "http://127.0.0.1:1",
        "test-token",
        program,
        elf
    )
    .is_ok());
    assert!(
        Trustee::connect("http://127.0.0.1:1", vec!["default".into()], None)
            .await
            .is_ok()
    );
}

#[cfg(feature = "ziren")]
#[tokio::test]
async fn daemon_recovers_simulation_configuration_without_contacting_proof_services() {
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = tempfile::tempdir().unwrap();

    let mut cfg = config();
    // Synthetic artifact identities exercise startup validation only, never proving.
    cfg.elf_file = root.path().join("synthetic.elf");
    let elf = b"not a runnable guest";
    std::fs::write(&cfg.elf_file, elf).unwrap();
    cfg.program.program_sha256 = hex::encode(Sha256::digest(elf));
    cfg.program_vkey_hash = "00".repeat(32);
    cfg.program.verifying_key_sha256 = hex::encode(Sha256::digest([0u8; 32]));
    cfg.proof_token_file = root.path().join("test.token");
    std::fs::write(&cfg.proof_token_file, b"synthetic-test-token").unwrap();
    std::fs::set_permissions(
        &cfg.proof_token_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let machine = MachineConfig {
        tee: Some(cfg),
        ..Default::default()
    };
    for native in [false, true] {
        let state = root.path().join(if native { "native" } else { "docker" });
        for _ in 0..2 {
            let mut options = json!({"machine":machine});
            if native {
                options["openshell"] = json!({"socket":root.path().join("compute.sock"), "admission_policy":"approved", "ledger_endpoint":"http://127.0.0.1:1"});
            }
            let config = serde_json::from_value(options).unwrap();
            let stop = tokio_util::sync::CancellationToken::new();
            let daemon_state = state.clone();
            let daemon_stop = stop.clone();
            let task = tokio::spawn(async move {
                trusted_shim::daemon::serve_configured(
                    &daemon_state,
                    "test-node".into(),
                    config,
                    daemon_stop,
                )
                .await
            });
            let socket = state.join("control.sock");
            for _ in 0..100 {
                if socket.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
            stream.write_all(&serde_json::to_vec(&json!({"protocol":1,"node_id":"test-node","command":{"operation":"capabilities"}})).unwrap()).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            let response: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(response["result"]["drivers"], json!(["tee-simulation"]));
            assert_eq!(
                response["result"]["machine_config_sha256"],
                machine.digest().unwrap()
            );
            assert_eq!(response["result"]["machine"]["attestation_verified"], false);
            stop.cancel();
            task.await.unwrap().unwrap();
        }
    }
}
