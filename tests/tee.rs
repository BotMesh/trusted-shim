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

#[tokio::test]
async fn dcap_submits_original_evidence_without_as_and_rejects_failed_proof() {
    use trusted_shim::{
        proof::*,
        tee::{AttestationGate, DcapConfig},
        Result,
    };
    struct RejectNetwork;
    #[async_trait::async_trait]
    impl ProofNetwork for RejectNetwork {
        async fn submit(&self, request: &ProofRequest) -> Result<String> {
            let witness: trusted_attestation_types::DcapWitness =
                serde_json::from_slice(&request.witness).unwrap();
            assert_eq!(
                witness.binding.domain,
                trusted_attestation_types::DCAP_DOMAIN
            );
            assert_eq!(witness.collateral, b"invalid-test-collateral");
            assert_eq!(
                request.expected_public_values,
                witness.expected_public_values().unwrap()
            );
            Ok(request.request_id.clone())
        }
        async fn status(&self, _: &str) -> Result<ProofStatus> {
            Ok(ProofStatus::Failed)
        }
    }
    let lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let collateral_file = root.path().join("collateral.abi");
    std::fs::write(&collateral_file, b"invalid-test-collateral").unwrap();
    let mut cfg = lab.config.clone();
    cfg.mode = Mode::Hardware;
    cfg.platform = "tdx".into();
    cfg.expected_measurement = "55".repeat(32);
    cfg.trustee_endpoint.clear();
    cfg.trustee_policy_ids.clear();
    cfg.dcap = Some(DcapConfig {
        collateral_file,
        min_tcb_evaluation_data_number: 20,
    });
    let gate = AttestationGate::new(
        root.path(),
        cfg.clone(),
        Arc::new(CocoEvidence::new(cfg.evidence_endpoint).unwrap()),
        None,
        Arc::new(RejectNetwork),
        Arc::new(ReceiptDouble { reject: true }),
    )
    .unwrap();
    let req = request("dcap-no-as");
    assert!(gate.authorize(&req.execution, &req).await.is_err());
    assert!(!root.path().join("tee/runtime").exists());
}

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

/// The launch digest the gate binds into the attestation report data, read
/// from its pending admission. Submission fails and receipts are rejected, so
/// nothing is authorized and no runtime is created.
async fn bound_request_sha256(lab: &Lab, request: &LaunchRequest) -> String {
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    proof.fail_submit.store(true, Ordering::SeqCst);
    let driver = lab.driver(root.path(), proof.clone(), true).await;
    assert!(driver.launch(request).await.is_err());
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
    no_container_intent(root.path());
    let path = std::fs::read_dir(root.path().join("tee"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "json"))
        .unwrap();
    let pending: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let bound = pending["binding"]["request_sha256"].as_str().unwrap();
    assert_eq!(
        bound,
        hex::encode(Sha256::digest(canonical(request).unwrap()))
    );
    bound.into()
}

#[tokio::test]
async fn attested_digest_of_an_unchanged_request_is_stable() {
    let lab = Lab::start(false, None).await;
    assert_eq!(
        bound_request_sha256(&lab, &request("pinned")).await,
        "b69471db0c81f96e6e95ace05d7383eccbea14c61869d611950b3de8366f82a2"
    );
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

#[tokio::test]
async fn resume_of_an_unlaunched_execution_submits_no_proof() {
    let lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    let driver = lab.driver(root.path(), proof.clone(), false).await;
    assert!(driver.resume(&request("never").execution).await.is_err());
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 0);
}

fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.0])
            .output();
    }
}

/// The admission records of `start`, as the gate stores them.
fn admission(root: &std::path::Path, start: u64) -> Value {
    let suffix = match start {
        0 => ".json".to_string(),
        n => format!(".start-{n}.json"),
    };
    let path = std::fs::read_dir(root.join("tee"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            let name = p.file_name().unwrap().to_str().unwrap();
            name.ends_with(&suffix) && (start != 0 || name.len() == 64 + ".json".len())
        })
        .unwrap();
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "requires local Docker and preloaded alpine:3.21; receipts are orchestration doubles"]
async fn simulated_resume_readmits_before_restarting_in_place() {
    let lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    let request = request(root.path().file_name().unwrap().to_str().unwrap());
    let execution = &request.execution;
    let driver = lab.driver(root.path(), proof.clone(), false).await;
    let launched = driver.launch(&request).await.unwrap();
    let _cleanup = Container(launched.runtime_id.clone());
    let id = docker(&["inspect", "-f", "{{.Id}}", &launched.runtime_id]);
    let submitted = || proof.submitted.load(Ordering::SeqCst);

    // A running runtime is left as it is, without a new admission.
    assert_eq!(
        driver.resume(execution).await.unwrap().state,
        RuntimeState::Ready
    );
    assert_eq!(submitted(), 1);

    docker(&["kill", &launched.runtime_id]);
    assert_eq!(
        driver.inspect(execution).await.unwrap().state,
        RuntimeState::Stopped
    );

    // A failed proof leaves it stopped. Retrying while that admission is
    // still current only queries it again; it never submits a second proof.
    proof.fail_proof.store(true, Ordering::SeqCst);
    assert!(driver.resume(execution).await.is_err());
    assert!(driver.resume(execution).await.is_err());
    assert_eq!(submitted(), 2);
    assert_eq!(
        driver.inspect(execution).await.unwrap().state,
        RuntimeState::Stopped
    );

    // Once it has expired, the next restart claims a new start of its own.
    let mut failed = admission(root.path(), 1);
    failed["binding"]["expires_at"] = json!(1);
    let failed_path = std::fs::read_dir(root.path().join("tee"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_str().unwrap().ends_with(".start-1.json"))
        .unwrap();
    std::fs::write(&failed_path, serde_json::to_vec(&failed).unwrap()).unwrap();
    proof.fail_proof.store(false, Ordering::SeqCst);
    let resumed = driver.resume(execution).await.unwrap();
    assert_eq!(resumed.state, RuntimeState::Ready);
    assert_eq!(submitted(), 3);
    // The same container, admitted afresh for exactly the launch's request.
    assert_eq!(
        docker(&["inspect", "-f", "{{.Id}}", &resumed.runtime_id]),
        id
    );
    let (launch, restart) = (admission(root.path(), 0), admission(root.path(), 2));
    assert_eq!(
        launch["binding"]["request_sha256"],
        restart["binding"]["request_sha256"]
    );
    assert_ne!(launch["binding"]["nonce"], restart["binding"]["nonce"]);
    assert_eq!(restart["authorized"], true);

    // An admission starts the container once: another crash needs another.
    docker(&["kill", &launched.runtime_id]);
    assert_eq!(
        driver.resume(execution).await.unwrap().state,
        RuntimeState::Ready
    );
    assert_eq!(submitted(), 4);
    // However often it restarts, only the current restart's record is kept.
    let restarts = std::fs::read_dir(root.path().join("tee"))
        .unwrap()
        .filter(|e| {
            let name = e.as_ref().unwrap().file_name();
            name.to_str().unwrap().contains(".start-")
        })
        .count();
    assert_eq!(restarts, 1);
    admission(root.path(), 3);

    // A stopped allocation is never resumed and costs no proof.
    driver.stop(execution).await.unwrap();
    assert!(driver.resume(execution).await.is_err());
    assert_eq!(submitted(), 4);
    driver.delete(execution).await.unwrap();
}

#[tokio::test]
#[ignore = "requires local Docker and preloaded alpine:3.21; receipts are orchestration doubles"]
async fn simulated_stop_during_a_resume_admission_is_final() {
    let lab = Lab::start(false, None).await;
    let root = tempfile::tempdir().unwrap();
    let proof = Arc::new(ProofDouble::default());
    let request = request(root.path().file_name().unwrap().to_str().unwrap());
    let execution = &request.execution;
    let driver = lab.driver(root.path(), proof.clone(), false).await;
    let launched = driver.launch(&request).await.unwrap();
    let _cleanup = Container(launched.runtime_id.clone());
    docker(&["kill", &launched.runtime_id]);
    proof.hold.store(true, Ordering::SeqCst);
    let (resumed, ()) = tokio::join!(driver.resume(execution), async {
        while proof.submitted.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // The admission holds no lock: inspect answers, and reports the restart.
        assert_eq!(
            driver.inspect(execution).await.unwrap().state,
            RuntimeState::Starting
        );
        // A concurrent resume joins nothing new.
        assert_eq!(
            driver.resume(execution).await.unwrap().state,
            RuntimeState::Starting
        );
        driver.stop(execution).await.unwrap();
        proof.hold.store(false, Ordering::SeqCst);
    });
    assert!(resumed.is_err());
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 2);
    assert_eq!(
        docker(&["inspect", "-f", "{{.State.Running}}", &launched.runtime_id]),
        "false"
    );
    assert_eq!(
        driver.inspect(execution).await.unwrap().state,
        RuntimeState::Stopped
    );
    driver.delete(execution).await.unwrap();
}
