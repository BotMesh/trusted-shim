use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use trusted_rail::{rego::*, *};
use trusted_shim::{contracts::*, ledger::SqliteLedger, proof::*};

// Orchestration test double: cryptographic verification is separately tested
// against the upstream Ziren verifier. Bytes here deliberately are not ZK proofs.
struct TestVerifier;
impl ReceiptVerifier for TestVerifier {
    fn verify(
        &self,
        _: &ProgramRef,
        receipt: &ProofReceipt,
        expected: &[u8],
    ) -> trusted_shim::Result<()> {
        if receipt.encoded_receipt == expected {
            Ok(())
        } else {
            Err(trusted_shim::Error::Untrusted)
        }
    }
}
fn program() -> ProgramRef {
    ProgramRef {
        kind: ProofKind::PolicyEvaluation,
        program_sha256: "1".repeat(64),
        verifying_key_sha256: "2".repeat(64),
    }
}
fn fixture() -> (PolicyBundle, EvaluationRequest) {
    let mut policy=PolicyBundle{policy:PolicyRef{issuer:"gateway".into(),policy_id:"allow-read".into(),version:1,sha256:String::new()},engine:engine_profile(),modules:[("p.rego".into(),"package trusted\ndefault decision := {\"decision\":\"deny\",\"reason_codes\":[]}\ndecision := {\"decision\":\"allow\",\"reason_codes\":[]} if {input.operation == \"read\"}".into())].into(),data:serde_json::json!({})};
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = EvaluationRequest {
        execution: ExecutionIdentity {
            namespace: "n".into(),
            workload: "w".into(),
            allocation_id: "a".into(),
            lease_id: "l".into(),
            generation: 1,
            node_id: "machine".into(),
        },
        principal: "alice".into(),
        action_id: "first".into(),
        operation: "read".into(),
        resource: "workspace".into(),
        parameters: serde_json::json!({}),
        context: serde_json::json!({"tenant":"n"}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: now,
        validity: Validity {
            not_before: now - 1,
            expires_at: now + 120,
        },
    };
    (policy, request)
}
fn open(path: &std::path::Path) -> SqliteLedger {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    SqliteLedger::open(path, program(), Arc::new(TestVerifier)).unwrap()
}
fn stage(l: &SqliteLedger, p: &PolicyBundle, r: &EvaluationRequest, id: &str) {
    l.activate(
        &r.execution,
        p,
        &r.context,
        &r.previous_state_root,
        "shared",
    )
    .unwrap();
    l.stage(id, r, 1).unwrap();
}

async fn serve(l: Arc<SqliteLedger>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(trusted_shim::ledger_transport::LedgerService::new(l).into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (address, task)
}

#[tokio::test]
async fn startup_snapshot_and_blocking_reservation_keep_proof_and_epoch_checks() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = open(&dir.path().join("ledger.sqlite"));
    let (policy, request) = fixture();
    assert!(ledger.authority_snapshot(&request.execution).is_err());
    ledger.set_budget("shared", 2).unwrap();
    stage(&ledger, &policy, &request, "startup");
    let (approved, context, root) = ledger.authority_snapshot(&request.execution).unwrap();
    assert_eq!(approved.policy, policy.policy);
    assert_eq!(context, request.context);
    assert_eq!(root, request.previous_state_root);
    let decision = RegorusEngine.evaluate(&approved, &request).unwrap();
    assert!(ledger.reserve_proven(&decision, b"forged").is_err());
    let proof = encode_public_values(&decision).unwrap();
    let grant = ledger.reserve_proven(&decision, &proof).unwrap();
    ledger
        .consume(&grant, &request.execution, &decision.request_sha256)
        .await
        .unwrap();
    assert!(ledger.reserve_proven(&decision, &proof).is_err());
    ledger.revoke(&request.execution).unwrap();
    assert!(ledger.authority_snapshot(&request.execution).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_credentials_fence_every_identity_dimension_and_consume_once_across_restart() {
    use trusted_shim::{
        ledger::LedgerPermission,
        ledger_transport::{wire, RemoteLedger},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let ledger = Arc::new(open(&path));
    ledger.set_budget("shared", 1).unwrap();
    let (p, r) = fixture();
    stage(&ledger, &p, &r, "remote");
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let proof = encode_public_values(&d).unwrap();
    let admission = ledger
        .issue_access(&r.execution, LedgerPermission::Admission, &r.validity)
        .unwrap();
    let execution = ledger
        .issue_access(&r.execution, LedgerPermission::Execution, &r.validity)
        .unwrap();
    let (address, task) = serve(ledger.clone()).await;
    let a = RemoteLedger::connect(&address, &admission, r.execution.clone())
        .await
        .unwrap();
    let e = RemoteLedger::connect(&address, &execution, r.execution.clone())
        .await
        .unwrap();
    assert!(e.reserve(&d, Some(&proof)).await.is_err());
    assert!(a.reserve(&d, None).await.is_err());
    assert!(a.reserve(&d, Some(b"not a proof")).await.is_err());

    // Raw gRPC deliberately bypasses the safe client's local execution pinning.
    let mut raw =
        wire::authorization_ledger_client::AuthorizationLedgerClient::connect(address.clone())
            .await
            .unwrap();
    for field in 0..6 {
        let mut wrong = d.clone();
        match field {
            0 => wrong.execution.namespace.push_str("-other"),
            1 => wrong.execution.workload.push_str("-other"),
            2 => wrong.execution.allocation_id.push_str("-other"),
            3 => wrong.execution.lease_id.push_str("-other"),
            4 => wrong.execution.generation += 1,
            _ => wrong.execution.node_id.push_str("-other"),
        }
        let mut req = tonic::Request::new(wire::ReserveRequest {
            decision_json: canonical_bytes(&wrong).unwrap(),
            proof_evidence: proof.clone(),
        });
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {admission}").parse().unwrap(),
        );
        assert_eq!(
            raw.reserve(req).await.err().unwrap().code(),
            tonic::Code::PermissionDenied
        );
    }
    let g = a.reserve(&d, Some(&proof)).await.unwrap();
    assert!(a
        .consume(&g, &g.execution, &g.request_sha256)
        .await
        .is_err());
    let mut wrong = g.execution.clone();
    wrong.namespace = "other".into();
    assert!(e.consume(&g, &wrong, &g.request_sha256).await.is_err());
    task.abort();
    let _ = task.await;
    drop(ledger);
    let ledger = Arc::new(open(&path));
    let (address, task) = serve(ledger.clone()).await;
    let e = Arc::new(
        RemoteLedger::connect(&address, &execution, r.execution.clone())
            .await
            .unwrap(),
    );
    let g = Arc::new(g);
    let mut tasks = vec![];
    for _ in 0..16 {
        let e = e.clone();
        let g = g.clone();
        tasks.push(tokio::spawn(async move {
            e.consume(&g, &g.execution, &g.request_sha256).await.is_ok()
        }));
    }
    let mut successes = 0;
    for task in tasks {
        successes += usize::from(task.await.unwrap());
    }
    assert_eq!(successes, 1);
    assert!(ledger
        .consume(&g, &g.execution, &g.request_sha256)
        .await
        .is_err());
    let a = RemoteLedger::connect(&address, &admission, r.execution.clone())
        .await
        .unwrap();
    assert!(a.reserve(&d, Some(&proof)).await.is_err());
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_revocation_expiry_and_malformed_auth_fail_closed() {
    use trusted_shim::{
        ledger::LedgerPermission,
        ledger_transport::{wire, RemoteLedger},
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let l = Arc::new(open(&path));
    l.set_budget("shared", 10).unwrap();
    let (p, r) = fixture();
    stage(&l, &p, &r, "remote");
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let proof = encode_public_values(&d).unwrap();
    let token = l
        .issue_access(
            &r.execution,
            LedgerPermission::AdmissionAndExecution,
            &r.validity,
        )
        .unwrap();
    let (address, task) = serve(l.clone()).await;
    let client = RemoteLedger::connect(&address, &token, r.execution.clone())
        .await
        .unwrap();
    let g = client.reserve(&d, Some(&proof)).await.unwrap();
    let mut raw =
        wire::authorization_ledger_client::AuthorizationLedgerClient::connect(address.clone())
            .await
            .unwrap();
    for headers in [
        vec![],
        vec![format!("Bearer {}", "0".repeat(64))],
        vec![format!("Bearer {token}"), format!("Bearer {token}")],
    ] {
        let mut req = tonic::Request::new(wire::ReserveRequest {
            decision_json: canonical_bytes(&d).unwrap(),
            proof_evidence: proof.clone(),
        });
        for h in headers {
            req.metadata_mut()
                .append("authorization", h.parse().unwrap());
        }
        assert!(raw.reserve(req).await.is_err());
    }
    // A valid token cannot smuggle an unknown decision field or oversized proof.
    for bad in 0..2 {
        let mut decision = serde_json::to_value(&d).unwrap();
        if bad == 0 {
            decision["override_policy"] = serde_json::json!(true);
        }
        let mut req = tonic::Request::new(wire::ReserveRequest {
            decision_json: serde_json::to_vec(&decision).unwrap(),
            proof_evidence: if bad == 0 {
                proof.clone()
            } else {
                vec![0; 1024 * 1024 + 1]
            },
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        assert_eq!(
            raw.reserve(req).await.err().unwrap().code(),
            tonic::Code::InvalidArgument
        );
    }
    use sha2::{Digest, Sha256};
    l.revoke_access_id(&hex::encode(Sha256::digest(token.as_bytes())))
        .unwrap();
    assert!(client
        .consume(&g, &g.execution, &g.request_sha256)
        .await
        .is_err());
    assert!(client.reserve(&d, Some(&proof)).await.is_err());
    // Rotated credentials retain the original grant and cumulative budget.
    let next = l
        .issue_access(&r.execution, LedgerPermission::Execution, &r.validity)
        .unwrap();
    let client = RemoteLedger::connect(&address, &next, r.execution.clone())
        .await
        .unwrap();
    let mut changed_context = r.context.clone();
    changed_context["revision"] = serde_json::json!(2);
    l.activate(
        &r.execution,
        &p,
        &changed_context,
        &r.previous_state_root,
        "shared",
    )
    .unwrap();
    assert!(client
        .consume(&g, &g.execution, &g.request_sha256)
        .await
        .is_err());

    let mut r2 = r.clone();
    r2.action_id = "new-context".into();
    r2.context = changed_context;
    l.stage("new-context", &r2, 1).unwrap();
    let d2 = RegorusEngine.evaluate(&p, &r2).unwrap();
    let g2 = l
        .reserve(&d2, Some(&encode_public_values(&d2).unwrap()))
        .await
        .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let short = l
        .issue_access(
            &r.execution,
            LedgerPermission::Execution,
            &Validity {
                not_before: now,
                expires_at: now + 1,
            },
        )
        .unwrap();
    let client = RemoteLedger::connect(&address, &short, r.execution.clone())
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(client
        .consume(&g2, &g2.execution, &g2.request_sha256)
        .await
        .is_err());
    l.revoke(&r.execution).unwrap();
    assert!(l
        .issue_access(&r.execution, LedgerPermission::Execution, &r.validity)
        .is_err());
    let next_client = RemoteLedger::connect(&address, &next, r.execution.clone())
        .await
        .unwrap();
    assert!(next_client
        .consume(&g2, &g2.execution, &g2.request_sha256)
        .await
        .is_err());
    task.abort();
    // Persisted credentials must not come back after a restart.
    let reopened = Arc::new(open(&path));
    let (address, task) = serve(reopened).await;
    let client = RemoteLedger::connect(&address, &token, r.execution.clone())
        .await
        .unwrap();
    assert!(client.reserve(&d, Some(&proof)).await.is_err());
    task.abort();
    for address in [
        "http://example.com:443",
        "http://localhost:8888",
        "https://user@example.com",
        "https://example.com/path?token=secret",
    ] {
        assert!(RemoteLedger::connect(address, &token, r.execution.clone())
            .await
            .is_err());
    }
}

struct PausedVerifier {
    entered: Arc<tokio::sync::Notify>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_ledger_uses_operator_ca_and_rejects_unknown_tls_authority() {
    // The host chooses its TLS provider explicitly when native OpenShell brings
    // another provider into the dependency graph. The transport library must
    // not replace an embedding gateway's process-wide crypto configuration.
    let _ = rustls::crypto::ring::default_provider().install_default();
    use std::process::{Command, Stdio};
    use tonic::transport::{
        Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
    };
    use trusted_shim::{
        ledger::LedgerPermission,
        ledger_transport::{LedgerService, RemoteLedger},
    };
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("server.pem");
    let key = dir.path().join("server.key");
    assert!(Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=ledger.test",
            "-addext",
            "subjectAltName=DNS:ledger.test",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
    let l = Arc::new(open(&dir.path().join("ledger.sqlite")));
    l.set_budget("shared", 1).unwrap();
    let (p, r) = fixture();
    stage(&l, &p, &r, "tls");
    let token = l
        .issue_access(
            &r.execution,
            LedgerPermission::AdmissionAndExecution,
            &r.validity,
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("https://{}", listener.local_addr().unwrap());
    let pem = std::fs::read(&cert).unwrap();
    let identity = Identity::from_pem(&pem, std::fs::read(&key).unwrap());
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))
            .unwrap()
            .add_service(LedgerService::new(l).into_service())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    assert!(RemoteLedger::connect(&address, &token, r.execution.clone())
        .await
        .is_err());
    let channel = Endpoint::from_shared(address)
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(pem))
                .domain_name("ledger.test"),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = RemoteLedger::from_channel(channel, &token, r.execution.clone()).unwrap();
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let g = client
        .reserve(&d, Some(&encode_public_values(&d).unwrap()))
        .await
        .unwrap();
    client
        .consume(&g, &g.execution, &g.request_sha256)
        .await
        .unwrap();
    task.abort();
}
impl ReceiptVerifier for PausedVerifier {
    fn verify(&self, _: &ProgramRef, _: &ProofReceipt, _: &[u8]) -> trusted_shim::Result<()> {
        self.entered.notify_one();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| trusted_shim::Error::Unavailable)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_revoked_during_proof_verification_cannot_reserve_budget() {
    use trusted_shim::{ledger::LedgerPermission, ledger_transport::RemoteLedger};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let _ = open(&path);
    let (send, receive) = std::sync::mpsc::channel();
    let entered = Arc::new(tokio::sync::Notify::new());
    let l = Arc::new(
        SqliteLedger::open(
            &path,
            program(),
            Arc::new(PausedVerifier {
                entered: entered.clone(),
                release: std::sync::Mutex::new(receive),
            }),
        )
        .unwrap(),
    );
    l.set_budget("shared", 1).unwrap();
    let (p, r) = fixture();
    stage(&l, &p, &r, "paused");
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let proof = encode_public_values(&d).unwrap();
    let token = l
        .issue_access(&r.execution, LedgerPermission::Admission, &r.validity)
        .unwrap();
    let (address, server) = serve(l.clone()).await;
    let client = RemoteLedger::connect(&address, &token, r.execution.clone())
        .await
        .unwrap();
    let admission = tokio::spawn(async move { client.reserve(&d, Some(&proof)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    l.revoke_access(&token).unwrap();
    send.send(()).unwrap();
    assert!(admission.await.unwrap().is_err());
    server.abort();
    // The rejected RPC left the one-unit budget untouched.
    let next = open(&path);
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    assert!(next
        .reserve(&d, Some(&encode_public_values(&d).unwrap()))
        .await
        .is_ok());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reservation_and_consumption_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let l = open(&path);
    l.set_budget("shared", 1).unwrap();
    let (p, r) = fixture();
    stage(&l, &p, &r, "job");
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let evidence = encode_public_values(&d).unwrap();
    assert!(l.reserve(&d, None).await.is_err());
    assert!(l.reserve(&d, Some(b"invalid")).await.is_err());
    let mut wrong = d.clone();
    wrong.request_sha256 = "f".repeat(64);
    assert!(l.reserve(&wrong, Some(&evidence)).await.is_err());
    let l = Arc::new(l);
    let mut tasks = vec![];
    for _ in 0..16 {
        let l = l.clone();
        let d = d.clone();
        let e = evidence.clone();
        tasks.push(tokio::spawn(async move {
            l.reserve(&d, Some(&e)).await.unwrap()
        }));
    }
    let mut grants = vec![];
    for t in tasks {
        grants.push(t.await.unwrap());
    }
    assert!(grants.iter().all(|g| g.credential == grants[0].credential));
    drop(l);
    let l = Arc::new(open(&path));
    assert_eq!(
        request_digest(&l.request("job").unwrap()).unwrap(),
        request_digest(&r).unwrap()
    );
    let mut changed = grants.pop().unwrap();
    changed.credential[0] ^= 1;
    assert!(l
        .consume(&changed, &r.execution, &d.request_sha256)
        .await
        .is_err());
    let mut tasks = vec![];
    for grant in grants {
        let l = l.clone();
        let e = r.execution.clone();
        let h = d.request_sha256.clone();
        tasks.push(tokio::spawn(async move {
            l.consume(&grant, &e, &h).await.is_ok()
        }));
    }
    let mut count = 0;
    for t in tasks {
        count += usize::from(t.await.unwrap());
    }
    assert_eq!(count, 1);
    assert!(l.reserve(&d, Some(&evidence)).await.is_err());
    // Another lease on another machine uses the same cumulative budget.
    let mut next = r.clone();
    next.execution.lease_id = "next".into();
    next.execution.node_id = "other".into();
    stage(&l, &p, &next, "next-job");
    let d2 = RegorusEngine.evaluate(&p, &next).unwrap();
    let e2 = encode_public_values(&d2).unwrap();
    assert!(l.reserve(&d2, Some(&e2)).await.is_err());
    l.set_budget("shared", 1).unwrap();
    assert!(l.reserve(&d2, Some(&e2)).await.is_err());
    l.set_budget("shared", 2).unwrap();
    assert!(l.reserve(&d2, Some(&e2)).await.is_ok());
    assert!(l.set_budget("shared", 1).is_err());
}
#[tokio::test]
async fn context_rotation_revocation_and_exact_request_are_authoritative() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let l = open(&path);
    l.set_budget("shared", 10).unwrap();
    let (p, r) = fixture();
    stage(&l, &p, &r, "job");
    let d = RegorusEngine.evaluate(&p, &r).unwrap();
    let e = encode_public_values(&d).unwrap();
    let g = l.reserve(&d, Some(&e)).await.unwrap();
    assert!(l.consume(&g, &r.execution, &"f".repeat(64)).await.is_err());
    let mut substituted = r.clone();
    substituted.parameters = serde_json::json!({"different":true});
    assert!(l.stage("job", &substituted, 1).is_err());
    let changed = serde_json::json!({"tenant":"other"});
    l.activate(&r.execution, &p, &changed, &r.previous_state_root, "shared")
        .unwrap();
    assert!(l
        .consume(&g, &r.execution, &d.request_sha256)
        .await
        .is_err());
    assert!(l.reserve(&d, Some(&e)).await.is_err());
    assert!(l.stage("other", &r, 1).is_err());
    l.revoke(&r.execution).unwrap();
    assert!(l
        .activate(
            &r.execution,
            &p,
            &r.context,
            &r.previous_state_root,
            "shared"
        )
        .is_err());
    let mut other = program();
    other.program_sha256 = "3".repeat(64);
    assert!(SqliteLedger::open(&path, other, Arc::new(TestVerifier)).is_err());
}
#[tokio::test]
async fn denies_expired_actions_and_never_refunds_consumed_grants() {
    let dir = tempfile::tempdir().unwrap();
    let l = open(&dir.path().join("ledger.sqlite"));
    l.set_budget("shared", 1).unwrap();
    let (p, mut r) = fixture();
    l.activate(
        &r.execution,
        &p,
        &r.context,
        &r.previous_state_root,
        "shared",
    )
    .unwrap();
    r.operation = "delete".into();
    assert!(l.stage("deny", &r, 1).is_err());
    r.operation = "read".into();
    r.validity.expires_at = r.evaluated_at_unix;
    assert!(l.stage("expired", &r, 1).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_connections_share_atomic_budget_and_revocation_fences() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let a = Arc::new(open(&path));
    let b = Arc::new(open(&path));
    a.set_budget("shared", 1).unwrap();
    let (p, r) = fixture();
    let mut next = r.clone();
    next.execution.lease_id = "next".into();
    stage(&a, &p, &r, "first");
    stage(&b, &p, &next, "second");
    let mut tasks = Vec::new();
    for (ledger, request) in [(a.clone(), r.clone()), (b.clone(), next)] {
        let d = RegorusEngine.evaluate(&p, &request).unwrap();
        let proof = encode_public_values(&d).unwrap();
        tasks.push(tokio::spawn(async move {
            ledger.reserve(&d, Some(&proof)).await
        }));
    }
    let mut granted = Vec::new();
    for t in tasks {
        if let Ok(g) = t.await.unwrap() {
            granted.push(g);
        }
    }
    assert_eq!(granted.len(), 1);
    let grant = granted.pop().unwrap();
    a.consume(&grant, &grant.execution, &grant.request_sha256)
        .await
        .unwrap();
    assert!(b
        .consume(&grant, &grant.execution, &grant.request_sha256)
        .await
        .is_err());
    let mut retired = r.execution.clone();
    retired.lease_id = "not-yet-active".into();
    a.revoke(&retired).unwrap();
    assert!(b
        .activate(&retired, &p, &r.context, &r.previous_state_root, "shared")
        .is_err());
    drop(a);
    drop(b);
    assert!(open(&path)
        .activate(&retired, &p, &r.context, &r.previous_state_root, "shared")
        .is_err());
}
