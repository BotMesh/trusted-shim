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
