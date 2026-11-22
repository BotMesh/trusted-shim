use async_trait::async_trait;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};
use trusted_shim::{
    contracts::*,
    ledger::*,
    proof::*,
    rail::{rego::*, *},
};

// These test doubles check orchestration only. They never produce ZK proofs.
struct Verifier;
impl ReceiptVerifier for Verifier {
    fn verify(
        &self,
        _: &ProgramRef,
        r: &ProofReceipt,
        expected: &[u8],
    ) -> trusted_shim::Result<()> {
        if r.encoded_receipt == expected {
            Ok(())
        } else {
            Err(trusted_shim::Error::Untrusted)
        }
    }
}
#[derive(Default)]
struct Network {
    submissions: AtomicUsize,
    mode: AtomicUsize,
    public: Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}
#[async_trait]
impl ProofNetwork for Network {
    async fn submit(&self, r: &ProofRequest) -> trusted_shim::Result<String> {
        let actual = evaluate_witness(&r.witness).unwrap();
        assert_eq!(actual, r.expected_public_values);
        self.submissions.fetch_add(1, Ordering::SeqCst);
        self.public
            .lock()
            .unwrap()
            .insert(r.request_id.clone(), actual);
        if self.mode.load(Ordering::SeqCst) == 1 {
            return Err(trusted_shim::Error::Unavailable);
        }
        Ok(r.request_id.clone())
    }
    async fn status(&self, id: &str) -> trusted_shim::Result<ProofStatus> {
        Ok(match self.mode.load(Ordering::SeqCst) {
            0 | 1 => ProofStatus::Pending,
            2 => ProofStatus::Complete(ProofReceipt {
                job_id: id.into(),
                encoded_receipt: self.public.lock().unwrap()[id].clone(),
            }),
            3 => ProofStatus::Complete(ProofReceipt {
                job_id: id.into(),
                encoded_receipt: b"forged".to_vec(),
            }),
            4 => ProofStatus::Failed,
            _ => ProofStatus::Complete(ProofReceipt {
                job_id: "another-job".into(),
                encoded_receipt: self.public.lock().unwrap()[id].clone(),
            }),
        })
    }
}
fn fixture() -> (PolicyBundle, EvaluationRequest) {
    let mut policy = PolicyBundle {
        policy: PolicyRef { issuer:"gateway".into(),policy_id:"preflight".into(),version:1,sha256:String::new() },
        engine:engine_profile(),
        modules:[("p.rego".into(),"package trusted\ndefault decision := {\"decision\":\"deny\",\"reason_codes\":[]}\ndecision := {\"decision\":\"allow\",\"reason_codes\":[]} if { input.operation == \"read\" }\ndecision := {\"decision\":\"approval_required\",\"reason_codes\":[]} if { input.operation == \"write\" }".into())].into(),
        data:serde_json::json!({}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let r = EvaluationRequest {
        execution: ExecutionIdentity {
            namespace: "tenant".into(),
            workload: "agent".into(),
            allocation_id: "a".into(),
            lease_id: "lease".into(),
            generation: 1,
            node_id: "node".into(),
        },
        principal: "alice".into(),
        action_id: "action".into(),
        operation: "read".into(),
        resource: "file".into(),
        parameters: serde_json::json!({}),
        context: serde_json::json!({}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: now,
        validity: Validity {
            not_before: now - 1,
            expires_at: now + 120,
        },
    };
    (policy, r)
}
fn open(path: &std::path::Path) -> Arc<SqliteLedger> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    Arc::new(
        SqliteLedger::open(
            path,
            ProgramRef {
                kind: ProofKind::PolicyEvaluation,
                program_sha256: "1".repeat(64),
                verifying_key_sha256: "2".repeat(64),
            },
            Arc::new(Verifier),
        )
        .unwrap(),
    )
}
fn activate(l: &SqliteLedger, p: &PolicyBundle, r: &EvaluationRequest, allowance: u64) {
    l.set_budget("shared", allowance).unwrap();
    l.activate(
        &r.execution,
        p,
        &r.context,
        &r.previous_state_root,
        "shared",
    )
    .unwrap();
}

#[tokio::test]
async fn native_verdicts_precede_remote_proofs_and_only_allow_gets_one_use_authority() {
    let dir = tempfile::tempdir().unwrap();
    let l = open(&dir.path().join("ledger.sqlite"));
    let (p, mut r) = fixture();
    activate(&l, &p, &r, 1);
    let n = Arc::new(Network::default());
    let worker = PreflightWorker::new(l.clone(), n.clone());
    let allow = l.preflight("allow", &r, 1).unwrap();
    assert_eq!(allow.receipt_state, PreflightReceiptState::Queued);
    assert_eq!(n.submissions.load(Ordering::SeqCst), 0);
    let grant = allow.grant.unwrap();
    let duplicate = l.preflight("allow", &r, 1).unwrap().grant.unwrap();
    assert_eq!(grant.credential, duplicate.credential);
    let digest = request_digest(&r).unwrap();
    assert!(l
        .consume(&grant, &r.execution, &"f".repeat(64))
        .await
        .is_err());
    l.consume(&grant, &r.execution, &digest).await.unwrap();
    assert!(l.consume(&duplicate, &r.execution, &digest).await.is_err());
    assert!(l.preflight("allow", &r, 1).is_err());
    for (job, op, decision) in [
        ("deny", "delete", Decision::Deny),
        ("approval", "write", Decision::ApprovalRequired),
    ] {
        r.action_id = job.into();
        r.operation = op.into();
        let v = l.preflight(job, &r, 1).unwrap();
        assert_eq!(v.decision.decision, decision);
        assert!(v.grant.is_none());
    }
    n.mode.store(2, Ordering::SeqCst);
    for id in l.pending_preflight().unwrap() {
        assert_eq!(
            worker.advance(&id).await.unwrap(),
            PreflightReceiptState::Verified
        );
        assert!(l.preflight_receipt(&id).unwrap().is_some());
    }
    assert_eq!(n.submissions.load(Ordering::SeqCst), 3);
    assert!(l.pending_preflight().unwrap().is_empty());
}

#[tokio::test]
async fn ambiguous_submission_restart_and_historical_proofs_never_renew_grants() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let l = open(&path);
    let (p, mut r) = fixture();
    r.validity.expires_at = r.evaluated_at_unix + 2;
    activate(&l, &p, &r, 1);
    let grant = l.preflight("history", &r, 1).unwrap().grant.unwrap();
    l.consume(&grant, &r.execution, &request_digest(&r).unwrap())
        .await
        .unwrap();
    let n = Arc::new(Network::default());
    n.mode.store(1, Ordering::SeqCst);
    let worker = PreflightWorker::new(l.clone(), n.clone());
    assert!(worker.advance("history").await.is_err());
    assert_eq!(
        l.preflight_receipt_state("history").unwrap(),
        PreflightReceiptState::Proving
    );
    l.revoke(&r.execution).unwrap();
    drop(worker);
    drop(l);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let l = open(&path);
    let worker = PreflightWorker::new(l.clone(), n.clone());
    n.mode.store(2, Ordering::SeqCst);
    assert_eq!(
        worker.advance("history").await.unwrap(),
        PreflightReceiptState::Verified
    );
    assert_eq!(n.submissions.load(Ordering::SeqCst), 1);
    assert!(l
        .consume(&grant, &r.execution, &request_digest(&r).unwrap())
        .await
        .is_err());
    assert!(l.preflight("history", &r, 1).is_err());
}

#[tokio::test]
async fn failed_forged_and_wrong_job_receipts_are_never_verified() {
    let dir = tempfile::tempdir().unwrap();
    let l = open(&dir.path().join("ledger.sqlite"));
    let (p, mut r) = fixture();
    activate(&l, &p, &r, 10);
    l.preflight("proof", &r, 1).unwrap();
    let n = Arc::new(Network::default());
    let worker = PreflightWorker::new(l.clone(), n.clone());
    for mode in [3, 5] {
        n.mode.store(mode, Ordering::SeqCst);
        assert!(worker.advance("proof").await.is_err());
        assert!(l.preflight_receipt("proof").unwrap().is_none());
    }
    n.mode.store(4, Ordering::SeqCst);
    assert_eq!(
        worker.advance("proof").await.unwrap(),
        PreflightReceiptState::Failed
    );
    r.action_id = "next".into();
    assert!(l.preflight("next", &r, 1).is_err());
    l.complete_preflight(&ProofReceipt {
        job_id: "proof".into(),
        encoded_receipt: n.public.lock().unwrap()["proof"].clone(),
    })
    .unwrap();
    assert!(l.preflight("next", &r, 1).is_ok());
}

#[test]
fn strict_creation_policy_changes_and_substitution_cannot_downgrade_admission() {
    let dir = tempfile::tempdir().unwrap();
    let l = open(&dir.path().join("ledger.sqlite"));
    let (mut p, mut r) = fixture();
    activate(&l, &p, &r, 10);
    l.stage("strict", &r, 1).unwrap();
    assert!(l.preflight("strict", &r, 1).is_err());
    r.action_id = "new".into();
    r.operation = "runtime.create".into();
    assert!(l.preflight("create", &r, 1).is_err());
    r.operation = "read".into();
    l.preflight("action", &r, 1).unwrap();
    let mut changed = r.clone();
    changed.parameters = serde_json::json!({"substitute":true});
    assert!(l.preflight("action", &changed, 1).is_err());
    assert!(l.preflight("action", &r, 2).is_err());
    assert!(l.preflight("other", &r, 1).is_err());
    p.policy.version += 1;
    p.policy.sha256 = policy_digest(&p).unwrap();
    activate(&l, &p, &r, 10);
    assert!(l.preflight("action", &r, 1).is_err());
}

#[test]
fn concurrent_connections_reserve_shared_budget_atomically_and_full_outbox_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let l = open(&path);
    let (p, r) = fixture();
    activate(&l, &p, &r, 1);
    let second = open(&path);
    let mut other = r.clone();
    other.action_id = "second".into();
    let thread = std::thread::spawn(move || second.preflight("second", &other, 1).is_ok());
    let first = l.preflight("first", &r, 1).is_ok();
    assert!(first ^ thread.join().unwrap());
    for i in 1..128 {
        let mut denied = r.clone();
        denied.action_id = format!("denied-{i}");
        denied.operation = "delete".into();
        assert!(l
            .preflight(&denied.action_id, &denied, 1)
            .unwrap()
            .grant
            .is_none());
    }
    let mut last = r;
    last.action_id = "overflow".into();
    last.operation = "delete".into();
    assert!(l.preflight("overflow", &last, 1).is_err());
    assert!(l.request("overflow").is_err());
    assert_eq!(l.pending_preflight().unwrap().len(), 128);
}
