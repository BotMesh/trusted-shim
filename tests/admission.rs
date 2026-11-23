use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use trusted_rail::{rego::*, *};
use trusted_shim::{admission::*, contracts::*, proof::*, runtime::ActionExecutor, Error};

fn fixture() -> (PolicyBundle, EvaluationRequest, ProgramRef) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut policy=PolicyBundle {
        policy:PolicyRef { issuer:"gateway".into(),policy_id:"policy".into(),version:1,sha256:String::new() },engine:engine_profile(),
        modules:[("p.rego".into(),"package trusted\ndefault decision := {\"decision\":\"deny\",\"reason_codes\":[]}\ndecision := {\"decision\":\"allow\",\"reason_codes\":[]} if { input.operation == \"read\" }".into())].into(),data:serde_json::json!({}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    let request = EvaluationRequest {
        execution: ExecutionIdentity {
            namespace: "tenant".into(),
            workload: "app".into(),
            allocation_id: "a".into(),
            lease_id: "l".into(),
            generation: 1,
            node_id: "n".into(),
        },
        principal: "alice".into(),
        action_id: "action".into(),
        operation: "read".into(),
        resource: "workspace".into(),
        parameters: serde_json::json!({}),
        context: serde_json::json!({}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: now,
        validity: Validity {
            not_before: now - 1,
            expires_at: now + 120,
        },
    };
    let program = ProgramRef {
        kind: ProofKind::PolicyEvaluation,
        program_sha256: "1".repeat(64),
        verifying_key_sha256: "2".repeat(64),
    };
    (policy, request, program)
}

// These are orchestration test doubles, not cryptographic or ledger implementations.
struct TestNetwork {
    state: AtomicUsize,
}
#[async_trait]
impl ProofNetwork for TestNetwork {
    async fn submit(&self, r: &ProofRequest) -> trusted_shim::Result<String> {
        assert_eq!(
            evaluate_witness(&r.witness).unwrap(),
            r.expected_public_values
        );
        Ok(r.request_id.clone())
    }
    async fn status(&self, id: &str) -> trusted_shim::Result<ProofStatus> {
        Ok(match self.state.load(Ordering::SeqCst) {
            0 => ProofStatus::Pending,
            1 => ProofStatus::Failed,
            2 => ProofStatus::Complete(ProofReceipt {
                job_id: id.into(),
                encoded_receipt: vec![1],
            }),
            _ => ProofStatus::Complete(ProofReceipt {
                job_id: "other-job".into(),
                encoded_receipt: vec![1],
            }),
        })
    }
}
struct TestVerifier {
    reject: bool,
}
impl ReceiptVerifier for TestVerifier {
    fn verify(
        &self,
        _: &ProgramRef,
        _: &ProofReceipt,
        expected: &[u8],
    ) -> trusted_shim::Result<()> {
        RegorusEngine.decode_public_values(expected).unwrap();
        if self.reject {
            Err(Error::Untrusted)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct TestLedger {
    reserves: AtomicUsize,
    consumed: Mutex<bool>,
}
#[async_trait]
impl AuthorizationLedger for TestLedger {
    async fn reserve(
        &self,
        d: &DecisionRecord,
        e: Option<&[u8]>,
    ) -> trusted_rail::Result<ExecutionGrant> {
        assert!(e.is_some());
        self.reserves.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionGrant {
            id: "grant".into(),
            credential: vec![7],
            execution: d.execution.clone(),
            request_sha256: d.request_sha256.clone(),
            validity: d.validity.clone(),
        })
    }
    async fn consume(
        &self,
        _: &ExecutionGrant,
        _: &ExecutionIdentity,
        _: &str,
    ) -> trusted_rail::Result<()> {
        let mut consumed = self.consumed.lock().unwrap();
        if *consumed {
            return Err(trusted_rail::Error::Conflict);
        }
        *consumed = true;
        Ok(())
    }
}
#[derive(Default)]
struct Handler(AtomicUsize);
#[async_trait]
impl ActionHandler for Handler {
    async fn run(&self, _: &EvaluationRequest) -> trusted_shim::Result<Vec<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    }
}

#[tokio::test]
async fn pending_failed_forged_or_wrong_job_never_reserve_authority() {
    let (policy, request, program) = fixture();
    let network = Arc::new(TestNetwork {
        state: AtomicUsize::new(0),
    });
    let ledger = Arc::new(TestLedger::default());
    let gate = PolicyAdmission::new(
        network.clone(),
        Arc::new(TestVerifier { reject: true }),
        ledger.clone(),
        program,
    )
    .unwrap();
    let job = gate.prepare("job", &policy, &request).unwrap();
    gate.submit(&job).await.unwrap();
    assert!(gate.authorize(&job).await.unwrap().is_none());
    for state in 1..=3 {
        network.state.store(state, Ordering::SeqCst);
        assert!(gate.authorize(&job).await.is_err());
    }
    assert_eq!(ledger.reserves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exact_request_and_atomic_consumption_gate_the_handler() {
    let (policy, request, program) = fixture();
    let ledger = Arc::new(TestLedger::default());
    let gate = PolicyAdmission::new(
        Arc::new(TestNetwork {
            state: AtomicUsize::new(2),
        }),
        Arc::new(TestVerifier { reject: false }),
        ledger.clone(),
        program,
    )
    .unwrap();
    let job = gate.prepare("job", &policy, &request).unwrap();
    let grant = gate.authorize(&job).await.unwrap().unwrap();
    let handler = Arc::new(Handler::default());
    let executor = AuthorizedExecutor::new(ledger.clone(), handler.clone());
    let mut changed = request.clone();
    changed.parameters = serde_json::json!({"command":"unexpected"});
    assert!(executor.execute(&changed, &grant).await.is_err());
    changed = request.clone();
    changed.execution.lease_id = "different".into();
    assert!(executor.execute(&changed, &grant).await.is_err());
    assert_eq!(handler.0.load(Ordering::SeqCst), 0);
    let (one, two) = tokio::join!(
        executor.execute(&request, &grant),
        executor.execute(&request, &grant)
    );
    assert!(one.is_ok() ^ two.is_ok());
    assert_eq!(handler.0.load(Ordering::SeqCst), 1);
}

#[test]
fn deny_expiry_and_wrong_proof_domain_cannot_create_jobs() {
    let (policy, mut request, mut program) = fixture();
    let network = Arc::new(TestNetwork {
        state: AtomicUsize::new(0),
    });
    let verifier = Arc::new(TestVerifier { reject: false });
    let ledger = Arc::new(TestLedger::default());
    program.kind = ProofKind::RemoteAttestation;
    assert!(PolicyAdmission::new(
        network.clone(),
        verifier.clone(),
        ledger.clone(),
        program.clone()
    )
    .is_err());
    program.kind = ProofKind::PolicyEvaluation;
    let gate = PolicyAdmission::new(network, verifier, ledger, program).unwrap();
    request.operation = "delete".into();
    assert!(gate.prepare("job", &policy, &request).is_err());
    request.operation = "read".into();
    request.validity.expires_at = 1;
    assert!(gate.prepare("job", &policy, &request).is_err());
}
