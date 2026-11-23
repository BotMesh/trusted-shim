//! Protocol fixtures only: receipts here are not cryptographic proofs.
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio_stream::wrappers::TcpListenerStream;
use trusted_shim::{
    contracts::ProofKind,
    proof::*,
    tee::{
        canonical,
        trustee::{wire, Trustee},
        CocoEvidence, Mode, TeeConfig, TeeDriver,
    },
    Error, Result,
};
pub(crate) fn config() -> TeeConfig {
    TeeConfig {
        mode: Mode::Simulation,
        platform: "sample".into(),
        evidence_endpoint: "http://127.0.0.1:1/aa/evidence".into(),
        trustee_endpoint: "http://127.0.0.1:1".into(),
        trustee_tls: None,
        dcap: None,
        trustee_policy_ids: vec!["default".into()],
        init_data_sha256: "11".repeat(32),
        endpoint_key_sha256: "22".repeat(32),
        expected_measurement: "abcde".into(),
        proof_endpoint: "http://127.0.0.1:1".into(),
        proof_token_file: "/unused/token".into(),
        elf_file: "/unused/guest".into(),
        proof_signer_file: None,
        program_vkey_hash: "0x0000".into(),
        program: ProgramRef {
            kind: ProofKind::RemoteAttestation,
            program_sha256: "aa".repeat(32),
            verifying_key_sha256: "bb".repeat(32),
        },
    }
}

#[derive(Default)]
pub(crate) struct ProtocolTrustee;
#[tonic::async_trait]
impl wire::attestation_service_server::AttestationService for ProtocolTrustee {
    async fn attestation_evaluate(
        &self,
        request: tonic::Request<wire::AttestationRequest>,
    ) -> std::result::Result<tonic::Response<wire::AttestationResponse>, tonic::Status> {
        use wire::individual_attestation_request::{InitData, RuntimeData};
        let mut request = request.into_inner();
        assert_eq!(request.policy_ids, ["default"]);
        assert_eq!(request.verification_requests.len(), 1);
        let request = request.verification_requests.pop().unwrap();
        assert_eq!(request.tee, "sample");
        assert_eq!(request.runtime_data_hash_algorithm, "sha256");
        assert_eq!(
            request.init_data,
            Some(InitData::InitDataDigest(URL_SAFE_NO_PAD.encode([0x11; 32])))
        );
        let Some(RuntimeData::RawRuntimeData(raw)) = request.runtime_data else {
            panic!("missing runtime binding")
        };
        let evidence: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(request.evidence).unwrap()).unwrap();
        let expected = URL_SAFE_NO_PAD.decode(raw).unwrap();
        if STANDARD
            .decode(evidence["report_data"].as_str().unwrap())
            .unwrap()
            != expected[..]
        {
            return Err(tonic::Status::permission_denied("report data mismatch"));
        }
        Ok(tonic::Response::new(wire::AttestationResponse {
            attestation_token: "protocol-fixture-not-a-token-or-proof".into(),
        }))
    }
    async fn set_attestation_policy(
        &self,
        _: tonic::Request<wire::SetPolicyRequest>,
    ) -> std::result::Result<tonic::Response<wire::SetPolicyResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("read only"))
    }
    async fn get_attestation_challenge(
        &self,
        _: tonic::Request<wire::ChallengeRequest>,
    ) -> std::result::Result<tonic::Response<wire::ChallengeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not used for sample"))
    }
}

pub(crate) struct Lab {
    pub(crate) config: TeeConfig,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Lab {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Lab {
    pub(crate) async fn start(bad_evidence: bool, real_trustee: Option<String>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config();
        config.evidence_endpoint = format!("http://{}/aa/evidence", listener.local_addr().unwrap());
        let app = axum::Router::new().route("/aa/evidence", axum::routing::get(move |axum::extract::Query(query): axum::extract::Query<HashMap<String,String>>| async move {
            assert_eq!(query["encoding"], "base64");
            let data = URL_SAFE_NO_PAD.decode(&query["runtime_data"]).unwrap();
            axum::Json(json!({"svn":"1","report_data":STANDARD.encode(if bad_evidence { vec![0;32] } else { data })}))
        }));
        let mut tasks = vec![tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        })];
        if let Some(endpoint) = real_trustee {
            config.trustee_endpoint = endpoint;
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.trustee_endpoint = format!("http://{}", listener.local_addr().unwrap());
            tasks.push(tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(
                        wire::attestation_service_server::AttestationServiceServer::new(
                            ProtocolTrustee,
                        ),
                    )
                    .serve_with_incoming(TcpListenerStream::new(listener))
                    .await
                    .unwrap();
            }));
        }
        Self { config, tasks }
    }
    pub(crate) async fn driver(
        &self,
        root: &std::path::Path,
        proof: Arc<ProofDouble>,
        reject: bool,
    ) -> TeeDriver {
        TeeDriver::new(
            root,
            "test-node".into(),
            self.config.clone(),
            Arc::new(CocoEvidence::new(self.config.evidence_endpoint.clone()).unwrap()),
            Trustee::connect(
                &self.config.trustee_endpoint,
                self.config.trustee_policy_ids.clone(),
                self.config.trustee_tls.as_ref(),
            )
            .await
            .unwrap(),
            proof,
            Arc::new(ReceiptDouble { reject }),
        )
        .unwrap()
    }
}

#[derive(Default)]
pub(crate) struct ProofDouble {
    pub(crate) submitted: AtomicUsize,
    pub(crate) fail_submit: AtomicBool,
    /// Every submitted proof fails.
    pub(crate) fail_proof: AtomicBool,
    /// Submitted proofs stay pending while set.
    pub(crate) hold: AtomicBool,
    public: Mutex<Option<(String, Vec<u8>)>>,
}
#[async_trait]
impl ProofNetwork for ProofDouble {
    async fn submit(&self, request: &ProofRequest) -> Result<String> {
        self.submitted.fetch_add(1, Ordering::SeqCst);
        let witness: Value = serde_json::from_slice(&request.witness).unwrap();
        assert_eq!(witness["binding"]["mode"], "simulation");
        let evidence: Vec<u8> = serde_json::from_value(witness["evidence"].clone()).unwrap();
        let public = canonical(&json!({"binding":witness["binding"], "evidence_sha256":hex::encode(Sha256::digest(evidence))})).unwrap();
        assert_eq!(public, request.expected_public_values);
        assert_eq!(request.program.kind, ProofKind::RemoteAttestation);
        *self.public.lock().unwrap() = Some((request.request_id.clone(), public));
        if self.fail_submit.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        Ok(request.request_id.clone())
    }
    async fn status(&self, id: &str) -> Result<ProofStatus> {
        let (job_id, bytes) = self.public.lock().unwrap().clone().unwrap();
        assert_eq!(id, job_id);
        if self.hold.load(Ordering::SeqCst) {
            return Ok(ProofStatus::Pending);
        }
        if self.fail_proof.load(Ordering::SeqCst) {
            return Ok(ProofStatus::Failed);
        }
        Ok(ProofStatus::Complete(ProofReceipt {
            job_id,
            encoded_receipt: bytes,
        }))
    }
}
pub(crate) struct ReceiptDouble {
    pub(crate) reject: bool,
}
impl ReceiptVerifier for ReceiptDouble {
    fn verify(&self, _: &ProgramRef, receipt: &ProofReceipt, expected: &[u8]) -> Result<()> {
        if self.reject || receipt.encoded_receipt != expected {
            Err(Error::Untrusted)
        } else {
            Ok(())
        }
    }
}
