use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    transport::{Channel, Server},
    Request, Response, Status,
};
use trusted_shim::{
    contracts::ProofKind,
    network::{wire::*, ZirenNetwork},
    proof::*,
};

#[derive(Clone, Default)]
struct Stage {
    submitted: Arc<Mutex<Option<GenerateProofRequest>>>,
}
#[async_trait]
impl stage_service_server::StageService for Stage {
    async fn generate_proof(
        &self,
        r: Request<GenerateProofRequest>,
    ) -> Result<Response<GenerateProofResponse>, Status> {
        assert_eq!(
            r.metadata().get("authorization").unwrap(),
            "Bearer test-only"
        );
        let r = r.into_inner();
        let proof_id = r.proof_id.clone();
        *self.submitted.lock().await = Some(r);
        Ok(Response::new(GenerateProofResponse {
            proof_id,
            status: 2,
            ..Default::default()
        }))
    }
    async fn get_status(
        &self,
        r: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let id = r.into_inner().proof_id;
        Ok(Response::new(GetStatusResponse {
            proof_id: id,
            status: 0,
            proof_with_public_inputs: b"test-wire-receipt".to_vec(),
            public_values_url: "http://169.254.169.254/never-follow".into(),
            ..Default::default()
        }))
    }
}
#[tokio::test]
async fn upstream_wire_framing_id_and_elf_are_bound_without_downloading_urls() {
    let service = Stage::default();
    let submitted = service.submitted.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        Server::builder()
            .add_service(stage_service_server::StageServiceServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let channel = Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let elf = b"test ELF bytes".to_vec();
    let program = ProgramRef {
        kind: ProofKind::PolicyEvaluation,
        program_sha256: hex::encode(Sha256::digest(&elf)),
        verifying_key_sha256: "2".repeat(64),
    };
    assert!(
        ZirenNetwork::from_channel(channel.clone(), "test-only", program.clone(), vec![0]).is_err()
    );
    let network = ZirenNetwork::from_channel(channel, "test-only", program.clone(), elf.clone())
        .unwrap()
        .with_fleet_signer(&[7; 32])
        .unwrap();
    let request = ProofRequest {
        request_id: "job-123".into(),
        program,
        witness: b"canonical-witness".to_vec(),
        expected_public_values: b"expected-public".to_vec(),
    };
    assert_eq!(network.submit(&request).await.unwrap(), "job-123");
    let wire = submitted.lock().await.take().unwrap();
    let signature: alloy_primitives::Signature = wire.signature.parse().unwrap();
    let recovered = signature.recover_address_from_msg(b"job-123&0").unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    assert_eq!(recovered, alloy_primitives::Address::from_private_key(&key));
    assert_eq!(wire.elf_data, elf);
    assert_eq!(wire.target_step, Some(5));
    let stdin: Vec<Vec<u8>> = bincode::deserialize(&wire.private_input_stream).unwrap();
    assert_eq!(stdin, vec![request.witness]);
    let ProofStatus::Complete(receipt) = network.status("job-123").await.unwrap() else {
        panic!("expected receipt")
    };
    assert_eq!(receipt.encoded_receipt, b"test-wire-receipt");
    server.abort();
}
