//! Upstream Ziren StageService, remote proving only. Credentials are supplied
//! explicitly; no SDK initialization or token-file discovery occurs.
use crate::{proof::*, Error, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tonic::{
    metadata::{Ascii, MetadataValue},
    transport::{Channel, ClientTlsConfig, Endpoint},
    Request,
};

pub mod wire {
    tonic::include_proto!("stage.v1");
}
use wire::{
    stage_service_client::StageServiceClient, GenerateProofRequest, GetStatusRequest, Status, Step,
};

const MAX_RECEIPT: usize = 1024 * 1024;

pub struct ZirenNetwork {
    channel: Channel,
    bearer: MetadataValue<Ascii>,
    program: ProgramRef,
    elf: Vec<u8>,
    fleet_signer: Option<k256::ecdsa::SigningKey>,
}

impl ZirenNetwork {
    pub async fn connect(
        endpoint: &str,
        token: &str,
        program: ProgramRef,
        elf: Vec<u8>,
    ) -> Result<Self> {
        let endpoint = Self::endpoint(endpoint)?;
        let channel = endpoint.connect().await.map_err(|_| Error::Unavailable)?;
        Self::from_channel(channel, token, program, elf)
    }

    /// Build a reconnecting channel without requiring the proof service to be up.
    /// Runtime inspection and cleanup must remain available during proof outages.
    pub fn connect_lazy(
        endpoint: &str,
        token: &str,
        program: ProgramRef,
        elf: Vec<u8>,
    ) -> Result<Self> {
        Self::from_channel(
            Self::endpoint(endpoint)?.connect_lazy(),
            token,
            program,
            elf,
        )
    }

    fn endpoint(endpoint: &str) -> Result<Endpoint> {
        let uri: tonic::codegen::http::Uri =
            endpoint.parse().map_err(|_| Error::InvalidContract)?;
        let local = matches!(uri.host(), Some("127.0.0.1" | "[::1]"));
        let mut endpoint =
            Endpoint::from_shared(endpoint.to_owned()).map_err(|_| Error::InvalidContract)?;
        match uri.scheme_str() {
            Some("https") => {
                endpoint = endpoint
                    .tls_config(ClientTlsConfig::new().with_native_roots())
                    .map_err(|_| Error::InvalidContract)?
            }
            Some("http") if local => (), // upstream fleet-proof-app binds numeric loopback only
            _ => return Err(Error::InvalidContract),
        }
        Ok(endpoint
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30)))
    }

    /// Explicit channel injection supports private CA/mTLS and test servers.
    /// The deployment owns channel authentication; never accept an agent's channel.
    pub fn from_channel(
        channel: Channel,
        token: &str,
        program: ProgramRef,
        elf: Vec<u8>,
    ) -> Result<Self> {
        if token.trim().is_empty()
            || elf.is_empty()
            || elf.len() > 64 * 1024 * 1024
            || hex::encode(Sha256::digest(&elf)) != program.program_sha256
        {
            return Err(Error::InvalidContract);
        }
        let mut bearer: MetadataValue<Ascii> = format!("Bearer {}", token.trim())
            .parse()
            .map_err(|_| Error::InvalidContract)?;
        bearer.set_sensitive(true);
        Ok(Self {
            channel,
            bearer,
            program,
            elf,
            fleet_signer: None,
        })
    }

    /// Compatibility with Fleet deployments that require the token-bound
    /// EIP-191 SDK signer in addition to bearer authentication. New token-only
    /// proof networks need no signer. Never discover keys from the filesystem.
    pub fn with_fleet_signer(mut self, secret: &[u8]) -> Result<Self> {
        self.fleet_signer =
            Some(k256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::InvalidContract)?);
        Ok(self)
    }
    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("authorization", self.bearer.clone());
        request
    }
}

pub(crate) fn valid_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[async_trait]
impl ProofNetwork for ZirenNetwork {
    async fn submit(&self, request: &ProofRequest) -> Result<String> {
        if request.program != self.program
            || !valid_job_id(&request.request_id)
            || request.witness.is_empty()
            || request.witness.len() > trusted_rail::rego::MAX_WITNESS_BYTES
            || request.expected_public_values.is_empty()
            || request.expected_public_values.len() > trusted_rail::rego::MAX_PUBLIC_BYTES
        {
            return Err(Error::InvalidContract);
        }
        // Upstream NetworkProver serializes ZKMStdin.buffer, not the raw witness.
        let input = bincode::serialize(&vec![request.witness.clone()])
            .map_err(|_| Error::InvalidContract)?;
        let response = StageServiceClient::new(self.channel.clone())
            .max_encoding_message_size(70 * 1024 * 1024)
            .max_decoding_message_size(MAX_RECEIPT)
            .generate_proof(self.request(GenerateProofRequest {
                proof_id: request.request_id.clone(),
                signature: match &self.fleet_signer {
                    Some(key) => fleet_signature(key, &request.request_id)?,
                    None => String::new(),
                },
                elf_data: self.elf.clone(), // upload actual approved ELF; do not assume server cache
                private_input_stream: input,
                target_step: Some(Step::InSnark as i32),
                ..Default::default()
            }))
            .await
            .map_err(|_| Error::Unavailable)?
            .into_inner();
        if response.proof_id != request.request_id
            || !matches!(
                Status::try_from(response.status),
                Ok(Status::Success | Status::Computing | Status::Unspecified)
            )
        {
            return Err(Error::Untrusted);
        }
        Ok(response.proof_id)
    }
    async fn status(&self, job_id: &str) -> Result<ProofStatus> {
        if !valid_job_id(job_id) {
            return Err(Error::InvalidContract);
        }
        let response = StageServiceClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_RECEIPT)
            .get_status(self.request(GetStatusRequest {
                proof_id: job_id.into(),
            }))
            .await
            .map_err(|_| Error::Unavailable)?
            .into_inner();
        if response.proof_id != job_id {
            return Err(Error::Untrusted);
        }
        match Status::try_from(response.status) {
            Ok(Status::Computing | Status::Unspecified) => Ok(ProofStatus::Pending),
            Ok(Status::Success) if !response.proof_with_public_inputs.is_empty() => {
                // The verifier authenticates the expected public bytes directly.
                // Do not follow worker-supplied download URLs or trust output_stream.
                Ok(ProofStatus::Complete(ProofReceipt {
                    job_id: job_id.into(),
                    encoded_receipt: response.proof_with_public_inputs,
                }))
            }
            Ok(Status::Success) => Err(Error::Untrusted),
            _ => Ok(ProofStatus::Failed),
        }
    }
}

// Fleet token::signed_message for block_no=None, seg_size=0. Use the same
// EIP-191 encoding and recoverable ECDSA libraries as upstream fleet-scheduler.
fn fleet_signature(key: &k256::ecdsa::SigningKey, job_id: &str) -> Result<String> {
    let message = format!("{job_id}&0");
    let hash = alloy_primitives::eip191_hash_message(message.as_bytes());
    let (signature, recovery) = key
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|_| Error::InvalidContract)?;
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(27 + recovery.to_byte());
    Ok(hex::encode(bytes))
}
