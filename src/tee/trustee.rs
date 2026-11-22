//! Stock Trustee v0.19 gRPC adapter. Its appraisal is a precheck, never a ZK receipt.
use super::{canonical, Binding};
use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub mod wire {
    tonic::include_proto!("attestation");
}

/// Operator-owned node identity. Contents never enter launch records or proofs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

pub(super) fn validate_endpoint(endpoint: &str, tls: Option<&TlsConfig>) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| Error::InvalidContract)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::InvalidContract);
    }
    match (url.scheme(), tls) {
        ("https", Some(tls))
            if [&tls.ca_file, &tls.cert_file, &tls.key_file]
                .iter()
                .all(|p| p.is_absolute()) =>
        {
            Ok(())
        }
        ("http", None) if matches!(url.host_str(), Some("127.0.0.1" | "[::1]")) => Ok(()),
        _ => Err(Error::InvalidContract),
    }
}

#[derive(Clone)]
pub struct Trustee {
    channel: Channel,
    policies: Vec<String>,
}

impl Trustee {
    pub async fn connect(
        endpoint: &str,
        policies: Vec<String>,
        tls: Option<&TlsConfig>,
    ) -> Result<Self> {
        validate_endpoint(endpoint, tls)?;
        let mut channel =
            Endpoint::from_shared(endpoint.to_owned()).map_err(|_| Error::InvalidContract)?;
        if let Some(tls) = tls {
            let ca = super::read_bounded(&tls.ca_file, 256 * 1024, false)?;
            let cert = super::read_bounded(&tls.cert_file, 256 * 1024, false)?;
            let key = super::read_private(&tls.key_file, 64 * 1024)?;
            channel = channel
                .tls_config(
                    ClientTlsConfig::new()
                        .ca_certificate(Certificate::from_pem(ca))
                        .identity(Identity::from_pem(cert, key)),
                )
                .map_err(|_| Error::InvalidContract)?;
        }
        let channel = channel
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .connect_lazy();
        Ok(Self { channel, policies })
    }

    pub async fn evaluate(&self, binding: &Binding, evidence: &[u8]) -> Result<()> {
        use wire::{
            individual_attestation_request::{InitData, RuntimeData},
            *,
        };
        let mut client =
            attestation_service_client::AttestationServiceClient::new(self.channel.clone())
                .max_decoding_message_size(1024 * 1024);
        let init = hex::decode(&binding.init_data_sha256).map_err(|_| Error::InvalidContract)?;
        // Trustee's RuntimeData::Raw compares bytes directly (despite the proto
        // comment saying it hashes them). Supply the same digest sent to AA.
        let response = client
            .attestation_evaluate(AttestationRequest {
                verification_requests: vec![IndividualAttestationRequest {
                    tee: binding.platform.clone(),
                    evidence: URL_SAFE_NO_PAD.encode(evidence),
                    runtime_data: Some(RuntimeData::RawRuntimeData(
                        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(binding)?)),
                    )),
                    init_data: Some(InitData::InitDataDigest(URL_SAFE_NO_PAD.encode(init))),
                    runtime_data_hash_algorithm: "sha256".into(),
                }],
                policy_ids: self.policies.clone(),
            })
            .await
            .map_err(|_| Error::Untrusted)?
            .into_inner();
        if response.attestation_token.is_empty() {
            return Err(Error::Untrusted);
        }
        // Deliberately do not promote an AS token into evidence that the guest ran.
        // The independent pinned RA program must verify the original quote and collateral.
        Ok(())
    }
}
