//! TEE startup uses the same evidence/proof/launch pipeline in hardware and
//! simulation modes. Only the operator selects the evidence service and guest.
use crate::{
    attestation::AttestationRequirement,
    contracts::{ExecutionIdentity, ProofKind},
    docker::DockerDriver,
    proof::*,
    runtime::{LaunchRequest, RuntimeDriver, RuntimeStatus},
    Error, Result,
};
pub mod trustee;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Hardware,
    Simulation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeConfig {
    pub mode: Mode,
    /// Confidential VM profiles: snp/tdx; sample is admitted only in simulation mode.
    pub platform: String,
    pub evidence_endpoint: String,
    pub trustee_endpoint: String,
    pub trustee_policy_ids: Vec<String>,
    /// Digest of measured init-data that confines this shim and the local Docker socket.
    pub init_data_sha256: String,
    /// Runtime endpoint identity must be provisioned inside the measured guest.
    pub endpoint_key_sha256: String,
    pub expected_measurement: String,
    pub proof_endpoint: String,
    pub proof_token_file: PathBuf,
    pub program: ProgramRef,
    pub program_vkey_hash: String,
    pub elf_file: PathBuf,
    pub proof_signer_file: Option<PathBuf>,
}

pub fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| Error::InvalidContract)?;
    value.sort_all_objects();
    serde_json::to_vec(&value).map_err(|_| Error::InvalidContract)
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical(value)?)))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| Error::Unavailable)
}

impl TeeConfig {
    pub fn driver(&self) -> &'static str {
        match self.mode {
            Mode::Hardware => "tee",
            Mode::Simulation => "tee-simulation",
        }
    }
    pub fn validate(&self) -> Result<()> {
        let platform_ok = match self.mode {
            Mode::Simulation => self.platform == "sample",
            Mode::Hardware => matches!(self.platform.as_str(), "snp" | "tdx"),
        };
        let url =
            reqwest::Url::parse(&self.evidence_endpoint).map_err(|_| Error::InvalidContract)?;
        let valid_hash = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !platform_ok
            || !valid_hash(&self.init_data_sha256)
            || !valid_hash(&self.endpoint_key_sha256)
            || !valid_hash(&self.program.program_sha256)
            || !valid_hash(&self.program.verifying_key_sha256)
            || self.trustee_policy_ids.is_empty()
            || self.trustee_policy_ids.len() > 16
            || self
                .trustee_policy_ids
                .iter()
                .any(|p| p.is_empty() || p.len() > 128)
            || self.expected_measurement.is_empty()
            || self.expected_measurement.len() > 1024
            || self.program.kind != ProofKind::RemoteAttestation
            || !matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
            || url.scheme() != "http"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/aa/evidence"
        {
            return Err(Error::InvalidContract);
        }
        Ok(())
    }
}

/// Public inputs bind the proof to a mode, platform, measured environment,
/// exact launch request and fresh challenge. A sample proof cannot attest hardware.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub domain: String,
    pub mode: Mode,
    pub platform: String,
    pub expected_measurement: String,
    pub init_data_sha256: String,
    pub endpoint_key_sha256: String,
    pub execution: ExecutionIdentity,
    pub request_sha256: String,
    pub nonce: String,
    pub expires_at: u64,
}

#[async_trait]
pub trait EvidenceSource: Send + Sync {
    async fn evidence(&self, report_data: &[u8]) -> Result<Vec<u8>>;
}

pub struct CocoEvidence {
    endpoint: String,
    client: reqwest::Client,
}
impl CocoEvidence {
    pub fn new(endpoint: String) -> Result<Self> {
        Ok(Self {
            endpoint,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|_| Error::Unavailable)?,
        })
    }
}
#[async_trait]
impl EvidenceSource for CocoEvidence {
    async fn evidence(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        let mut response = self
            .client
            .get(&self.endpoint)
            .query(&[
                ("runtime_data", URL_SAFE_NO_PAD.encode(report_data)),
                ("encoding", "base64".into()),
            ])
            .send()
            .await
            .map_err(|_| Error::Unavailable)?
            .error_for_status()
            .map_err(|_| Error::Untrusted)?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
            if bytes.len() + chunk.len() > 512 * 1024 {
                return Err(Error::InvalidContract);
            }
            bytes.extend(chunk);
        }
        if bytes.is_empty() {
            return Err(Error::Untrusted);
        }
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    binding: Binding,
    config_sha256: String,
    job_id: String,
    evidence: Vec<u8>,
    submitted: bool,
    authorized: bool,
}

pub struct TeeDriver {
    config: TeeConfig,
    state: PathBuf,
    backend: DockerDriver,
    evidence: Arc<dyn EvidenceSource>,
    trustee: trustee::Trustee,
    network: Arc<dyn ProofNetwork>,
    verifier: Arc<dyn ReceiptVerifier>,
    serial: tokio::sync::Mutex<()>,
}

impl TeeDriver {
    pub fn new(
        state: &Path,
        node: String,
        config: TeeConfig,
        evidence: Arc<dyn EvidenceSource>,
        trustee: trustee::Trustee,
        network: Arc<dyn ProofNetwork>,
        verifier: Arc<dyn ReceiptVerifier>,
    ) -> Result<Self> {
        config.validate()?;
        let state = state.join("tee");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state)
            .map_err(|_| Error::Unavailable)?;
        let metadata = std::fs::symlink_metadata(&state).map_err(|_| Error::Unavailable)?;
        if !metadata.is_dir()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::Untrusted);
        }
        let profile = digest(&(
            config.mode,
            &config.platform,
            &config.init_data_sha256,
            &config.endpoint_key_sha256,
            &config.expected_measurement,
            &config.program,
        ))?;
        let profile_path = state.join("profile.sha256");
        match std::fs::read_to_string(&profile_path) {
            Ok(old) if old == profile => (),
            Ok(_) => return Err(Error::Untrusted),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut file =
                    tempfile::NamedTempFile::new_in(&state).map_err(|_| Error::Unavailable)?;
                file.write_all(profile.as_bytes())
                    .map_err(|_| Error::Unavailable)?;
                file.as_file().sync_all().map_err(|_| Error::Unavailable)?;
                file.persist_noclobber(&profile_path)
                    .map_err(|_| Error::Ownership)?;
                std::fs::File::open(&state)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| Error::Unavailable)?;
            }
            Err(_) => return Err(Error::Unavailable),
        }
        Ok(Self {
            backend: DockerDriver::new(state.join("runtime"), node)?,
            state,
            config,
            evidence,
            trustee,
            network,
            verifier,
            serial: tokio::sync::Mutex::new(()),
        })
    }

    #[cfg(feature = "ziren")]
    pub async fn connect(state: &Path, node: String, config: TeeConfig) -> Result<Self> {
        config.validate()?;
        let token_text = read_private(&config.proof_token_file, 4096)?;
        let token_text = std::str::from_utf8(&token_text).map_err(|_| Error::InvalidContract)?;
        let elf = read_bounded(&config.elf_file, 64 * 1024 * 1024, false)?;
        let mut network = crate::network::ZirenNetwork::connect_lazy(
            &config.proof_endpoint,
            token_text,
            config.program.clone(),
            elf,
        )?;
        if let Some(path) = &config.proof_signer_file {
            let secret = read_private(path, 256)?;
            let text = std::str::from_utf8(&secret)
                .map_err(|_| Error::InvalidContract)?
                .trim();
            let key = hex::decode(text.strip_prefix("0x").unwrap_or(text))
                .map_err(|_| Error::InvalidContract)?;
            network = network.with_fleet_signer(&key)?;
        }
        let verifier = crate::ziren::ZirenGroth16Verifier::new(
            config.program.clone(),
            &config.program_vkey_hash,
        )?;
        let evidence = CocoEvidence::new(config.evidence_endpoint.clone())?;
        let trustee =
            trustee::Trustee::connect(&config.trustee_endpoint, config.trustee_policy_ids.clone())
                .await?;
        Self::new(
            state,
            node,
            config,
            Arc::new(evidence),
            trustee,
            Arc::new(network),
            Arc::new(verifier),
        )
    }

    pub fn driver(&self) -> &'static str {
        self.config.driver()
    }
    pub(crate) fn backend(&self) -> &DockerDriver {
        &self.backend
    }
    fn delegated(request: &LaunchRequest) -> LaunchRequest {
        // Hardware deployment is inside an already measured confidential VM, not
        // an SGX host or a host-side Docker socket. The pinned RA guest must enforce
        // that measured init-data covers this shim, its key and the local runtime.
        let mut delegated = request.clone();
        delegated.driver = "docker".into();
        delegated.trust.attestation = AttestationRequirement::SkipNonTee;
        delegated.trust.attestation_proof = ProofRequirement::NotRequired;
        delegated
    }
    async fn launch_admitted(&self, request: &LaunchRequest) -> Result<RuntimeStatus> {
        self.backend.launch(&Self::delegated(request)).await
    }
    fn path(&self, execution: &ExecutionIdentity) -> Result<PathBuf> {
        Ok(self.state.join(format!("{}.json", digest(execution)?)))
    }
    fn save(&self, path: &Path, pending: &Pending) -> Result<()> {
        let mut file =
            tempfile::NamedTempFile::new_in(&self.state).map_err(|_| Error::Unavailable)?;
        file.write_all(&serde_json::to_vec(pending).map_err(|_| Error::InvalidContract)?)
            .map_err(|_| Error::Unavailable)?;
        file.as_file().sync_all().map_err(|_| Error::Unavailable)?;
        file.persist(path).map_err(|_| Error::Unavailable)?;
        std::fs::File::open(&self.state)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)
    }
}

#[async_trait]
impl RuntimeDriver for TeeDriver {
    async fn launch(&self, request: &LaunchRequest) -> Result<RuntimeStatus> {
        tokio::time::timeout(Duration::from_secs(300), self.launch_inner(request))
            .await
            .map_err(|_| Error::Unavailable)?
    }
    async fn inspect(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus> {
        self.backend.inspect(execution).await
    }
    async fn stop(&self, execution: &ExecutionIdentity) -> Result<()> {
        self.backend.stop(execution).await
    }
    async fn delete(&self, execution: &ExecutionIdentity) -> Result<()> {
        self.backend.delete(execution).await
    }
}

impl TeeDriver {
    async fn launch_inner(&self, request: &LaunchRequest) -> Result<RuntimeStatus> {
        if request.driver != self.driver()
            || request.trust.attestation != (AttestationRequirement::Required { profile: self.config.platform.clone() })
            || request.trust.attestation_proof != ProofRequirement::Required
            // Policy admission remains a separate gate; never claim it was proved here.
            || request.trust.policy_proof != ProofRequirement::NotRequired
        {
            return Err(Error::Unsupported);
        }
        self.backend.validate_launch(&Self::delegated(request))?;
        if self.config.mode == Mode::Hardware {
            let suffix = request
                .image
                .rsplit_once("@sha256:")
                .map(|(_, digest)| digest);
            if suffix.is_none_or(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(Error::InvalidContract);
            }
        }
        let _serial = self.serial.lock().await;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.state.join("launch.lock"))
            .map_err(|_| Error::Unavailable)?;
        lock.try_lock_exclusive().map_err(|_| Error::Ownership)?;
        let path = self.path(&request.execution)?;
        let request_sha256 = digest(request)?;
        let config_sha256 = digest(&self.config)?;
        let mut pending: Pending = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut nonce = [0u8; 32];
                getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
                let binding = Binding {
                    domain: "trusted-shim.remote-attestation.v1".into(),
                    mode: self.config.mode,
                    platform: self.config.platform.clone(),
                    expected_measurement: self.config.expected_measurement.clone(),
                    init_data_sha256: self.config.init_data_sha256.clone(),
                    endpoint_key_sha256: self.config.endpoint_key_sha256.clone(),
                    execution: request.execution.clone(),
                    request_sha256: request_sha256.clone(),
                    nonce: hex::encode(nonce),
                    expires_at: now()? + 300,
                };
                let report_data =
                    hex::decode(digest(&binding)?).map_err(|_| Error::InvalidContract)?;
                let evidence = self.evidence.evidence(&report_data).await?;
                if evidence.is_empty() || evidence.len() > 128 * 1024 {
                    return Err(Error::InvalidContract);
                }
                self.trustee.evaluate(&binding, &evidence).await?;
                let pending = Pending {
                    job_id: format!("ra-{}", binding.nonce),
                    binding,
                    config_sha256: config_sha256.clone(),
                    evidence,
                    submitted: false,
                    authorized: false,
                };
                self.save(&path, &pending)?;
                pending
            }
            Err(_) => return Err(Error::Unavailable),
        };
        if pending.binding.request_sha256 != request_sha256
            || pending.binding.execution != request.execution
            || pending.config_sha256 != config_sha256
        {
            return Err(Error::Untrusted);
        }
        // After admission, retries reconcile the already-authorized exact request.
        // Docker's durable tombstone prevents a stopped/deleted generation restarting.
        if pending.authorized {
            if now()? >= pending.binding.expires_at {
                // An expired grant can only observe an already created workload.
                let status = self.backend.inspect(&request.execution).await?;
                if status.state == crate::runtime::RuntimeState::Starting {
                    return Err(Error::Untrusted);
                }
                return Ok(status);
            }
            return self.launch_admitted(request).await;
        }
        if now()? >= pending.binding.expires_at {
            return Err(Error::Untrusted);
        }
        let public = serde_json::json!({"binding":pending.binding,"evidence_sha256":hex::encode(Sha256::digest(&pending.evidence))});
        let expected = canonical(&public)?;
        if !pending.submitted {
            // Persist BEFORE the RPC; an ambiguous submission is only queried, never resubmitted.
            pending.submitted = true;
            self.save(&path, &pending)?;
            let witness = canonical(
                &serde_json::json!({"binding":pending.binding,"evidence":pending.evidence}),
            )?;
            let id = self
                .network
                .submit(&ProofRequest {
                    request_id: pending.job_id.clone(),
                    program: self.config.program.clone(),
                    witness,
                    expected_public_values: expected.clone(),
                })
                .await?;
            if id != pending.job_id {
                return Err(Error::Untrusted);
            }
        }
        loop {
            if now()? >= pending.binding.expires_at {
                return Err(Error::Untrusted);
            }
            match self.network.status(&pending.job_id).await? {
                ProofStatus::Pending => tokio::time::sleep(Duration::from_millis(100)).await,
                ProofStatus::Failed => return Err(Error::Untrusted),
                ProofStatus::Complete(receipt) => {
                    if receipt.job_id != pending.job_id {
                        return Err(Error::Untrusted);
                    }
                    self.verifier
                        .verify(&self.config.program, &receipt, &expected)?;
                    if now()? >= pending.binding.expires_at {
                        return Err(Error::Untrusted);
                    }
                    pending.authorized = true;
                    self.save(&path, &pending)?;
                    return self.launch_admitted(request).await;
                }
            }
        }
    }
}

#[cfg(feature = "ziren")]
fn read_bounded(path: &Path, max: u64, private: bool) -> Result<Vec<u8>> {
    use std::io::Read;
    if !path.is_absolute() {
        return Err(Error::InvalidContract);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Error::Unavailable)?;
    let meta = file.metadata().map_err(|_| Error::Unavailable)?;
    if !meta.is_file()
        || private
            && (meta.permissions().mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() })
    {
        return Err(Error::Untrusted);
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(Error::InvalidContract);
    }
    Ok(bytes)
}
#[cfg(feature = "ziren")]
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    read_bounded(path, max, true)
}
