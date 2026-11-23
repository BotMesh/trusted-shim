//! TEE startup uses the same evidence/proof/launch pipeline in hardware and
//! simulation modes. Only the operator selects the evidence service and guest.
use crate::{
    attestation::AttestationRequirement,
    contracts::{ExecutionIdentity, ProofKind},
    docker::DockerDriver,
    proof::*,
    runtime::{LaunchRequest, RuntimeDriver, RuntimeState, RuntimeStatus},
    Error, Result,
};
pub mod trustee;
pub use trusted_attestation_types::{Binding, Mode};

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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DcapConfig {
    /// Automata Collateral::sol_abi_encode() artifact, refreshed outside the guest.
    pub collateral_file: PathBuf,
    pub min_tcb_evaluation_data_number: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeeConfig {
    pub mode: Mode,
    /// Confidential VM profiles: snp/tdx; sample is admitted only in simulation mode.
    pub platform: String,
    pub evidence_endpoint: String,
    #[serde(default)]
    pub trustee_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustee_tls: Option<trustee::TlsConfig>,
    #[serde(default)]
    pub trustee_policy_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dcap: Option<DcapConfig>,
    /// Digest of measured init-data that confines this shim and its local runtime endpoints.
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
    trusted_attestation_types::canonical(value).map_err(|_| Error::InvalidContract)
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
        if self.trustee_endpoint.is_empty() {
            if self.trustee_tls.is_some()
                || !self.trustee_policy_ids.is_empty()
                || self.dcap.is_none()
            {
                return Err(Error::InvalidContract);
            }
        } else {
            trustee::validate_endpoint(&self.trustee_endpoint, self.trustee_tls.as_ref())?;
            if self.trustee_policy_ids.is_empty() {
                return Err(Error::InvalidContract);
            }
        }
        if let Some(dcap) = &self.dcap {
            if self.mode != Mode::Hardware
                || self.platform != "tdx"
                || !dcap.collateral_file.is_absolute()
                || dcap.min_tcb_evaluation_data_number == 0
            {
                return Err(Error::InvalidContract);
            }
        }
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
            || (self.dcap.is_some() && !valid_hash(&self.expected_measurement))
            || !valid_hash(&self.init_data_sha256)
            || !valid_hash(&self.endpoint_key_sha256)
            || !valid_hash(&self.program.program_sha256)
            || !valid_hash(&self.program.verifying_key_sha256)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dcap: Option<DcapPending>,
    submitted: bool,
    authorized: bool,
}

/// The admission an in-place restart is on. `used` is set before the container
/// is started, so one admission never starts it twice; the next restart then
/// claims a new one.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Starts {
    start: u64,
    used: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DcapPending {
    collateral: Vec<u8>,
    verification_time: u64,
}

/// Durable RA admission shared by machine-local runtime backends.
pub struct AttestationGate {
    config: TeeConfig,
    state: PathBuf,
    evidence: Arc<dyn EvidenceSource>,
    trustee: Option<trustee::Trustee>,
    network: Arc<dyn ProofNetwork>,
    verifier: Arc<dyn ReceiptVerifier>,
    serial: tokio::sync::Mutex<()>,
}

impl AttestationGate {
    pub fn new(
        state: &Path,
        config: TeeConfig,
        evidence: Arc<dyn EvidenceSource>,
        trustee: impl Into<Option<trustee::Trustee>>,
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
            state,
            config,
            evidence,
            trustee: trustee.into(),
            network,
            verifier,
            serial: tokio::sync::Mutex::new(()),
        })
    }

    #[cfg(feature = "ziren")]
    pub async fn connect(state: &Path, config: TeeConfig) -> Result<Self> {
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
        let trustee = if config.trustee_endpoint.is_empty() {
            None
        } else {
            Some(
                trustee::Trustee::connect(
                    &config.trustee_endpoint,
                    config.trustee_policy_ids.clone(),
                    config.trustee_tls.as_ref(),
                )
                .await?,
            )
        };
        Self::new(
            state,
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
    /// The admission record of an execution's `start`: 0 is its launch, each
    /// in-place restart after it has the next number and its own nonce.
    fn path(&self, execution: &ExecutionIdentity, start: u64) -> Result<PathBuf> {
        let id = digest(execution)?;
        Ok(self.state.join(match start {
            0 => format!("{id}.json"),
            n => format!("{id}.start-{n}.json"),
        }))
    }
    fn starts_path(&self, execution: &ExecutionIdentity) -> Result<PathBuf> {
        Ok(self
            .state
            .join(format!("{}.starts.json", digest(execution)?)))
    }
    fn save(&self, path: &Path, value: &impl Serialize) -> Result<()> {
        let mut file =
            tempfile::NamedTempFile::new_in(&self.state).map_err(|_| Error::Unavailable)?;
        file.write_all(&serde_json::to_vec(value).map_err(|_| Error::InvalidContract)?)
            .map_err(|_| Error::Unavailable)?;
        file.as_file().sync_all().map_err(|_| Error::Unavailable)?;
        file.persist(path).map_err(|_| Error::Unavailable)?;
        std::fs::File::open(&self.state)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)
    }
}

/// A verified receipt authorizes creation only while its challenge is fresh.
pub struct AttestationAdmission {
    expires_at: u64,
}
impl AttestationAdmission {
    pub fn ensure_fresh(&self) -> Result<()> {
        if now()? >= self.expires_at {
            return Err(Error::Untrusted);
        }
        Ok(())
    }
}
impl AttestationGate {
    /// A node may require RA even for requests that do not request attestation.
    pub fn validate_request(&self, request: &LaunchRequest) -> Result<()> {
        match (&request.trust.attestation, &request.trust.attestation_proof) {
            (AttestationRequirement::SkipNonTee, ProofRequirement::NotRequired) => (),
            (AttestationRequirement::Required { profile }, ProofRequirement::Required)
                if profile == &self.config.platform => {}
            _ => return Err(Error::Unsupported),
        }
        if self.config.mode == Mode::Hardware {
            let suffix = request
                .image
                .rsplit_once("@sha256:")
                .map(|(_, digest)| digest);
            if suffix.is_none_or(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(Error::InvalidContract);
            }
        }
        Ok(())
    }
    /// Bind the backend's immutable create operation, excluding bearer tokens.
    /// Callers check freshness immediately before dispatch.
    pub async fn authorize(
        &self,
        execution: &ExecutionIdentity,
        operation: &(impl Serialize + Sync),
    ) -> Result<AttestationAdmission> {
        self.authorize_start(execution, 0, digest(operation)?).await
    }

    /// Admits one start of an execution whose launch bound `request_sha256`.
    /// Each start has its own record, so a restart gets fresh evidence and a
    /// proof of its own; the binding format the guest verifies is unchanged.
    pub(crate) async fn authorize_start(
        &self,
        execution: &ExecutionIdentity,
        start: u64,
        request_sha256: String,
    ) -> Result<AttestationAdmission> {
        // The budget starts once this node's single admission slot is held, so
        // waiting behind another admission does not use it up.
        let _serial = self.serial.lock().await;
        tokio::time::timeout(
            Duration::from_secs(300),
            self.authorize_inner(execution, start, request_sha256),
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// The request an execution's launch was admitted with, under this same
    /// configuration. A restart is admitted for exactly that request. After any
    /// change to the TEE configuration, the launch's admission no longer
    /// matches, so a crashed runtime stays down until it is launched again.
    pub(crate) fn launched_request(&self, execution: &ExecutionIdentity) -> Result<String> {
        let pending = self
            .read_pending(&self.path(execution, 0)?)?
            .ok_or(Error::Ownership)?;
        if !pending.authorized
            || pending.binding.execution != *execution
            || pending.config_sha256 != digest(&self.config)?
        {
            return Err(Error::Untrusted);
        }
        Ok(pending.binding.request_sha256)
    }

    /// The start a restart is admitted under. It continues the current one
    /// while that is unused and its admission can still complete, so a
    /// retried or interrupted restart resumes the same proof instead of
    /// submitting another; otherwise it durably claims the next number.
    pub(crate) async fn claim_start(&self, execution: &ExecutionIdentity) -> Result<u64> {
        let _serial = self.serial.lock().await;
        let path = self.starts_path(execution)?;
        let current = self.read_starts(&path)?;
        if let Some(Starts { start, used: false }) = current {
            match self.read_pending(&self.path(execution, start)?)? {
                None => return Ok(start),
                Some(pending) if now()? < pending.binding.expires_at => return Ok(start),
                Some(_) => (),
            }
        }
        let start = current
            .as_ref()
            .map_or(Some(1), |c| c.start.checked_add(1))
            .ok_or(Error::InvalidContract)?;
        // The previous restart's admission is spent or expired: remove it, so an
        // execution keeps at most one, however often it crashes. Removing it
        // first is safe: if the counter is not advanced, that start is claimed
        // again with a new record and a new nonce.
        if let Some(previous) = &current {
            match std::fs::remove_file(self.path(execution, previous.start)?) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err(Error::Unavailable),
            }
        }
        self.save(&path, &Starts { start, used: false })?;
        Ok(start)
    }

    /// Spends an admitted start immediately before its container is started.
    /// A start that fails after this point is never retried with the same
    /// admission.
    pub(crate) async fn use_start(&self, execution: &ExecutionIdentity, start: u64) -> Result<()> {
        let _serial = self.serial.lock().await;
        let path = self.starts_path(execution)?;
        match self.read_starts(&path)? {
            Some(Starts {
                start: s,
                used: false,
            }) if s == start => self.save(&path, &Starts { start, used: true }),
            _ => Err(Error::Ownership),
        }
    }

    fn read_starts(&self, path: &Path) -> Result<Option<Starts>> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Error::InvalidContract),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }
    fn read_pending(&self, path: &Path) -> Result<Option<Pending>> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Error::InvalidContract),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }

    async fn authorize_inner(
        &self,
        execution: &ExecutionIdentity,
        start: u64,
        request_sha256: String,
    ) -> Result<AttestationAdmission> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(self.state.join("launch.lock"))
            .map_err(|_| Error::Unavailable)?;
        lock.try_lock_exclusive().map_err(|_| Error::Ownership)?;
        let path = self.path(execution, start)?;
        let config_sha256 = digest(&self.config)?;
        let mut pending: Pending = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut nonce = [0u8; 32];
                getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
                let verification_time = now()?;
                let binding = Binding {
                    domain: if self.config.dcap.is_some() {
                        trusted_attestation_types::DCAP_DOMAIN
                    } else {
                        "trusted-shim.remote-attestation.v1"
                    }
                    .into(),
                    mode: self.config.mode,
                    platform: self.config.platform.clone(),
                    expected_measurement: self.config.expected_measurement.clone(),
                    init_data_sha256: self.config.init_data_sha256.clone(),
                    endpoint_key_sha256: self.config.endpoint_key_sha256.clone(),
                    execution: execution.clone(),
                    request_sha256: request_sha256.clone(),
                    nonce: hex::encode(nonce),
                    expires_at: verification_time + 300,
                };
                let report_data =
                    hex::decode(digest(&binding)?).map_err(|_| Error::InvalidContract)?;
                let evidence = self.evidence.evidence(&report_data).await?;
                if evidence.is_empty() || evidence.len() > 128 * 1024 {
                    return Err(Error::InvalidContract);
                }
                if let Some(trustee) = &self.trustee {
                    trustee.evaluate(&binding, &evidence).await?;
                }
                let dcap = self
                    .config
                    .dcap
                    .as_ref()
                    .map(|dcap| {
                        Ok(DcapPending {
                            collateral: read_bounded(&dcap.collateral_file, 1024 * 1024, false)?,
                            verification_time,
                        })
                    })
                    .transpose()?;
                let pending = Pending {
                    job_id: format!("ra-{}", binding.nonce),
                    binding,
                    config_sha256: config_sha256.clone(),
                    evidence,
                    dcap,
                    submitted: false,
                    authorized: false,
                };
                self.save(&path, &pending)?;
                pending
            }
            Err(_) => return Err(Error::Unavailable),
        };
        if pending.binding.request_sha256 != request_sha256
            || pending.binding.execution != *execution
            || pending.config_sha256 != config_sha256
        {
            return Err(Error::Untrusted);
        }
        if pending.authorized {
            return Ok(AttestationAdmission {
                expires_at: pending.binding.expires_at,
            });
        }
        if now()? >= pending.binding.expires_at {
            return Err(Error::Untrusted);
        }
        let (witness, expected) = match (&self.config.dcap, &pending.dcap) {
            (Some(config), Some(dcap)) => {
                let witness = trusted_attestation_types::DcapWitness {
                    binding: pending.binding.clone(),
                    evidence: pending.evidence.clone(),
                    collateral: dcap.collateral.clone(),
                    verification_time: dcap.verification_time,
                    min_tcb_evaluation_data_number: config.min_tcb_evaluation_data_number,
                };
                let public = witness
                    .expected_public_values()
                    .map_err(|_| Error::InvalidContract)?;
                let bytes = canonical(&witness)?;
                if bytes.len() > trusted_attestation_types::MAX_WITNESS_BYTES {
                    return Err(Error::InvalidContract);
                }
                (bytes, public)
            }
            (None, None) => (
                canonical(
                    &serde_json::json!({"binding":pending.binding,"evidence":pending.evidence}),
                )?,
                canonical(
                    &serde_json::json!({"binding":pending.binding,"evidence_sha256":hex::encode(Sha256::digest(&pending.evidence))}),
                )?,
            ),
            _ => return Err(Error::Untrusted),
        };
        if !pending.submitted {
            // Persist BEFORE the RPC; an ambiguous submission is only queried, never resubmitted.
            pending.submitted = true;
            self.save(&path, &pending)?;
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
                    return Ok(AttestationAdmission {
                        expires_at: pending.binding.expires_at,
                    });
                }
            }
        }
    }
}

/// Docker lifecycle inside a measured confidential VM. OpenShell calls the
/// admission gate directly, without passing through this Docker adapter.
pub struct TeeDriver {
    gate: AttestationGate,
    backend: DockerDriver,
    /// Executions whose in-place restart is being admitted.
    resuming: std::sync::Mutex<std::collections::HashSet<String>>,
}

/// Holds an execution's place in `TeeDriver::resuming` until its restart ends.
struct Resuming<'a>(&'a TeeDriver, String);
impl Drop for Resuming<'_> {
    fn drop(&mut self) {
        if let Ok(mut set) = self.0.resuming.lock() {
            set.remove(&self.1);
        }
    }
}
impl TeeDriver {
    pub fn new(
        state: &Path,
        node: String,
        config: TeeConfig,
        evidence: Arc<dyn EvidenceSource>,
        trustee: impl Into<Option<trustee::Trustee>>,
        network: Arc<dyn ProofNetwork>,
        verifier: Arc<dyn ReceiptVerifier>,
    ) -> Result<Self> {
        let gate = AttestationGate::new(state, config, evidence, trustee, network, verifier)?;
        Ok(Self {
            backend: DockerDriver::new(gate.state.join("runtime"), node)?,
            gate,
            resuming: Default::default(),
        })
    }
    #[cfg(feature = "ziren")]
    pub async fn connect(state: &Path, node: String, config: TeeConfig) -> Result<Self> {
        let gate = AttestationGate::connect(state, config).await?;
        Ok(Self {
            backend: DockerDriver::new(gate.state.join("runtime"), node)?,
            gate,
            resuming: Default::default(),
        })
    }
    pub fn driver(&self) -> &'static str {
        self.gate.driver()
    }
    pub fn gate(&self) -> &AttestationGate {
        &self.gate
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

    async fn launch_inner(&self, request: &LaunchRequest) -> Result<RuntimeStatus> {
        if request.driver != self.driver()
            || request.trust.attestation
                != (AttestationRequirement::Required {
                    profile: self.gate.config.platform.clone(),
                })
            || request.trust.attestation_proof != ProofRequirement::Required
            || request.trust.policy_proof != ProofRequirement::NotRequired
        {
            return Err(Error::Unsupported);
        }
        let options = self.backend.validate_launch(&Self::delegated(request))?;
        // In the confidential VM, the host's network is the VM's own. A
        // workload on it could reach the attestation agent, which serves on
        // loopback, and ask it for evidence over report data of its choosing.
        if options.network == Some(crate::docker::NetworkMode::Host) {
            return Err(Error::Unsupported);
        }
        self.gate.validate_request(request)?;
        let admission = self.gate.authorize(&request.execution, request).await?;
        if admission.ensure_fresh().is_err() {
            let status = self.backend.inspect(&request.execution).await?;
            if status.state == crate::runtime::RuntimeState::Starting {
                return Err(Error::Untrusted);
            }
            return Ok(status);
        }
        self.launch_admitted(request).await
    }

    /// Starts a Running allocation's own exited container again in place, as
    /// `DockerDriver::resume` does, but only behind a fresh admission: new
    /// evidence and a verified proof for the request the launch was admitted
    /// with. Nothing about the workload can change on a restart.
    ///
    /// The admission runs without the slot's lock, so `inspect` stays
    /// responsive and reports `starting`; a stop or delete during it is final,
    /// because the start re-checks the allocation under that lock. A failed or
    /// expired admission leaves the container stopped. One restart runs at a
    /// time per execution: a concurrent call reports the current status.
    /// A restart requires the TEE configuration the launch was admitted under;
    /// see `AttestationGate::launched_request`.
    pub async fn resume(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus> {
        let key = digest(execution)?;
        if !self
            .resuming
            .lock()
            .map_err(|_| Error::Unavailable)?
            .insert(key.clone())
        {
            return self.inspect(execution).await;
        }
        let _resuming = Resuming(self, key);
        // Only the admission is timed. Nothing cancels the restart once its
        // start is spent, so an admission is never wasted on a timeout.
        self.resume_inner(execution).await
    }

    async fn resume_inner(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus> {
        if let Some(status) = self.backend.resume_status(execution).await? {
            return Ok(status);
        }
        let request_sha256 = self.gate.launched_request(execution)?;
        let start = self.gate.claim_start(execution).await?;
        self.gate
            .authorize_start(execution, start, request_sha256)
            .await?
            .ensure_fresh()?;
        self.gate.use_start(execution, start).await?;
        self.backend.resume(execution).await
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
        let mut status = self.backend.inspect(execution).await?;
        if status.state == RuntimeState::Stopped
            && self
                .resuming
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contains(&digest(execution)?)
        {
            status.state = RuntimeState::Starting;
        }
        Ok(status)
    }
    async fn stop(&self, execution: &ExecutionIdentity) -> Result<()> {
        self.backend.stop(execution).await
    }
    async fn delete(&self, execution: &ExecutionIdentity) -> Result<()> {
        self.backend.delete(execution).await
    }
}

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
fn read_private(path: &Path, max: u64) -> Result<Vec<u8>> {
    read_bounded(path, max, true)
}
