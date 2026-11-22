//! Durable ownership for native OpenShell provisioning. This is a privileged
//! node adapter, not an agent API. The authorization ledger stays in the central
//! gateway; a node must use an authenticated client for that authority.
//!
//! Compute readiness is deliberately not application readiness. Only the native
//! gateway can join supervisor, policy and fence evidence before exposing a route.
use crate::{
    admission::execution_digest,
    attestation::AttestationRequirement,
    openshell::{NativeCreate, NativeDriver},
    proof::ProofRequirement,
    runtime::LaunchRequest,
    Error, Result,
};
use fs2::FileExt;
use openshell_core::proto::compute::v1::DriverSandbox;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use trusted_contracts::ExecutionIdentity;
use trusted_rail::{rego::commitment, AuthorizationLedger, EvaluationRequest, ExecutionGrant};

fn hash(domain: &str, value: &impl Serialize) -> Result<String> {
    commitment(domain, value).map_err(|_| Error::InvalidContract)
}
fn db<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| Error::Unavailable)
}

/// These parameters must be evaluated by Rail before obtaining a proof-backed
/// grant. The native digest binds the exact gateway-prepared protobuf bytes,
/// including split launch credentials, without putting credentials in the proof.
impl NativeCreate {
    pub fn authorization_parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "launch_sha256": self.launch_sha256,
            "native_sha256": self.native_sha256,
            "native_policy_sha256": self.policy_sha256,
        })
    }
    pub fn authorization_resource(&self) -> String {
        format!("openshell/sandbox/{}", self.sandbox.id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningPhase {
    Reserved,
    Authorizing,
    Dispatched,
    Created,
    Stopping,
    Stopped,
    Deleting,
    Deleted,
}

/// No native spec, environment, credentials or platform diagnostic messages.
#[derive(Clone, Debug, Serialize)]
pub struct ProvisioningStatus {
    pub execution: ExecutionIdentity,
    pub sandbox_id: String,
    pub phase: ProvisioningPhase,
    pub present: bool,
    pub platform_ready: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    execution: ExecutionIdentity,
    launch_sha256: String,
    native_sha256: String,
    authorization_sha256: String,
    sandbox_id: String,
    sandbox_name: String,
    workspace: String,
    phase: ProvisioningPhase,
    instance_id: Option<String>,
}

/// The directory is node-private and durable across upgrades. Tombstones and
/// sandbox identity claims are retained; wiping it while allocations exist is unsafe.
#[derive(Clone)]
pub struct ManagedNativeDriver {
    state: PathBuf,
    node_id: String,
    connection: Arc<Mutex<Connection>>,
    native: NativeDriver,
}

impl ManagedNativeDriver {
    pub fn open(state: PathBuf, node_id: String, native: NativeDriver) -> Result<Self> {
        if !state.is_absolute() || node_id.is_empty() {
            return Err(Error::InvalidContract);
        }
        let metadata = std::fs::symlink_metadata(&state).map_err(|_| Error::Unavailable)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(Error::Untrusted);
        }
        let path = state.join("openshell.sqlite");
        let _file = Self::private_file(path.clone())?;
        let connection = db(Connection::open(path))?;
        db(connection.busy_timeout(std::time::Duration::from_secs(5)))?;
        db(connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS allocations(slot TEXT PRIMARY KEY, record TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);",
        ))?;
        File::open(&state)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            state,
            node_id,
            connection: Arc::new(Mutex::new(connection)),
            native,
        })
    }

    fn private_file(path: PathBuf) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Unavailable)?;
        let m = file.metadata().map_err(|_| Error::Unavailable)?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.permissions().mode() & 0o077 != 0
            || m.nlink() != 1
        {
            return Err(Error::Untrusted);
        }
        Ok(file)
    }
    fn slot(&self, e: &ExecutionIdentity) -> Result<String> {
        if e.node_id != self.node_id {
            return Err(Error::Ownership);
        }
        if e.generation == 0
            || [
                &e.namespace,
                &e.workload,
                &e.allocation_id,
                &e.lease_id,
                &e.node_id,
            ]
            .iter()
            .any(|v| v.is_empty() || v.len() > 256 || v.contains('\0'))
        {
            return Err(Error::InvalidContract);
        }
        hash(
            "trusted-shim.openshell.slot.v1",
            &(&e.namespace, &e.workload, &e.allocation_id, &e.node_id),
        )
    }
    async fn lock(&self, slot: &str) -> Result<File> {
        let path = self.state.join(format!("openshell-{slot}.lock"));
        tokio::task::spawn_blocking(move || {
            let file = Self::private_file(path)?;
            file.lock_exclusive().map_err(|_| Error::Unavailable)?;
            Ok(file)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }
    fn read(&self, slot: &str) -> Result<Option<Record>> {
        let c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let record: Option<String> = db(c
            .query_row(
                "SELECT record FROM allocations WHERE slot=?1",
                [slot],
                |r| r.get(0),
            )
            .optional())?;
        record
            .map(|r| serde_json::from_str(&r).map_err(|_| Error::Untrusted))
            .transpose()
    }
    fn save(&self, slot: &str, record: &Record, fresh: bool) -> Result<()> {
        let json = serde_json::to_string(record).map_err(|_| Error::InvalidContract)?;
        let mut c = self.connection.lock().map_err(|_| Error::Unavailable)?;
        let tx = db(c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate))?;
        if fresh {
            tx.execute(
                "INSERT INTO identities VALUES(?1,?2)",
                params![record.sandbox_id, record.sandbox_name],
            )
            .map_err(|_| Error::Ownership)?;
        }
        db(tx.execute("INSERT INTO allocations VALUES(?1,?2) ON CONFLICT(slot) DO UPDATE SET record=excluded.record", params![slot, json]))?;
        db(tx.commit())
    }
    fn owned(&self, slot: &str, execution: &ExecutionIdentity) -> Result<Record> {
        let record = self.read(slot)?.ok_or(Error::Ownership)?;
        if &record.execution != execution {
            return Err(Error::Ownership);
        }
        Ok(record)
    }
    async fn observe(&self, slot: &str, record: &mut Record) -> Result<Option<DriverSandbox>> {
        if record.sandbox_id.is_empty() {
            return Ok(None);
        }
        let sandbox = self
            .native
            .inspect(&record.sandbox_id, &record.sandbox_name)
            .await?;
        if let Some(s) = &sandbox {
            if s.workspace != record.workspace {
                return Err(Error::Ownership);
            }
            if let Some(status) = &s.status {
                if let Some(expected) = &record.instance_id {
                    if status.instance_id != *expected {
                        return Err(Error::Ownership);
                    }
                } else if !status.instance_id.is_empty() {
                    record.instance_id = Some(status.instance_id.clone());
                    self.save(slot, record, false)?;
                }
            }
        }
        Ok(sandbox)
    }
    fn status(record: &Record, sandbox: Option<&DriverSandbox>) -> ProvisioningStatus {
        ProvisioningStatus {
            execution: record.execution.clone(),
            sandbox_id: record.sandbox_id.clone(),
            phase: record.phase,
            present: sandbox.is_some(),
            platform_ready: sandbox.and_then(|s| s.status.as_ref()).is_some_and(|s| {
                !s.deleting
                    && s.conditions
                        .iter()
                        .any(|c| c.r#type == "Ready" && c.status == "True")
            }),
        }
    }

    /// Grant is minted only after remote policy proof verification. Replays only
    /// inspect the original sandbox; neither a timeout nor a missing resource
    /// authorizes another CreateSandbox. The owner must reconcile ambiguous work.
    pub async fn launch(
        &self,
        request: &LaunchRequest,
        prepared: NativeCreate,
        authorization: &EvaluationRequest,
        grant: &ExecutionGrant,
        ledger: &dyn AuthorizationLedger,
    ) -> Result<ProvisioningStatus> {
        if request.trust.attestation != AttestationRequirement::SkipNonTee
            || request.trust.attestation_proof != ProofRequirement::NotRequired
        {
            return Err(Error::Unsupported);
        }
        // This grant proves provisioning policy only. It does not enable a
        // proof-required agent action boundary or attest a non-TEE machine.
        if request.trust.policy_proof != ProofRequirement::NotRequired
            || !request.services.is_empty()
        {
            return Err(Error::Unsupported);
        }
        let digest = execution_digest(authorization, grant)?;
        if prepared.launch_sha256 != hash("trusted-shim.launch.v1", request)?
            || prepared.sandbox.workspace != request.execution.namespace
            || authorization.execution != request.execution
            || authorization.operation != "runtime.create"
            || authorization.resource != prepared.authorization_resource()
            || authorization.parameters != prepared.authorization_parameters()
        {
            return Err(Error::Untrusted);
        }
        let slot = self.slot(&request.execution)?;
        let _lock = self.lock(&slot).await?;
        if let Some(mut old) = self.read(&slot)? {
            if old.execution == request.execution && old.phase != ProvisioningPhase::Reserved {
                if old.launch_sha256 != prepared.launch_sha256
                    || old.native_sha256 != prepared.native_sha256
                    || old.authorization_sha256 != digest
                    || !matches!(
                        old.phase,
                        ProvisioningPhase::Dispatched | ProvisioningPhase::Created
                    )
                {
                    return Err(Error::Ownership);
                }
                let observed = self.observe(&slot, &mut old).await?;
                return Ok(Self::status(&old, observed.as_ref()));
            }
            if old.execution != request.execution
                && (old.phase != ProvisioningPhase::Deleted
                    || request.execution.generation <= old.execution.generation
                    || self.observe(&slot, &mut old).await?.is_some())
            {
                return Err(Error::Ownership);
            }
        }
        if self
            .native
            .inspect(&prepared.sandbox.id, &prepared.sandbox.name)
            .await?
            .is_some()
        {
            return Err(Error::Ownership);
        }
        let mut record = Record {
            execution: request.execution.clone(),
            launch_sha256: prepared.launch_sha256.clone(),
            native_sha256: prepared.native_sha256.clone(),
            authorization_sha256: digest.clone(),
            sandbox_id: prepared.sandbox.id.clone(),
            sandbox_name: prepared.sandbox.name.clone(),
            workspace: prepared.sandbox.workspace.clone(),
            phase: ProvisioningPhase::Authorizing,
            instance_id: None,
        };
        let dispatch = self.native.prepare_dispatch(prepared).await?;
        self.save(&slot, &record, true)?;
        ledger
            .consume(grant, &request.execution, &digest)
            .await
            .map_err(|_| Error::Untrusted)?;
        execution_digest(authorization, grant)?; // consumption may outlive validity
        record.phase = ProvisioningPhase::Dispatched;
        self.save(&slot, &record, false)?;
        execution_digest(authorization, grant)?;
        dispatch.send().await?;
        record.phase = ProvisioningPhase::Created;
        self.save(&slot, &record, false)?;
        let observed = self.observe(&slot, &mut record).await?;
        Ok(Self::status(&record, observed.as_ref()))
    }

    pub async fn inspect(&self, execution: &ExecutionIdentity) -> Result<ProvisioningStatus> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let mut record = self.owned(&slot, execution)?;
        let observed = self.observe(&slot, &mut record).await?;
        Ok(Self::status(&record, observed.as_ref()))
    }

    /// Hold an admitted allocation before private provisioning material arrives.
    /// No credentials, proof consumption or native mutation is needed. Cleanup
    /// leaves a tombstone so a delayed grant cannot revive a cancelled lease.
    pub async fn reserve(&self, execution: &ExecutionIdentity) -> Result<ProvisioningStatus> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        if let Some(mut old) = self.read(&slot)? {
            let observed = self.observe(&slot, &mut old).await?;
            if old.execution == *execution {
                return Ok(Self::status(&old, observed.as_ref()));
            }
            if old.phase != ProvisioningPhase::Deleted
                || execution.generation <= old.execution.generation
                || observed.is_some()
            {
                return Err(Error::Ownership);
            }
        }
        let record = Record {
            execution: execution.clone(),
            launch_sha256: String::new(),
            native_sha256: String::new(),
            authorization_sha256: String::new(),
            sandbox_id: String::new(),
            sandbox_name: String::new(),
            workspace: execution.namespace.clone(),
            phase: ProvisioningPhase::Reserved,
            instance_id: None,
        };
        self.save(&slot, &record, false)?;
        Ok(Self::status(&record, None))
    }

    /// Cleanup uses persisted ownership, even after the launch grant expires.
    pub async fn delete(&self, execution: &ExecutionIdentity) -> Result<()> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let mut record = self.owned(&slot, execution)?;
        let observed = self.observe(&slot, &mut record).await?;
        // An unanswered create may still be in flight. An absent snapshot is
        // insufficient to release its reservation or authorize a new generation.
        if record.phase == ProvisioningPhase::Dispatched && observed.is_none() {
            return Err(Error::Unavailable);
        }
        record.phase = ProvisioningPhase::Deleting;
        self.save(&slot, &record, false)?;
        if !record.sandbox_id.is_empty() {
            self.native
                .delete(&record.sandbox_id, &record.sandbox_name)
                .await?;
        }
        record.phase = ProvisioningPhase::Deleted;
        self.save(&slot, &record, false)
    }

    pub async fn stop(&self, execution: &ExecutionIdentity) -> Result<()> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let mut record = self.owned(&slot, execution)?;
        if matches!(
            record.phase,
            ProvisioningPhase::Deleting | ProvisioningPhase::Deleted
        ) {
            return Err(Error::Ownership);
        }
        let observed = self.observe(&slot, &mut record).await?;
        if record.phase == ProvisioningPhase::Dispatched && observed.is_none() {
            return Err(Error::Unavailable);
        }
        record.phase = ProvisioningPhase::Stopping;
        self.save(&slot, &record, false)?;
        if !record.sandbox_id.is_empty() {
            self.native
                .stop(&record.sandbox_id, &record.sandbox_name)
                .await?;
        }
        let observed = self.observe(&slot, &mut record).await?;
        if observed.as_ref().is_some_and(|s| {
            !s.status.as_ref().is_some_and(|status| {
                status.conditions.iter().any(|c| {
                    c.r#type == "Ready" && c.status == "False" && c.reason == "ContainerExited"
                })
            })
        }) {
            return Err(Error::Unavailable);
        }
        record.phase = ProvisioningPhase::Stopped;
        self.save(&slot, &record, false)
    }
}
