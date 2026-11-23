//! Machine-local Docker lifecycle. The caller is the authenticated node adapter,
//! never an agent. This driver provides resource limits, not shell policy isolation.
use crate::{
    attestation::AttestationRequirement,
    proof::ProofRequirement,
    runtime::{
        ExitStatus, LaunchRequest, ResourceLimits, RuntimeDriver, RuntimeState, RuntimeStatus,
    },
    Error, Result,
};
use async_trait::async_trait;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use trusted_contracts::ExecutionIdentity;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerOptions {
    pub user: Option<String>,
    pub workdir: Option<String>,
    /// Administrator-approved Docker bind specifications, source:destination[:options].
    pub volumes: Vec<String>,
    /// Host GPU ids already granted by the local allocator.
    pub gpus: Vec<String>,
    pub shm_bytes: Option<u64>,
    /// A single service port, published only on host loopback.
    pub port: Option<u16>,
    pub container_port: Option<u16>,
    pub entrypoint: Option<String>,
    pub stop_timeout_s: Option<u32>,
    /// HTTP surfaces approved in the existing application manifest.
    pub ingress: std::collections::BTreeMap<String, crate::management::Ingress>,
    /// The container's network. Unset, it is Docker's default bridge network,
    /// with `port` published on host loopback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkMode>,
    /// A run that ends when its process exits, such as a batch job. It has
    /// no port or services, and its container is never started again: not by
    /// `resume` or `restart`, and not by a replayed launch. It is kept, with its exit
    /// status and logs, until `delete`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub run_to_completion: bool,
}

/// A network other than Docker's default bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Loopback only: no egress, no published port and no services.
    None,
    /// The host's own network namespace. The container listens on `port`
    /// itself and reaches everything the host does, including its loopback
    /// services, so only an administrator should choose it. A TEE runtime
    /// refuses it: in a confidential VM that includes the attestation agent.
    Host,
}

impl NetworkMode {
    /// Docker's `HostConfig.NetworkMode` for this network.
    fn docker(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Host => "host",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Creating,
    Starting,
    Running,
    Stopped,
    Deleted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    execution: ExecutionIdentity,
    request_sha256: String,
    limits: ResourceLimits,
    phase: Phase,
    stop_timeout_s: u32,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    allocated_port: bool,
    #[serde(default)]
    services: Vec<trusted_data_router::ServiceSpec>,
    #[serde(default)]
    ingress: std::collections::BTreeMap<String, crate::management::Ingress>,
    /// Omitted for Docker's default network, so existing journals keep their bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<NetworkMode>,
    /// Omitted when false, so existing journals keep their bytes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    run_to_completion: bool,
}

/// A window of a runtime's output, from `DockerDriver::read_logs`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLogs {
    /// Base64 of whole lines, each starting with its RFC 3339 UTC time.
    pub output: String,
    /// `since` for the next read: Unix seconds and nanoseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_since: Option<String>,
    /// Output after this window was already there; read again at once.
    pub more: bool,
}

/// Private state must survive upgrades, deletion and restart. A tombstone fences
/// old generations; removing this directory while allocations exist is unsafe.
#[derive(Clone)]
pub struct DockerDriver {
    state: PathBuf,
    node_id: String,
}

/// Docker's accepted `--cpu-shares` range on Linux.
const CPU_SHARES: std::ops::RangeInclusive<u64> = 2..=262_144;
/// The longest grace period a launch may ask for between SIGTERM and SIGKILL.
pub const MAX_STOP_TIMEOUT_S: u32 = 3600;
/// How long a Docker command may take beyond a stop's grace period.
const STOP_MARGIN_S: u64 = 60;

fn hash(value: &impl Serialize) -> Result<String> {
    // Convert through Value to sort all maps, including driver-specific options.
    let mut value = serde_json::to_value(value).map_err(|_| Error::InvalidContract)?;
    value.sort_all_objects();
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&value).map_err(|_| Error::InvalidContract)?,
    )))
}
fn available<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| Error::Unavailable)
}

// Keep draining the pipe so verbose containers cannot deadlock `docker logs`,
// but retain only the last 128 KiB of each stream (256 KiB total).
pub(crate) async fn log_tail(mut reader: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    const LIMIT: usize = 128 * 1024;
    let mut tail = std::collections::VecDeque::with_capacity(LIMIT);
    let mut chunk = [0; 16 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|_| Error::Unavailable)?;
        if n == 0 {
            return Ok(tail.into());
        }
        let discard = (tail.len() + n).saturating_sub(LIMIT);
        tail.drain(..discard);
        tail.extend(&chunk[..n]);
    }
}

/// Up to `limit` bytes of a command's stdout and stderr together, through
/// one pipe so that their order is kept, and whether that is all of it. A
/// command that is cut off is killed; one that ends must succeed, because its
/// own errors share the pipe and are never returned as output.
pub(crate) async fn read_output(
    mut command: tokio::process::Command,
    limit: usize,
) -> Result<(Vec<u8>, bool)> {
    use std::io::Read;
    let (mut reader, writer) = available(std::io::pipe())?;
    command
        .stdin(Stdio::null())
        .stdout(available(writer.try_clone())?)
        .stderr(writer)
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| Error::Unavailable)?;
    // Only the child may hold the pipe's write end, so the read ends with it.
    drop(command);
    let (mut bytes, complete) = tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        (&mut reader)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let complete = bytes.len() <= limit;
        Ok::<_, Error>((bytes, complete))
    })
    .await
    .map_err(|_| Error::Unavailable)??;
    if complete {
        if !child
            .wait()
            .await
            .map_err(|_| Error::Unavailable)?
            .success()
        {
            return Err(Error::Unavailable);
        }
    } else {
        let _ = child.kill().await;
        bytes.truncate(limit);
    }
    Ok((bytes, complete))
}

/// Durable single-use journal for request-bound HTTP grants, shared by the
/// Docker and native ingress paths. True only for the first unexpired use.
pub(crate) async fn consume_once(
    path: std::path::PathBuf,
    key: String,
    expires_at: u64,
) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
            let _file=available(OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(&path))?;
            let mut db=rusqlite::Connection::open(path).map_err(|_|Error::Unavailable)?;
            db.busy_timeout(Duration::from_secs(5)).map_err(|_|Error::Unavailable)?;
            db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS invocations(id TEXT PRIMARY KEY, expires INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS invocation_expiry ON invocations(expires);").map_err(|_|Error::Unavailable)?;
            let transaction=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|_|Error::Unavailable)?;
            let now=trusted_router_transport::grants::now();
            if now>=expires_at{return Err(Error::Untrusted)}
            transaction.execute("DELETE FROM invocations WHERE expires <= ?1",[now]).map_err(|_|Error::Unavailable)?;
            let inserted=transaction.execute("INSERT OR IGNORE INTO invocations(id,expires) VALUES(?1,?2)",rusqlite::params![key,expires_at]).map_err(|_|Error::Unavailable)?;
            transaction.commit().map_err(|_|Error::Unavailable)?;
            Ok(inserted==1)
        }).await.map_err(|_|Error::Unavailable)?
}

impl DockerDriver {
    pub(crate) fn claims(&self, execution: &ExecutionIdentity) -> Result<bool> {
        Ok(self.read(&self.slot(execution)?)?.is_some_and(|r| {
            r.phase != Phase::Deleted || r.execution.generation >= execution.generation
        }))
    }
    pub(crate) fn validate_launch(&self, request: &LaunchRequest) -> Result<DockerOptions> {
        self.slot(&request.execution)?;
        Self::options(request)
    }

    pub(crate) fn has_allocations(state: &Path) -> Result<bool> {
        for entry in available(fs::read_dir(state))? {
            let path = available(entry)?.path();
            let Some(slot) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if path.extension().is_some_and(|s| s == "json")
                && slot.len() == 64
                && slot.bytes().all(|b| b.is_ascii_hexdigit())
            {
                let record: Record = serde_json::from_slice(&available(fs::read(path))?)
                    .map_err(|_| Error::InvalidContract)?;
                if record.phase != Phase::Deleted {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Private durable replay ledger survives connector and shim restarts. A
    /// failed/ambiguous upstream dispatch never refunds an invocation.
    pub(crate) async fn consume_http_request(
        &self,
        execution: &ExecutionIdentity,
        service: &str,
        id: &str,
        expires_at: u64,
    ) -> Result<bool> {
        consume_once(
            self.state.join("http-invocations.sqlite"),
            hash(&(execution, service, id))?,
            expires_at,
        )
        .await
    }
    fn allocate_port(&self, execution: &ExecutionIdentity) -> Result<u16> {
        // Reserve in the durable node state before dropping the OS socket.
        // Docker receives a fixed mapping, so restarts cannot move the target.
        for _ in 0..128 {
            let socket = available(std::net::TcpListener::bind("127.0.0.1:0"))?;
            let port = available(socket.local_addr())?.port();
            let path = self.state.join(format!("port-{port}.json"));
            let mut file = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(Error::Unavailable),
            };
            available(
                file.write_all(&serde_json::to_vec(execution).map_err(|_| Error::InvalidContract)?),
            )?;
            available(file.sync_all())?;
            available(File::open(&self.state).and_then(|f| f.sync_all()))?;
            return Ok(port);
        }
        Err(Error::Unavailable)
    }
    fn release_port(&self, record: &Record) -> Result<()> {
        if !record.allocated_port {
            return Ok(());
        }
        let path = self.state.join(format!(
            "port-{}.json",
            record.port.ok_or(Error::InvalidContract)?
        ));
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Unavailable),
        };
        let owner: ExecutionIdentity =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?;
        // A repeated cleanup may observe this port already assigned elsewhere.
        // Its old container has been confirmed absent; never touch the new owner.
        if owner != record.execution {
            return Ok(());
        }
        available(fs::remove_file(path))?;
        available(File::open(&self.state).and_then(|f| f.sync_all()))
    }
    /// Node-administrator access only. All callers must validate a control grant.
    pub(crate) async fn metadata(&self, execution: &ExecutionIdentity) -> Result<Value> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let record = self.owned(&slot, execution)?;
        let container = Self::container(&slot, &record)
            .await?
            .ok_or(Error::Ownership)?;
        if Self::status(&slot, &record, Some(&container))?.state != RuntimeState::Ready {
            return Err(Error::Ownership);
        }
        Ok(
            json!({"environment":container["Config"]["Env"], "image":container["Config"]["Image"],
            "user":container["Config"]["User"], "runtime_id":Self::name(&slot)}),
        )
    }

    pub(crate) async fn execute(
        &self,
        execution: &ExecutionIdentity,
        request: crate::management::ExecRequest,
        expires_at: u64,
    ) -> Result<crate::management::ExecResponse> {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        if trusted_router_transport::grants::now() >= expires_at {
            return Err(Error::Untrusted);
        }
        let record = self.owned(&slot, execution)?;
        if Self::status(
            &slot,
            &record,
            Self::container(&slot, &record).await?.as_ref(),
        )?
        .state
            != RuntimeState::Ready
        {
            return Err(Error::Ownership);
        }
        if request.command.is_empty()
            || request.command.len() > 256
            || request
                .command
                .iter()
                .any(|s| s.contains('\0') || s.len() > 1024 * 1024)
            || request.timeout_seconds == 0
            || request.timeout_seconds > 600
            || request.user.as_ref().is_some_and(|u| {
                u.is_empty()
                    || u.len() > 128
                    || !u
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
            })
        {
            return Err(Error::InvalidContract);
        }
        let input = base64::engine::general_purpose::STANDARD
            .decode(&request.stdin)
            .map_err(|_| Error::InvalidContract)?;
        const LIMIT: usize = 64 * 1024 * 1024;
        if input.len() > LIMIT {
            return Err(Error::InvalidContract);
        }
        let mut command = tokio::process::Command::new("/usr/bin/docker");
        command
            .arg("--host=unix:///var/run/docker.sock")
            .args(["exec", "-i"]);
        if let Some(user) = &request.user {
            command.args(["--user", user]);
        }
        let mut child = command
            .args([
                "--",
                &Self::name(&slot),
                "timeout",
                "-s",
                "TERM",
                "-k",
                "5",
                &request.timeout_seconds.to_string(),
            ])
            .args(&request.command)
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_HOST")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::Unavailable)?;
        let mut stdin = child.stdin.take().ok_or(Error::Unavailable)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(Error::Unavailable)?
            .take(LIMIT as u64 + 1);
        let mut stderr = child
            .stderr
            .take()
            .ok_or(Error::Unavailable)?
            .take(LIMIT as u64 + 1);
        let operation = async {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let ((), _, _) = tokio::try_join!(
                async move {
                    stdin.write_all(&input).await?;
                    stdin.shutdown().await?;
                    drop(stdin);
                    Ok::<(), std::io::Error>(())
                },
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err)
            )
            .map_err(|_| Error::Unavailable)?;
            if out.len() + err.len() > LIMIT {
                return Err(Error::Unavailable);
            }
            let status = child.wait().await.map_err(|_| Error::Unavailable)?;
            Ok(crate::management::ExecResponse {
                stdout: base64::engine::general_purpose::STANDARD.encode(out),
                stderr: base64::engine::general_purpose::STANDARD.encode(err),
                exit_code: status.code().unwrap_or(-1),
            })
        };
        tokio::time::timeout(Duration::from_secs(request.timeout_seconds + 15), operation)
            .await
            .map_err(|_| Error::Unavailable)?
    }

    pub(crate) async fn logs(
        &self,
        execution: &ExecutionIdentity,
        tail: u32,
        expires_at: u64,
    ) -> Result<crate::management::LogsResponse> {
        use base64::Engine as _;
        let remaining = expires_at.saturating_sub(trusted_router_transport::grants::now());
        if remaining == 0 || !(1..=5000).contains(&tail) {
            return Err(Error::Untrusted);
        }
        // Bound lock acquisition, ownership checks, and the full read together.
        tokio::time::timeout(Duration::from_secs(remaining.min(15)), async {
            let slot = self.slot(execution)?;
            let _lock = self.lock(&slot).await?;
            let record = self.owned(&slot, execution)?;
            if record.phase == Phase::Deleted || Self::container(&slot, &record).await?.is_none() {
                return Err(Error::Ownership);
            }
            let mut child = tokio::process::Command::new("/usr/bin/docker")
                .arg("--host=unix:///var/run/docker.sock")
                .args([
                    "logs",
                    "--tail",
                    &tail.to_string(),
                    "--",
                    &Self::name(&slot),
                ])
                .env_remove("DOCKER_CONTEXT")
                .env_remove("DOCKER_HOST")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| Error::Unavailable)?;
            let (stdout, stderr) = tokio::try_join!(
                log_tail(child.stdout.take().ok_or(Error::Unavailable)?),
                log_tail(child.stderr.take().ok_or(Error::Unavailable)?),
            )?;
            if !child
                .wait()
                .await
                .map_err(|_| Error::Unavailable)?
                .success()
            {
                return Err(Error::Unavailable);
            }
            Ok(crate::management::LogsResponse {
                stdout: base64::engine::general_purpose::STANDARD.encode(stdout),
                stderr: base64::engine::general_purpose::STANDARD.encode(stderr),
            })
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// A bounded window of the runtime's output from `since` on, for the node
    /// adapter that launched it. Stdout and stderr come together in Docker's
    /// order, each line with its timestamp; see `log_window::window` for where
    /// the next window starts. It reads at most `log_window::LIMIT`, within 15 s.
    pub async fn read_logs(
        &self,
        execution: &ExecutionIdentity,
        since: Option<&str>,
    ) -> Result<RuntimeLogs> {
        use base64::Engine as _;
        let since = since
            .map(|s| crate::log_window::parse_since(s).ok_or(Error::InvalidContract))
            .transpose()?;
        let slot = self.slot(execution)?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let _lock = self.lock(&slot).await?;
            let record = self.owned(&slot, execution)?;
            if record.phase == Phase::Deleted || Self::container(&slot, &record).await?.is_none() {
                return Err(Error::Ownership);
            }
            let mut command = tokio::process::Command::new("/usr/bin/docker");
            command
                .arg("--host=unix:///var/run/docker.sock")
                .args(["logs", "--timestamps"]);
            if let Some(since) = since {
                command.args(["--since", &crate::log_window::since_arg(since)]);
            }
            command
                .args(["--", &Self::name(&slot)])
                .env_remove("DOCKER_CONTEXT")
                .env_remove("DOCKER_HOST");
            let (bytes, complete) = read_output(command, crate::log_window::LIMIT).await?;
            let window = crate::log_window::window(&bytes, complete, since);
            Ok(RuntimeLogs {
                output: base64::engine::general_purpose::STANDARD.encode(window.output),
                next_since: window.next.map(crate::log_window::since_arg),
                more: window.more,
            })
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    /// Stops the container within its grace period and starts it again, as
    /// `docker restart` does. The grace period runs without the slot's lock, as
    /// in `stop`; the container starts again only if the allocation is still
    /// Running and its container is the same one, so a stop or delete
    /// meanwhile stays final.
    pub(crate) async fn restart(
        &self,
        execution: &ExecutionIdentity,
        expires_at: u64,
    ) -> Result<()> {
        let slot = self.slot(execution)?;
        let (id, grace) = {
            let _lock = self.lock(&slot).await?;
            if trusted_router_transport::grants::now() >= expires_at {
                return Err(Error::Untrusted);
            }
            let record = self.owned(&slot, execution)?;
            // A run to completion is never started again.
            if record.phase != Phase::Running || record.run_to_completion {
                return Err(Error::Ownership);
            }
            let container = Self::container(&slot, &record)
                .await?
                .ok_or(Error::Ownership)?;
            (Self::id(&container)?, record.stop_timeout_s)
        };
        Self::stop_container(&id, grace).await?;
        let _lock = self.lock(&slot).await?;
        let record = self.owned(&slot, execution)?;
        let container = Self::container(&slot, &record)
            .await?
            .ok_or(Error::Ownership)?;
        if record.phase != Phase::Running || container["Id"] != id.as_str() {
            return Err(Error::Ownership);
        }
        // Re-checks the committed limits before anything is started again.
        Self::status(&slot, &record, Some(&container))?;
        Self::docker(&["start".into(), id]).await?;
        Ok(())
    }

    /// Starts this allocation's own exited container again, in place. Fleet,
    /// as the supervisor, decides when; the shim never does it on its own and a
    /// lost connection still never restarts anything. The container keeps its
    /// committed configuration, limits and writable layer, so this is not a
    /// replay of the launch: nothing is created or resubmitted. Only a
    /// `Running` allocation qualifies -- stop/delete fences stay final -- a
    /// running container is left as it is, and a missing one is never
    /// substituted.
    pub async fn resume(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let (record, container) = self.resumable(&slot, execution).await?;
        // Re-checks the committed limits before anything is started again.
        if Self::status(&slot, &record, Some(&container))?.state == RuntimeState::Stopped {
            Self::docker(&["start".into(), Self::name(&slot)]).await?;
        }
        Self::status(
            &slot,
            &record,
            Self::container(&slot, &record).await?.as_ref(),
        )
    }

    /// What `resume` would do, without doing it: `None` when it would start the
    /// exited container, otherwise the status it would leave unchanged. It
    /// applies the same checks, so a TEE resume admits only what `resume` starts.
    pub(crate) async fn resume_status(
        &self,
        execution: &ExecutionIdentity,
    ) -> Result<Option<RuntimeStatus>> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let (record, container) = self.resumable(&slot, execution).await?;
        let status = Self::status(&slot, &record, Some(&container))?;
        Ok((status.state != RuntimeState::Stopped).then_some(status))
    }

    /// A Running allocation's own record and existing container. Called with
    /// the slot's lock held.
    async fn resumable(
        &self,
        slot: &str,
        execution: &ExecutionIdentity,
    ) -> Result<(Record, Value)> {
        let record = self.owned(slot, execution)?;
        // A run to completion ends when its process does; a retry is a new
        // execution.
        if record.phase != Phase::Running || record.run_to_completion {
            return Err(Error::Ownership);
        }
        let container = Self::container(slot, &record)
            .await?
            .ok_or(Error::Ownership)?;
        Ok((record, container))
    }

    fn network_paths(&self, execution: &ExecutionIdentity) -> Result<(PathBuf, PathBuf)> {
        self.slot(execution)?;
        let id = hash(execution)?;
        Ok((
            self.state.join(format!("{id}.network.lock")),
            self.state.join(format!("{id}.network.closed")),
        ))
    }

    /// Hold the connector's lock until every stream is joined. Cleanup first
    /// writes its permanent fence, then waits for this lock before port reuse.
    pub async fn network_lease(
        &self,
        execution: &ExecutionIdentity,
    ) -> Result<crate::data_plane::NetworkLease> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let record = self.owned(&slot, execution)?;
        if record.services.is_empty()
            || Self::status(
                &slot,
                &record,
                Self::container(&slot, &record).await?.as_ref(),
            )?
            .state
                != RuntimeState::Ready
        {
            return Err(Error::Ownership);
        }
        let (path, closed) = self.network_paths(execution)?;
        let file = available(
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path),
        )?;
        file.try_lock_exclusive().map_err(|_| Error::Ownership)?;
        if closed.try_exists().map_err(|_| Error::Unavailable)? {
            return Err(Error::Ownership);
        }
        Ok(crate::data_plane::NetworkLease {
            fence: crate::data_plane::NetworkFence {
                _file: file,
                closed,
            },
            services: record.services,
            ingress: record.ingress,
            target: std::net::SocketAddr::from((
                [127, 0, 0, 1],
                record.port.ok_or(Error::InvalidContract)?,
            )),
        })
    }

    async fn drain_network(&self, execution: &ExecutionIdentity) -> Result<File> {
        let (path, closed) = self.network_paths(execution)?;
        let tombstone = available(
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(closed),
        )?;
        available(tombstone.sync_all())?;
        available(File::open(&self.state).and_then(|f| f.sync_all()))?;
        let file = available(
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path),
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(_) => return Err(Error::Unavailable),
            }
        }
    }

    pub fn new(state: impl Into<PathBuf>, node_id: String) -> Result<Self> {
        let state = state.into();
        if !state.is_absolute() || node_id.is_empty() {
            return Err(Error::InvalidContract);
        }
        available(
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&state),
        )?;
        if available(fs::metadata(&state))?.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidContract);
        }
        Ok(Self { state, node_id })
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
            .any(|s| s.is_empty() || s.len() > 256 || s.contains('\0'))
        {
            return Err(Error::InvalidContract);
        }
        hash(&(&e.namespace, &e.workload, &e.allocation_id, &e.node_id))
    }

    async fn lock(&self, slot: &str) -> Result<File> {
        let path = self.state.join(format!("{slot}.lock"));
        tokio::task::spawn_blocking(move || {
            let file = available(
                OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .read(true)
                    .write(true)
                    .mode(0o600)
                    .open(path),
            )?;
            available(file.lock_exclusive())?;
            Ok(file)
        })
        .await
        .map_err(|_| Error::Unavailable)?
    }

    fn read(&self, slot: &str) -> Result<Option<Record>> {
        match fs::read(self.state.join(format!("{slot}.json"))) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| Error::InvalidContract),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::Unavailable),
        }
    }

    fn save(&self, slot: &str, record: &Record) -> Result<()> {
        let mut temp = available(tempfile::NamedTempFile::new_in(&self.state))?;
        available(
            temp.write_all(&serde_json::to_vec(record).map_err(|_| Error::InvalidContract)?),
        )?;
        available(temp.as_file().sync_all())?;
        temp.persist(self.state.join(format!("{slot}.json")))
            .map_err(|_| Error::Unavailable)?;
        available(File::open(&self.state).and_then(|f| f.sync_all()))
    }

    fn owned(&self, slot: &str, e: &ExecutionIdentity) -> Result<Record> {
        let record = self.read(slot)?.ok_or(Error::Ownership)?;
        if &record.execution != e {
            return Err(Error::Ownership);
        }
        Ok(record)
    }

    async fn docker(args: &[String]) -> Result<Vec<u8>> {
        Self::docker_within(args, Duration::from_secs(120)).await
    }

    async fn docker_within(args: &[String], timeout: Duration) -> Result<Vec<u8>> {
        // Pin the local daemon. Agent environment cannot redirect DOCKER_HOST or
        // select another context. Never print argv, env or Docker's error body.
        let mut command = tokio::process::Command::new("/usr/bin/docker");
        command
            .arg("--host=unix:///var/run/docker.sock")
            .args(args)
            .env_remove("DOCKER_CONTEXT")
            .env_remove("DOCKER_HOST")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        if !output.status.success() {
            return Err(Error::Unavailable);
        }
        Ok(output.stdout)
    }

    fn name(slot: &str) -> String {
        format!("trusted-shim-{slot}")
    }

    /// The container's full id. Unlike its name, it never refers to a later
    /// generation's container, so it is safe to use without the slot's lock.
    fn id(container: &Value) -> Result<String> {
        container["Id"]
            .as_str()
            .filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_owned)
            .ok_or(Error::Unavailable)
    }

    /// SIGTERM, then SIGKILL `grace` seconds later. Callers do not hold the
    /// slot's lock, so `inspect` and other allocations stay responsive during
    /// a long grace period.
    async fn stop_container(id: &str, grace: u32) -> Result<Vec<u8>> {
        Self::docker_within(
            &["stop".into(), "--time".into(), grace.to_string(), id.into()],
            Duration::from_secs(u64::from(grace) + STOP_MARGIN_S),
        )
        .await
    }

    async fn container(slot: &str, record: &Record) -> Result<Option<Value>> {
        let name = Self::name(slot);
        // `inspect` alone cannot distinguish a missing container from an offline
        // daemon. A successful list is required before confirming absence.
        let ids = Self::docker(&[
            "ps".into(),
            "-aq".into(),
            "--no-trunc".into(),
            "--filter".into(),
            format!("name=^/{name}$"),
        ])
        .await?;
        if ids.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let bytes = Self::docker(&["inspect".into(), name]).await?;
        let values: Vec<Value> = serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)?;
        let value = values.into_iter().next().ok_or(Error::Unavailable)?;
        if value["Config"]["Labels"]["trusted-shim.execution"] != hash(&record.execution)?
            || value["Config"]["Labels"]["trusted-shim.request"] != record.request_sha256
        {
            return Err(Error::Ownership);
        }
        Ok(Some(value))
    }

    fn status(slot: &str, r: &Record, container: Option<&Value>) -> Result<RuntimeStatus> {
        let effective_limits = if let Some(v) = container {
            if v["HostConfig"]["NanoCpus"].as_u64()
                != Some(r.limits.cpu_millicores.unwrap_or(0) * 1_000_000)
                || r.limits
                    .memory_bytes
                    .is_some_and(|bytes| v["HostConfig"]["MemorySwap"].as_u64() != Some(bytes))
                // Docker reports 0 when no weight was requested, and the
                // daemon's default of 1024 applies.
                || v["HostConfig"]["CpuShares"].as_u64() != Some(r.limits.cpu_shares.unwrap_or(0))
            {
                return Err(Error::Untrusted);
            }
            ResourceLimits {
                cpu_millicores: v["HostConfig"]["NanoCpus"]
                    .as_u64()
                    .filter(|v| *v > 0)
                    .map(|v| v / 1_000_000),
                memory_bytes: v["HostConfig"]["Memory"].as_u64().filter(|v| *v > 0),
                cpu_shares: v["HostConfig"]["CpuShares"].as_u64().filter(|v| *v > 0),
            }
        } else {
            r.limits.clone()
        };
        // A chosen network is part of the committed launch, like its limits.
        if let (Some(v), Some(network)) = (container, r.network) {
            if v["HostConfig"]["NetworkMode"] != network.docker() {
                return Err(Error::Untrusted);
            }
        }
        if container.is_some() && effective_limits != r.limits {
            return Err(Error::Untrusted);
        }
        let mut state = match container.and_then(|v| v["State"]["Status"].as_str()) {
            Some("running") => RuntimeState::Ready,
            Some("created") => RuntimeState::Starting,
            Some("exited" | "dead") => RuntimeState::Stopped,
            None if r.phase == Phase::Deleted => RuntimeState::Stopped,
            _ => RuntimeState::Failed,
        };
        if matches!(r.phase, Phase::Stopped | Phase::Deleted) && state == RuntimeState::Ready {
            state = RuntimeState::Stopping;
        }
        let exit = container
            .filter(|_| state == RuntimeState::Stopped)
            .and_then(Self::exit);
        Ok(RuntimeStatus {
            execution: r.execution.clone(),
            runtime_id: Self::name(slot),
            state,
            effective_limits,
            port: r.port,
            exit,
        })
    }

    /// An exited container's exit status, from `docker inspect`.
    fn exit(container: &Value) -> Option<ExitStatus> {
        let state = &container["State"];
        Some(ExitStatus {
            code: state["ExitCode"].as_i64()?,
            oom_killed: state["OOMKilled"].as_bool()?,
            started_at: state["StartedAt"].as_str()?.to_owned(),
            finished_at: state["FinishedAt"].as_str()?.to_owned(),
        })
    }

    fn options(request: &LaunchRequest) -> Result<DockerOptions> {
        crate::access::driver_bounds(request)?;
        if request.driver != "docker"
            || request.trust.attestation != AttestationRequirement::SkipNonTee
            || request.trust.attestation_proof != ProofRequirement::NotRequired
            || request.trust.policy_proof != ProofRequirement::NotRequired
        {
            return Err(Error::Unsupported);
        }
        if request.image.is_empty()
            || request.image.starts_with('-')
            || request.image.contains('\0')
            || request
                .limits
                .cpu_millicores
                .is_some_and(|v| v == 0 || v > i64::MAX as u64 / 1_000_000)
            || request
                .limits
                .memory_bytes
                .is_some_and(|v| v < 6 * 1024 * 1024 || v > i64::MAX as u64)
            // Docker would clamp an out-of-range weight instead of refusing it.
            || request
                .limits
                .cpu_shares
                .is_some_and(|v| !CPU_SHARES.contains(&v))
            || request.command.iter().any(|s| s.contains('\0'))
            || request.environment.iter().any(|(k, v)| {
                k.is_empty() || k.contains(['=', '\0']) || v.contains(['\0', '\n', '\r'])
            })
        {
            return Err(Error::InvalidContract);
        }
        // Native OpenShell attachments; this path keeps its own driver_options
        // gpus/volumes. Never silently ignore an allocation's devices or storage.
        if !request.gpus.is_empty() || !request.mounts.is_empty() {
            return Err(Error::Unsupported);
        }
        let options: DockerOptions = serde_json::from_value(if request.driver_options.is_null() {
            json!({})
        } else {
            request.driver_options.clone()
        })
        .map_err(|_| Error::InvalidContract)?;
        if options.port == Some(0) && options.container_port.is_none()
            || options.container_port == Some(0)
            || options.container_port.is_some() && options.port.is_none()
            || options
                .entrypoint
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.contains('\0'))
            || options
                .stop_timeout_s
                .is_some_and(|n| n > MAX_STOP_TIMEOUT_S)
            || options.gpus.iter().any(|id| {
                id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || options
                .user
                .iter()
                .chain(options.workdir.iter())
                .chain(options.volumes.iter())
                .any(|s| s.contains('\0'))
            || options
                .volumes
                .iter()
                .any(|s| !s.starts_with('/') || !s.contains(":"))
        {
            return Err(Error::InvalidContract);
        }
        match options.network {
            // Nothing can reach a container without a network.
            Some(NetworkMode::None)
                if options.port.is_some()
                    || options.container_port.is_some()
                    || !options.ingress.is_empty()
                    || !request.services.is_empty() =>
            {
                return Err(Error::InvalidContract)
            }
            // There is no mapping: the container listens on `port` itself, so
            // the port can't be chosen for it.
            Some(NetworkMode::Host)
                if options.container_port.is_some() || options.port == Some(0) =>
            {
                return Err(Error::InvalidContract)
            }
            _ => {}
        }
        // A run to completion is reached by nothing: it ends on its own.
        if options.run_to_completion
            && (options.port.is_some()
                || options.container_port.is_some()
                || !options.ingress.is_empty()
                || !request.services.is_empty())
        {
            return Err(Error::InvalidContract);
        }
        let mut names = std::collections::HashSet::new();
        for service in &request.services {
            if service.id.namespace != request.execution.namespace
                || service.id.workload != request.execution.workload
                || service.id.service.is_empty()
                || service.id.service.len() > 64
                || !service
                    .id
                    .service
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !names.insert(&service.id.service)
                || !(service.endpoint_ref == "app" && service.id.service != "control"
                    || service.endpoint_ref == "control" && service.id.service == "control"
                    || service.endpoint_ref == format!("ingress:{}", service.id.service)
                        && service.id.service != "control"
                        && options.ingress.contains_key(&service.id.service))
                || options.port.is_none()
                || !matches!(
                    service.protocol,
                    trusted_data_router::Protocol::Http1
                        | trusted_data_router::Protocol::WebSocket
                        | trusted_data_router::Protocol::Tcp
                )
            {
                return Err(Error::Unsupported);
            }
        }
        for ingress in options.ingress.values() {
            ingress.validate()?;
            if let Some(env) = &ingress.bearer_env {
                if !request.environment.get(env).is_some_and(|v| !v.is_empty()) {
                    return Err(Error::InvalidContract);
                }
            }
        }
        Ok(options)
    }

    fn create_args(
        slot: &str,
        r: &Record,
        request: &LaunchRequest,
        options: &DockerOptions,
    ) -> Vec<String> {
        let mut args = vec![
            "create".into(),
            "--name".into(),
            Self::name(slot),
            "--restart=no".into(),
            "--pull=never".into(),
            "--label".into(),
            format!(
                "trusted-shim.execution={}",
                hash(&r.execution).expect("serializable identity")
            ),
            "--label".into(),
            format!("trusted-shim.request={}", r.request_sha256),
        ];
        if let Some(cpu) = request.limits.cpu_millicores {
            args.extend(["--cpus".into(), format!("{}.{:03}", cpu / 1000, cpu % 1000)]);
        }
        if let Some(bytes) = request.limits.memory_bytes {
            args.extend([
                "--memory".into(),
                bytes.to_string(),
                "--memory-swap".into(),
                bytes.to_string(),
            ]);
        }
        if let Some(shares) = request.limits.cpu_shares {
            args.extend(["--cpu-shares".into(), shares.to_string()]);
        }
        if let Some(bytes) = options.shm_bytes {
            args.extend(["--shm-size".into(), bytes.to_string()]);
        }
        if let Some(network) = options.network {
            args.push(format!("--network={}", network.docker()));
        }
        if let Some(port) = r.port.filter(|_| options.network.is_none()) {
            args.extend([
                "--publish".into(),
                format!(
                    "127.0.0.1:{port}:{}",
                    options.container_port.unwrap_or(port)
                ),
            ]);
        }
        if let Some(entrypoint) = &options.entrypoint {
            args.extend(["--entrypoint".into(), entrypoint.clone()]);
        }
        if let Some(user) = &options.user {
            args.extend(["--user".into(), user.clone()]);
        }
        if let Some(dir) = &options.workdir {
            args.extend(["--workdir".into(), dir.clone()]);
        }
        if !options.gpus.is_empty() {
            args.extend([
                "--gpus".into(),
                format!("\"device={}\"", options.gpus.join(",")),
            ]);
        }
        for v in &options.volumes {
            args.extend(["--volume".into(), v.clone()]);
        }
        args.extend(["--".into(), request.image.clone()]);
        args.extend(request.command.clone());
        args
    }
}

#[async_trait]
impl RuntimeDriver for DockerDriver {
    async fn launch(&self, request: &LaunchRequest) -> Result<RuntimeStatus> {
        let options = Self::options(request)?;
        let slot = self.slot(&request.execution)?;
        let _lock = self.lock(&slot).await?;
        let digest = hash(request)?;
        let previous = self.read(&slot)?;
        let mut record = match previous {
            Some(r) if r.execution == request.execution => {
                if r.request_sha256 != digest || matches!(r.phase, Phase::Deleted | Phase::Stopped)
                {
                    return Err(Error::Ownership);
                }
                r
            }
            prior => {
                if let Some(old) = prior {
                    if old.phase != Phase::Deleted
                        || request.execution.generation <= old.execution.generation
                        || Self::container(&slot, &old).await?.is_some()
                    {
                        return Err(Error::Ownership);
                    }
                }
                let r = Record {
                    execution: request.execution.clone(),
                    request_sha256: digest,
                    limits: request.limits.clone(),
                    phase: Phase::Creating,
                    stop_timeout_s: options.stop_timeout_s.unwrap_or(30),
                    port: if options.port == Some(0) {
                        Some(self.allocate_port(&request.execution)?)
                    } else {
                        options.port
                    },
                    allocated_port: options.port == Some(0),
                    services: request.services.clone(),
                    ingress: options.ingress.clone(),
                    network: options.network,
                    run_to_completion: options.run_to_completion,
                };
                self.save(&slot, &r)?;
                r
            }
        };
        let mut container = Self::container(&slot, &record).await?;
        let mut may_start = false;
        if record.phase == Phase::Creating {
            let info: Value = serde_json::from_slice(
                &Self::docker(&["info".into(), "--format".into(), "{{json .}}".into()]).await?,
            )
            .map_err(|_| Error::Unavailable)?;
            if info["OSType"] != "linux"
                || request.limits.cpu_millicores.is_some()
                    && (info["CpuCfsQuota"] != true || info["CpuCfsPeriod"] != true)
                || request.limits.memory_bytes.is_some()
                    && (info["MemoryLimit"] != true || info["SwapLimit"] != true)
                || request.limits.cpu_shares.is_some() && info["CPUShares"] != true
            {
                return Err(Error::Unsupported);
            }
            if container.is_none() {
                let mut env_file = available(tempfile::NamedTempFile::new_in(&self.state))?;
                for (key, value) in &request.environment {
                    available(writeln!(env_file, "{key}={value}"))?;
                }
                available(env_file.flush())?;
                let mut args = Self::create_args(&slot, &record, request, &options);
                args.splice(
                    1..1,
                    [
                        "--env-file".into(),
                        env_file.path().to_string_lossy().into_owned(),
                    ],
                );
                Self::docker(&args).await?;
                container = Self::container(&slot, &record).await?;
            }
            if container
                .as_ref()
                .and_then(|v| v["State"]["Status"].as_str())
                != Some("created")
            {
                return Err(Error::Untrusted);
            }
            // Confirm effective hard limits before starting any code.
            Self::status(&slot, &record, container.as_ref())?;
            record.phase = Phase::Starting;
            self.save(&slot, &record)?;
            may_start = true;
        }
        // A recovered starting intent may already have dispatched Docker start.
        // Never resend it against a created container: an orphaned first call
        // could otherwise start it again after a short-lived execution exits.
        if record.phase == Phase::Starting {
            match container
                .as_ref()
                .and_then(|v| v["State"]["Status"].as_str())
            {
                Some("created") if may_start => {
                    Self::docker(&["start".into(), Self::name(&slot)]).await?;
                }
                Some("running" | "exited" | "dead") => {}
                _ => return Err(Error::Untrusted),
            }
            record.phase = Phase::Running;
            self.save(&slot, &record)?;
            container = Self::container(&slot, &record).await?;
        }
        // A terminated/missing started container is never automatically replayed.
        Self::status(&slot, &record, container.as_ref())
    }

    async fn inspect(&self, execution: &ExecutionIdentity) -> Result<RuntimeStatus> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let r = self.owned(&slot, execution)?;
        Self::status(&slot, &r, Self::container(&slot, &r).await?.as_ref())
    }

    async fn stop(&self, execution: &ExecutionIdentity) -> Result<()> {
        let slot = self.slot(execution)?;
        // Fence the allocation first, so nothing starts it again, then wait
        // out the grace period without the slot's lock.
        let (id, grace) = {
            let _lock = self.lock(&slot).await?;
            let mut r = self.owned(&slot, execution)?;
            drop(self.drain_network(execution).await?);
            if r.phase != Phase::Deleted {
                r.phase = Phase::Stopped;
                self.save(&slot, &r)?;
            }
            match Self::container(&slot, &r).await? {
                Some(v) if v["State"]["Running"] == true => (Self::id(&v)?, r.stop_timeout_s),
                _ => return Ok(()),
            }
        };
        let stopped = Self::stop_container(&id, grace).await;
        let _lock = self.lock(&slot).await?;
        let running = match self.read(&slot)? {
            Some(r) if &r.execution == execution => Self::container(&slot, &r)
                .await?
                .is_some_and(|v| v["Id"] == id.as_str() && v["State"]["Running"] == true),
            // A later generation owns the slot only after this allocation's
            // container was confirmed gone.
            _ => false,
        };
        if running {
            return Err(stopped.err().unwrap_or(Error::Unavailable));
        }
        Ok(())
    }

    async fn delete(&self, execution: &ExecutionIdentity) -> Result<()> {
        let slot = self.slot(execution)?;
        let mut _lock = self.lock(&slot).await?;
        let mut r = match self.read(&slot)? {
            Some(r) if &r.execution == execution => r,
            Some(_) => return Err(Error::Ownership),
            None => Record {
                execution: execution.clone(),
                request_sha256: String::new(),
                limits: ResourceLimits {
                    cpu_millicores: None,
                    memory_bytes: None,
                    cpu_shares: None,
                },
                phase: Phase::Deleted,
                stop_timeout_s: 30,
                port: None,
                allocated_port: false,
                services: Vec::new(),
                ingress: Default::default(),
                network: None,
                run_to_completion: false,
            },
        };
        drop(self.drain_network(execution).await?);
        // Fence even a launch that has not reached this machine yet.
        r.phase = Phase::Deleted;
        self.save(&slot, &r)?;
        if let Some(container) = Self::container(&slot, &r).await? {
            if container["State"]["Running"] == true {
                // As in `stop`, the grace period runs without the slot's lock.
                // Its outcome doesn't matter: the removal below kills what is left.
                let id = Self::id(&container)?;
                drop(_lock);
                let _ = Self::stop_container(&id, r.stop_timeout_s).await;
                _lock = self.lock(&slot).await?;
                r = match self.read(&slot)? {
                    Some(r) if &r.execution == execution => r,
                    // A later generation owns the slot only after this
                    // allocation's container was confirmed gone.
                    _ => return Ok(()),
                };
            }
            if Self::container(&slot, &r).await?.is_some() {
                Self::docker(&["rm".into(), "--force".into(), Self::name(&slot)]).await?;
            }
        }
        if Self::container(&slot, &r).await?.is_some() {
            return Err(Error::Unavailable);
        }
        self.release_port(&r)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(limits: Value) -> LaunchRequest {
        serde_json::from_value(json!({
            "execution": {"namespace":"test", "workload":"docker", "allocation_id":"unit",
                "lease_id":"one", "generation":1, "node_id":"test-node"},
            "driver":"docker", "image":"alpine:3.21", "command":["sleep","300"],
            "environment":{}, "limits":limits,
            "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
            "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required",
                "attestation_proof":"not_required"},
            "services":[], "driver_options":{"stop_timeout_s":1}
        }))
        .unwrap()
    }

    fn record(request: &LaunchRequest) -> Record {
        Record {
            execution: request.execution.clone(),
            request_sha256: hash(request).unwrap(),
            limits: request.limits.clone(),
            phase: Phase::Running,
            stop_timeout_s: 1,
            port: None,
            allocated_port: false,
            services: Vec::new(),
            ingress: Default::default(),
            network: None,
            run_to_completion: false,
        }
    }

    /// The digest in the journal and the `trusted-shim.request` label. A launch
    /// replays only while it is unchanged.
    #[test]
    fn replay_identity_of_an_unchanged_request_is_stable() {
        let r = request(json!({"cpu_millicores":250,"memory_bytes":33554432}));
        assert_eq!(
            hash(&r).unwrap(),
            "dd4e15c723fe2f6c7d1ea97a7df6244b273aab7a5122ed5588f1557ec04f389d"
        );
        let journal = serde_json::to_vec(&record(&r)).unwrap();
        let value: Value = serde_json::from_slice(&journal).unwrap();
        assert_eq!(
            value["limits"],
            json!({"cpu_millicores":250,"memory_bytes":33554432})
        );
        let loaded: Record = serde_json::from_slice(&journal).unwrap();
        assert_eq!(serde_json::to_vec(&loaded).unwrap(), journal);
    }

    /// Inspect output for a container created with the committed CPU and
    /// memory limits and the given `HostConfig.CpuShares`.
    fn container(cpu_shares: Value) -> Value {
        json!({"State":{"Status":"running"},"HostConfig":{"NanoCpus":250_000_000u64,
            "Memory":33_554_432u64,"MemorySwap":33_554_432u64,"CpuShares":cpu_shares}})
    }

    #[test]
    fn cpu_shares_are_bounded_passed_to_docker_and_verified() {
        fn limits(shares: Value) -> Value {
            json!({"cpu_millicores":250, "memory_bytes":33554432, "cpu_shares":shares})
        }
        let absent = request(json!({"cpu_millicores":250,"memory_bytes":33554432}));
        let null = request(limits(Value::Null));
        assert_eq!(hash(&null).unwrap(), hash(&absent).unwrap());
        let weighted = request(limits(json!(64)));
        assert_ne!(hash(&weighted).unwrap(), hash(&absent).unwrap());
        assert_eq!(
            serde_json::to_value(&weighted).unwrap()["limits"],
            limits(json!(64))
        );

        for invalid in [0, 1, 262_145, u64::MAX] {
            assert!(matches!(
                DockerDriver::options(&request(limits(json!(invalid)))),
                Err(Error::InvalidContract)
            ));
        }
        for valid in [2, 64, 1024, 262_144] {
            DockerDriver::options(&request(limits(json!(valid)))).unwrap();
        }

        let args = |r: &LaunchRequest| {
            DockerDriver::create_args("slot", &record(r), r, &DockerDriver::options(r).unwrap())
        };
        let weighted_args = args(&weighted);
        let flag = weighted_args
            .iter()
            .position(|a| a == "--cpu-shares")
            .unwrap();
        assert_eq!(weighted_args[flag + 1], "64");
        assert!(flag < weighted_args.iter().position(|a| a == "--").unwrap());
        assert!(!args(&absent).iter().any(|a| a.starts_with("--cpu-shares")));

        // Unset, Docker reports 0 and applies its default weight.
        let status = DockerDriver::status("slot", &record(&absent), Some(&container(json!(0))));
        assert_eq!(status.unwrap().effective_limits, absent.limits);
        let status = DockerDriver::status("slot", &record(&weighted), Some(&container(json!(64))));
        assert_eq!(status.unwrap().effective_limits.cpu_shares, Some(64));
        // Any other reported weight, the explicit default included, is not the
        // committed launch and is refused like a changed CPU or memory limit.
        for (r, reported) in [
            (&absent, json!(1024)),
            (&absent, json!(64)),
            (&absent, Value::Null),
            (&weighted, json!(0)),
            (&weighted, json!(1024)),
            (&weighted, Value::Null),
        ] {
            assert!(matches!(
                DockerDriver::status("slot", &record(r), Some(&container(reported))),
                Err(Error::Untrusted)
            ));
        }
    }
}

#[cfg(test)]
mod stop_timeout_tests {
    use super::*;

    fn request(driver_options: Value) -> LaunchRequest {
        serde_json::from_value(json!({
            "execution": {"namespace":"test", "workload":"docker", "allocation_id":"unit",
                "lease_id":"one", "generation":1, "node_id":"test-node"},
            "driver":"docker", "image":"alpine:3.21", "command":["sleep","300"],
            "environment":{}, "limits":{"cpu_millicores":250,"memory_bytes":33554432},
            "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
            "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required",
                "attestation_proof":"not_required"},
            "services":[], "driver_options":driver_options
        }))
        .unwrap()
    }

    #[test]
    fn a_grace_period_may_be_up_to_an_hour() {
        for accepted in [0, 1, 90, 91, 600, MAX_STOP_TIMEOUT_S] {
            let options =
                DockerDriver::options(&request(json!({"stop_timeout_s": accepted}))).unwrap();
            assert_eq!(options.stop_timeout_s, Some(accepted));
        }
        assert!(matches!(
            DockerDriver::options(&request(json!({"stop_timeout_s": MAX_STOP_TIMEOUT_S + 1}))),
            Err(Error::InvalidContract)
        ));
        assert_eq!(
            DockerDriver::options(&request(json!({})))
                .unwrap()
                .stop_timeout_s,
            None
        );
    }

    #[test]
    fn only_a_full_container_id_is_used_without_the_lock() {
        let id = "ab".repeat(32);
        assert_eq!(DockerDriver::id(&json!({"Id": id})).unwrap(), id);
        for invalid in [
            json!({}),
            json!({"Id": null}),
            json!({"Id": "abc"}),
            json!({"Id": "trusted-shim-slot"}),
            json!({"Id": format!("{}zz", "ab".repeat(31))}),
            json!({"Id": format!("{id}0")}),
        ] {
            assert!(matches!(
                DockerDriver::id(&invalid),
                Err(Error::Unavailable)
            ));
        }
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;

    fn request(driver_options: Value, services: Value) -> LaunchRequest {
        serde_json::from_value(json!({
            "execution": {"namespace":"test", "workload":"docker", "allocation_id":"unit",
                "lease_id":"one", "generation":1, "node_id":"test-node"},
            "driver":"docker", "image":"alpine:3.21", "command":["sleep","300"],
            "environment":{}, "limits":{"cpu_millicores":250,"memory_bytes":33554432},
            "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
            "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required",
                "attestation_proof":"not_required"},
            "services":services, "driver_options":driver_options
        }))
        .unwrap()
    }

    fn app() -> Value {
        json!([{"id":{"namespace":"test","workload":"docker","service":"app"},
            "endpoint_ref":"app","protocol":"http1"}])
    }

    fn record(request: &LaunchRequest, options: &DockerOptions) -> Record {
        Record {
            execution: request.execution.clone(),
            request_sha256: hash(request).unwrap(),
            limits: request.limits.clone(),
            phase: Phase::Running,
            stop_timeout_s: 1,
            port: options.port,
            allocated_port: false,
            services: request.services.clone(),
            ingress: options.ingress.clone(),
            network: options.network,
            run_to_completion: options.run_to_completion,
        }
    }

    fn args(request: &LaunchRequest) -> Vec<String> {
        let options = DockerDriver::options(request).unwrap();
        DockerDriver::create_args("slot", &record(request, &options), request, &options)
    }

    #[test]
    fn a_network_without_a_surface_is_none_and_one_listening_itself_is_host() {
        for valid in [
            // Null is unset, as for the other options: Docker's default network.
            request(json!({"network":null}), json!([])),
            request(json!({"network":"none"}), json!([])),
            request(json!({"network":"host"}), json!([])),
            request(json!({"network":"host","port":8080}), app()),
        ] {
            DockerDriver::options(&valid).unwrap();
        }
        for (case, invalid) in [
            // Nothing can reach a container without a network.
            request(json!({"network":"none","port":8080}), json!([])),
            request(
                json!({"network":"none","port":0,"container_port":8080}),
                json!([]),
            ),
            request(json!({"network":"none"}), app()),
            // On the host's network the container listens on the port itself.
            request(
                json!({"network":"host","port":8080,"container_port":80}),
                app(),
            ),
            request(
                json!({"network":"host","port":0,"container_port":8080}),
                app(),
            ),
            // Only the two named networks.
            request(json!({"network":"bridge"}), json!([])),
            request(json!({"network":"container:other"}), json!([])),
        ]
        .iter()
        .enumerate()
        {
            assert!(
                matches!(DockerDriver::options(invalid), Err(Error::InvalidContract)),
                "case {case}"
            );
        }
    }

    #[test]
    fn the_network_reaches_docker_and_only_the_default_one_publishes_a_port() {
        let none = args(&request(json!({"network":"none"}), json!([])));
        assert!(none.contains(&"--network=none".into()));
        assert!(!none.iter().any(|a| a == "--publish"));

        let host = args(&request(json!({"network":"host","port":8080}), app()));
        assert!(host.contains(&"--network=host".into()));
        assert!(!host.iter().any(|a| a == "--publish"));
        let end = host.iter().position(|a| a == "--").unwrap();
        assert!(host.iter().position(|a| a == "--network=host").unwrap() < end);

        let default = args(&request(json!({"port":8080}), app()));
        assert!(!default.iter().any(|a| a.starts_with("--network")));
        let publish = default.iter().position(|a| a == "--publish").unwrap();
        assert_eq!(default[publish + 1], "127.0.0.1:8080:8080");
    }

    #[test]
    fn a_chosen_network_is_verified_and_the_default_one_keeps_its_journal() {
        let container = |mode: Value| {
            json!({"State":{"Status":"running"},"HostConfig":{"NanoCpus":250_000_000u64,
                "Memory":33_554_432u64,"MemorySwap":33_554_432u64,"CpuShares":0,"NetworkMode":mode}})
        };
        let none = request(json!({"network":"none"}), json!([]));
        let none = record(&none, &DockerDriver::options(&none).unwrap());
        DockerDriver::status("slot", &none, Some(&container(json!("none")))).unwrap();
        for changed in [
            json!("bridge"),
            json!("host"),
            json!("default"),
            Value::Null,
        ] {
            assert!(matches!(
                DockerDriver::status("slot", &none, Some(&container(changed))),
                Err(Error::Untrusted)
            ));
        }

        // Docker reports the default network as `bridge` or `default`; an
        // existing allocation is not checked against either.
        let default = request(json!({}), json!([]));
        let default = record(&default, &DockerDriver::options(&default).unwrap());
        for mode in [json!("bridge"), json!("default")] {
            DockerDriver::status("slot", &default, Some(&container(mode))).unwrap();
        }
        let journal = serde_json::to_value(&default).unwrap();
        assert!(journal.get("network").is_none());
        assert_eq!(serde_json::to_value(&none).unwrap()["network"], "none");
    }
}

#[cfg(test)]
mod completion_tests {
    use super::*;

    fn request(driver_options: Value, services: Value) -> LaunchRequest {
        serde_json::from_value(json!({
            "execution": {"namespace":"test", "workload":"docker", "allocation_id":"unit",
                "lease_id":"one", "generation":1, "node_id":"test-node"},
            "driver":"docker", "image":"alpine:3.21", "command":["true"],
            "environment":{}, "limits":{"cpu_millicores":250,"memory_bytes":33554432},
            "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
            "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required",
                "attestation_proof":"not_required"},
            "services":services, "driver_options":driver_options
        }))
        .unwrap()
    }

    fn record(run_to_completion: bool) -> Record {
        let r = request(json!({}), json!([]));
        Record {
            execution: r.execution.clone(),
            request_sha256: hash(&r).unwrap(),
            limits: r.limits.clone(),
            phase: Phase::Running,
            stop_timeout_s: 1,
            port: None,
            allocated_port: false,
            services: Vec::new(),
            ingress: Default::default(),
            network: None,
            run_to_completion,
        }
    }

    fn container(state: Value) -> Value {
        json!({"State":state,"HostConfig":{"NanoCpus":250_000_000u64,
            "Memory":33_554_432u64,"MemorySwap":33_554_432u64,"CpuShares":0}})
    }

    /// `restart` refuses it from the journal, before Docker is asked anything.
    #[tokio::test]
    async fn a_run_to_completion_is_never_restarted() {
        let dir = tempfile::tempdir().unwrap();
        let driver = DockerDriver::new(dir.path().join("state"), "test-node".into()).unwrap();
        let r = record(true);
        let slot = driver.slot(&r.execution).unwrap();
        driver.save(&slot, &r).unwrap();
        assert!(matches!(
            driver.restart(&r.execution, u64::MAX).await,
            Err(Error::Ownership)
        ));
    }

    #[test]
    fn an_exited_container_reports_how_it_ended() {
        let exited = container(json!({"Status":"exited","ExitCode":137,"OOMKilled":true,
            "StartedAt":"2026-11-23T10:00:00.1Z","FinishedAt":"2026-11-23T10:05:00.2Z"}));
        let status = DockerDriver::status("slot", &record(false), Some(&exited)).unwrap();
        assert_eq!(status.state, RuntimeState::Stopped);
        assert_eq!(
            status.exit,
            Some(ExitStatus {
                code: 137,
                oom_killed: true,
                started_at: "2026-11-23T10:00:00.1Z".into(),
                finished_at: "2026-11-23T10:05:00.2Z".into(),
            })
        );
        let wire = serde_json::to_value(&status).unwrap();
        assert_eq!(
            wire["exit"],
            json!({"code":137,"oom_killed":true,"started_at":"2026-11-23T10:00:00.1Z",
                "finished_at":"2026-11-23T10:05:00.2Z"})
        );

        // A process that hasn't ended has no exit status, and the field is
        // left out, so a status reads as it did.
        for state in [
            json!({"Status":"running","ExitCode":0,"OOMKilled":false,
                "StartedAt":"2026-11-23T10:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}),
            json!({"Status":"created","ExitCode":0,"OOMKilled":false,
                "StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}),
        ] {
            let status =
                DockerDriver::status("slot", &record(false), Some(&container(state))).unwrap();
            assert_eq!(status.exit, None);
            assert!(serde_json::to_value(&status).unwrap().get("exit").is_none());
        }
        let missing = DockerDriver::status("slot", &record(false), None).unwrap();
        assert_eq!(missing.exit, None);
        let incomplete = container(json!({"Status":"exited","ExitCode":1}));
        let status = DockerDriver::status("slot", &record(false), Some(&incomplete)).unwrap();
        assert_eq!(status.exit, None);
    }

    #[test]
    fn a_run_to_completion_has_no_surface_and_keeps_other_journals_unchanged() {
        DockerDriver::options(&request(json!({"run_to_completion":true}), json!([]))).unwrap();
        let app = json!([{"id":{"namespace":"test","workload":"docker","service":"app"},
            "endpoint_ref":"app","protocol":"http1"}]);
        for (options, services) in [
            (json!({"run_to_completion":true,"port":8080}), app.clone()),
            (json!({"run_to_completion":true,"port":8080}), json!([])),
            (
                json!({"run_to_completion":true,"port":0,"container_port":8080}),
                json!([]),
            ),
            (json!({"run_to_completion":true}), app),
        ] {
            assert!(matches!(
                DockerDriver::options(&request(options, services)),
                Err(Error::InvalidContract)
            ));
        }
        assert!(serde_json::to_value(record(false))
            .unwrap()
            .get("run_to_completion")
            .is_none());
        assert_eq!(
            serde_json::to_value(record(true)).unwrap()["run_to_completion"],
            true
        );
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;

    fn sh(script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[tokio::test]
    async fn output_keeps_the_order_of_both_streams_and_stops_at_its_limit() {
        let (bytes, complete) = read_output(sh("echo 1; echo 2 >&2; echo 3"), 1024)
            .await
            .unwrap();
        assert_eq!(bytes, b"1\n2\n3\n");
        assert!(complete);

        // Cut off and killed: it would otherwise run for five minutes.
        let started = std::time::Instant::now();
        let (bytes, complete) = read_output(sh("yes; sleep 300"), 1000).await.unwrap();
        assert_eq!(bytes.len(), 1000);
        assert!(!complete);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));

        // Exactly the limit is all of it.
        let (bytes, complete) = read_output(sh("printf 1234"), 4).await.unwrap();
        assert_eq!((bytes.as_slice(), complete), (&b"1234"[..], true));

        // A failed command's errors are never output.
        assert!(matches!(
            read_output(sh("echo secret-detail >&2; exit 1"), 1024).await,
            Err(Error::Unavailable)
        ));
    }
}
