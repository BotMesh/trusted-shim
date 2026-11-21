//! Machine-local Docker lifecycle. The caller is the authenticated node adapter,
//! never an agent. This driver provides resource limits, not shell policy isolation.
use crate::{
    attestation::AttestationRequirement,
    proof::ProofRequirement,
    runtime::{LaunchRequest, ResourceLimits, RuntimeDriver, RuntimeState, RuntimeStatus},
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
    path::PathBuf,
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
}

/// Private state must survive upgrades, deletion and restart. A tombstone fences
/// old generations; removing this directory while allocations exist is unsafe.
#[derive(Clone)]
pub struct DockerDriver {
    state: PathBuf,
    node_id: String,
}

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

impl DockerDriver {
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

    pub(crate) async fn restart(
        &self,
        execution: &ExecutionIdentity,
        expires_at: u64,
    ) -> Result<()> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        if trusted_router_transport::grants::now() >= expires_at {
            return Err(Error::Untrusted);
        }
        let record = self.owned(&slot, execution)?;
        if record.phase != Phase::Running || Self::container(&slot, &record).await?.is_none() {
            return Err(Error::Ownership);
        }
        Self::docker(&[
            "restart".into(),
            "--time".into(),
            record.stop_timeout_s.to_string(),
            Self::name(&slot),
        ])
        .await?;
        Ok(())
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
            _file: file,
            closed,
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
        let output = tokio::time::timeout(Duration::from_secs(120), command.output())
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
            {
                return Err(Error::Untrusted);
            }
            ResourceLimits {
                cpu_millicores: v["HostConfig"]["NanoCpus"]
                    .as_u64()
                    .filter(|v| *v > 0)
                    .map(|v| v / 1_000_000),
                memory_bytes: v["HostConfig"]["Memory"].as_u64().filter(|v| *v > 0),
            }
        } else {
            r.limits.clone()
        };
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
        Ok(RuntimeStatus {
            execution: r.execution.clone(),
            runtime_id: Self::name(slot),
            state,
            effective_limits,
            port: r.port,
        })
    }

    fn options(request: &LaunchRequest) -> Result<DockerOptions> {
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
            || request.command.iter().any(|s| s.contains('\0'))
            || request.environment.iter().any(|(k, v)| {
                k.is_empty() || k.contains(['=', '\0']) || v.contains(['\0', '\n', '\r'])
            })
        {
            return Err(Error::InvalidContract);
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
            || options.stop_timeout_s.is_some_and(|n| n > 90)
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
        if let Some(bytes) = options.shm_bytes {
            args.extend(["--shm-size".into(), bytes.to_string()]);
        }
        if let Some(port) = r.port {
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
        let _lock = self.lock(&slot).await?;
        let mut r = self.owned(&slot, execution)?;
        let _network = self.drain_network(execution).await?;
        if r.phase != Phase::Deleted {
            r.phase = Phase::Stopped;
            self.save(&slot, &r)?;
        }
        if Self::container(&slot, &r).await?.is_some() {
            Self::docker(&[
                "stop".into(),
                "--time".into(),
                r.stop_timeout_s.to_string(),
                Self::name(&slot),
            ])
            .await?;
            if Self::container(&slot, &r)
                .await?
                .is_some_and(|v| v["State"]["Running"] == true)
            {
                return Err(Error::Unavailable);
            }
        }
        Ok(())
    }

    async fn delete(&self, execution: &ExecutionIdentity) -> Result<()> {
        let slot = self.slot(execution)?;
        let _lock = self.lock(&slot).await?;
        let mut r = match self.read(&slot)? {
            Some(r) if &r.execution == execution => r,
            Some(_) => return Err(Error::Ownership),
            None => Record {
                execution: execution.clone(),
                request_sha256: String::new(),
                limits: ResourceLimits {
                    cpu_millicores: None,
                    memory_bytes: None,
                },
                phase: Phase::Deleted,
                stop_timeout_s: 30,
                port: None,
                allocated_port: false,
                services: Vec::new(),
                ingress: Default::default(),
            },
        };
        let _network = self.drain_network(execution).await?;
        // Fence even a launch that has not reached this machine yet.
        r.phase = Phase::Deleted;
        self.save(&slot, &r)?;
        if let Some(container) = Self::container(&slot, &r).await? {
            if container["State"]["Running"] == true {
                Self::docker(&[
                    "stop".into(),
                    "--time".into(),
                    r.stop_timeout_s.to_string(),
                    Self::name(&slot),
                ])
                .await?;
            }
            Self::docker(&["rm".into(), "--force".into(), Self::name(&slot)]).await?;
        }
        if Self::container(&slot, &r).await?.is_some() {
            return Err(Error::Unavailable);
        }
        self.release_port(&r)?;
        Ok(())
    }
}
