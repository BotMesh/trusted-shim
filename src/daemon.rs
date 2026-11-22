//! Private, versioned node-to-runtime protocol. The daemon, not its clients,
//! owns connector tasks. Losing a client never cancels an accepted operation.
use crate::{
    contracts::ExecutionIdentity,
    data_plane::{self, NetworkConfig},
    docker::DockerDriver,
    runtime::{LaunchRequest, RuntimeDriver, RuntimeState},
    Error, Result,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub const PROTOCOL: u32 = 1;
const MAX_REQUEST: usize = crate::provisioning::MAX_PROVISION_BYTES + 16 * 1024;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub machine: crate::machine::MachineConfig,
    /// Native enforcement connection, not an enable switch. Without it, only
    /// requests with no user access rules can use the driver directly.
    pub openshell: Option<crate::openshell_daemon::OpenShellConfig>,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverKind {
    #[default]
    Docker,
    Tee,
    #[serde(rename = "tee-simulation")]
    TeeSimulation,
    /// Read compatibility for existing native journals; never advertised as a driver.
    #[serde(rename = "openshell")]
    LegacyOpenShell,
}
impl DriverKind {
    fn is_docker(&self) -> bool {
        matches!(self, Self::Docker)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub node_id: String,
    pub command: Command,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Capabilities,
    Launch {
        request: Box<LaunchRequest>,
    },
    Allocate {
        execution: ExecutionIdentity,
        driver: DriverKind,
    },
    Provision {
        payload: Box<crate::provisioning::ProvisionRequest>,
    },
    Inspect {
        execution: ExecutionIdentity,
        #[serde(default)]
        driver: DriverKind,
    },
    Stop {
        execution: ExecutionIdentity,
        #[serde(default)]
        driver: DriverKind,
    },
    Delete {
        execution: ExecutionIdentity,
        #[serde(default)]
        driver: DriverKind,
    },
    Network {
        execution: ExecutionIdentity,
        config: NetworkConfig,
        #[serde(default)]
        driver: DriverKind,
    },
}

pub fn capabilities() -> Value {
    json!({"protocol": PROTOCOL, "drivers": ["docker"], "access_policy": {"provider":"openshell", "default":"driver_bounds"}, "features": [
        "data-plane-v1", "runtime-management-v1", "single-use-ingress-v1", "runtime-daemon-v1", "openshell-access-v1"
    ]})
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRecord {
    execution: ExecutionIdentity,
    config: NetworkConfig,
    #[serde(default, skip_serializing_if = "DriverKind::is_docker")]
    driver: DriverKind,
}

struct NetworkTask {
    record: Vec<u8>,
    stop: CancellationToken,
    task: JoinHandle<Result<()>>,
    health: Arc<crate::openshell_data_plane::Health>,
}

struct Daemon {
    driver: Option<DockerDriver>,
    tee: Option<crate::tee::TeeDriver>,
    machine: crate::machine::MachineProfile,
    machine_config_sha256: String,
    openshell: Option<crate::openshell_daemon::OpenShellRuntime>,
    node_id: String,
    creations: Mutex<()>,
    networks_dir: PathBuf,
    networks: Mutex<HashMap<String, NetworkTask>>,
}

fn network_key(execution: &ExecutionIdentity) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(execution).map_err(|_| Error::InvalidContract)?,
    )))
}

impl Daemon {
    fn lifecycle_driver(
        &self,
        execution: &ExecutionIdentity,
        requested: DriverKind,
    ) -> Result<DriverKind> {
        if let Some(native) = &self.openshell {
            if native.driver.claims(execution)? {
                return Ok(DriverKind::LegacyOpenShell);
            }
        }
        Ok(requested)
    }
    fn unclaimed_local(&self, execution: &ExecutionIdentity) -> Result<()> {
        if self
            .driver
            .as_ref()
            .map(|d| d.claims(execution))
            .transpose()?
            .unwrap_or(false)
            || self
                .tee
                .as_ref()
                .map(|d| d.backend().claims(execution))
                .transpose()?
                .unwrap_or(false)
        {
            return Err(Error::Ownership);
        }
        Ok(())
    }

    fn docker(&self) -> Result<&DockerDriver> {
        self.driver.as_ref().ok_or(Error::Unsupported)
    }
    fn tee(&self, driver: DriverKind) -> Result<&crate::tee::TeeDriver> {
        let tee = self.tee.as_ref().ok_or(Error::Unsupported)?;
        let expected = match driver {
            DriverKind::Tee => "tee",
            DriverKind::TeeSimulation => "tee-simulation",
            _ => return Err(Error::Unsupported),
        };
        if tee.driver() != expected {
            return Err(Error::Untrusted);
        }
        Ok(tee)
    }
    fn local(&self, driver: DriverKind) -> Result<&DockerDriver> {
        match driver {
            DriverKind::Docker => self.docker(),
            DriverKind::Tee | DriverKind::TeeSimulation => Ok(self.tee(driver)?.backend()),
            _ => Err(Error::Unsupported),
        }
    }
    fn runtime(&self, driver: DriverKind) -> Result<&dyn RuntimeDriver> {
        match driver {
            DriverKind::Docker => Ok(self.docker()?),
            DriverKind::Tee | DriverKind::TeeSimulation => Ok(self.tee(driver)?),
            _ => Err(Error::Unsupported),
        }
    }
    async fn network(&self, mut record: NetworkRecord) -> Result<Value> {
        record.driver = self.lifecycle_driver(&record.execution, record.driver)?;
        let key = network_key(&record.execution)?;
        let bytes = serde_json::to_vec(&record).map_err(|_| Error::InvalidContract)?;
        let mut networks = self.networks.lock().await;
        if let Some(previous) = networks.get(&key) {
            if previous.record != bytes {
                return Err(Error::Ownership);
            }
            if !previous.task.is_finished() {
                return Ok(json!({"connected_worker": true}));
            }
        }
        // Validate and acquire the port/ownership fence before acknowledging.
        // The worker takes the same lock when it begins; competing legacy
        // connectors cannot silently redirect or duplicate this allocation.
        data_plane::validate_config(&record.config)?;
        match record.driver {
            DriverKind::Docker | DriverKind::Tee | DriverKind::TeeSimulation => {
                if self
                    .local(record.driver)?
                    .inspect(&record.execution)
                    .await?
                    .state
                    != RuntimeState::Ready
                {
                    return Err(Error::Ownership);
                }
                drop(
                    self.local(record.driver)?
                        .network_lease(&record.execution)
                        .await?,
                );
            }
            DriverKind::LegacyOpenShell => {
                let native = self.openshell.as_ref().ok_or(Error::Unsupported)?;
                native.supervisor_image.as_ref().ok_or(Error::Unsupported)?;
                drop(native.driver.network_lease(&record.execution).await?);
            }
        }
        let mut file =
            tempfile::NamedTempFile::new_in(&self.networks_dir).map_err(|_| Error::Unavailable)?;
        file.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        file.as_file().sync_all().map_err(|_| Error::Unavailable)?;
        file.persist(self.networks_dir.join(format!("{key}.json")))
            .map_err(|_| Error::Unavailable)?;
        self.sync_networks()?;
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let health = Arc::new(crate::openshell_data_plane::Health::default());
        let task = match record.driver {
            DriverKind::Docker | DriverKind::Tee | DriverKind::TeeSimulation => {
                let driver = self.local(record.driver)?.clone();
                tokio::spawn(async move {
                    data_plane::serve(&driver, &record.execution, &record.config, worker_stop).await
                })
            }
            DriverKind::LegacyOpenShell => {
                let native = self.openshell.as_ref().ok_or(Error::Unsupported)?;
                let driver = native.driver.clone();
                let image = native.supervisor_image.clone().ok_or(Error::Unsupported)?;
                let health = health.clone();
                tokio::spawn(async move {
                    crate::openshell_data_plane::serve(
                        &driver,
                        &record.execution,
                        &record.config,
                        &image,
                        worker_stop,
                        health,
                    )
                    .await
                })
            }
        };
        networks.insert(
            key,
            NetworkTask {
                record: bytes,
                stop,
                task,
                health,
            },
        );
        Ok(json!({"connected_worker": true}))
    }

    fn sync_networks(&self) -> Result<()> {
        File::open(&self.networks_dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)
    }

    async fn forget_network(&self, execution: &ExecutionIdentity) -> Result<()> {
        let key = network_key(execution)?;
        let mut networks = self.networks.lock().await;
        // Delete/stop already holds the driver's durable fence. It cancels and
        // drains network leases before confirming cleanup to the scheduler.
        if let Some(task) = networks.remove(&key) {
            task.stop.cancel();
            let _ = task.task.await;
        }
        match std::fs::remove_file(self.networks_dir.join(format!("{key}.json"))) {
            Ok(()) => self.sync_networks(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::Unavailable),
        }
    }

    async fn execute(&self, request: Request) -> Result<Value> {
        if request.protocol != PROTOCOL || request.node_id != self.node_id {
            return Err(Error::InvalidContract);
        }
        match request.command {
            Command::Capabilities => {
                let mut value = capabilities();
                value["drivers"] = json!(self.machine.drivers);
                value["machine"] = json!(self.machine);
                value["machine_config_sha256"] = json!(self.machine_config_sha256);
                if let Some(native) = &self.openshell {
                    value["openshell_config_sha256"] = json!(native.configuration_sha256);
                    value["features"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("openshell-provisioning-v1"));
                    value["features"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("openshell-allocation-v1"));
                    if native.supervisor_image.is_some() {
                        value["features"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!("openshell-local-services-v1"));
                        value["features"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!("openshell-service-health-v1"));
                    }
                }
                if self.tee.is_some() {
                    value["features"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("tee-startup-v1"));
                }
                value["pid"] = json!(std::process::id());
                Ok(value)
            }
            Command::Launch { request } => {
                let _creation = self.creations.lock().await;
                crate::access::driver_bounds(&request)?;
                if self
                    .openshell
                    .as_ref()
                    .map(|n| n.driver.claims(&request.execution))
                    .transpose()?
                    .unwrap_or(false)
                {
                    return Err(Error::Ownership);
                }
                let driver: DriverKind = serde_json::from_value(json!(request.driver))
                    .map_err(|_| Error::Unsupported)?;
                serde_json::to_value(self.runtime(driver)?.launch(&request).await?)
                    .map_err(|_| Error::InvalidContract)
            }
            Command::Allocate { execution, driver } => {
                let _creation = self.creations.lock().await;
                if !matches!(driver, DriverKind::LegacyOpenShell) {
                    self.runtime(driver)?;
                }
                self.unclaimed_local(&execution)?;
                serde_json::to_value(
                    self.openshell
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .driver
                        .reserve(&execution)
                        .await?,
                )
                .map_err(|_| Error::InvalidContract)
            }
            Command::Provision { payload } => {
                let _creation = self.creations.lock().await;
                self.unclaimed_local(&payload.request.execution)?;
                if payload.request.driver != "openshell" {
                    let driver = serde_json::from_value(json!(payload.request.driver))
                        .map_err(|_| Error::Unsupported)?;
                    self.runtime(driver)?;
                }
                serde_json::to_value(
                    self.openshell
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .provision(*payload, self.tee.as_ref().map(|tee| tee.gate()))
                        .await?,
                )
                .map_err(|_| Error::InvalidContract)
            }
            Command::Inspect { execution, driver } => {
                match self.lifecycle_driver(&execution, driver)? {
                    DriverKind::Docker | DriverKind::Tee | DriverKind::TeeSimulation => {
                        serde_json::to_value(self.runtime(driver)?.inspect(&execution).await?)
                    }
                    DriverKind::LegacyOpenShell => {
                        let status = self
                            .openshell
                            .as_ref()
                            .ok_or(Error::Unsupported)?
                            .driver
                            .inspect(&execution)
                            .await?;
                        let ready = status.platform_ready
                            && self
                                .networks
                                .lock()
                                .await
                                .get(&network_key(&execution)?)
                                .is_some_and(|task| {
                                    !task.stop.is_cancelled()
                                        && !task.task.is_finished()
                                        && task.health.ready()
                                });
                        let mut value =
                            serde_json::to_value(status).map_err(|_| Error::InvalidContract)?;
                        value["application_ready"] = json!(ready);
                        Ok(value)
                    }
                }
                .map_err(|_| Error::InvalidContract)
            }
            Command::Stop { execution, driver } => {
                match self.lifecycle_driver(&execution, driver)? {
                    DriverKind::Docker | DriverKind::Tee | DriverKind::TeeSimulation => {
                        self.runtime(driver)?.stop(&execution).await?;
                        self.forget_network(&execution).await?;
                    }
                    DriverKind::LegacyOpenShell => {
                        self.openshell
                            .as_ref()
                            .ok_or(Error::Unsupported)?
                            .driver
                            .stop(&execution)
                            .await?;
                        self.forget_network(&execution).await?;
                    }
                }
                Ok(json!({"stopped": true}))
            }
            Command::Delete { execution, driver } => {
                match self.lifecycle_driver(&execution, driver)? {
                    DriverKind::Docker | DriverKind::Tee | DriverKind::TeeSimulation => {
                        self.runtime(driver)?.delete(&execution).await?;
                        self.forget_network(&execution).await?;
                    }
                    DriverKind::LegacyOpenShell => {
                        self.openshell
                            .as_ref()
                            .ok_or(Error::Unsupported)?
                            .driver
                            .delete(&execution)
                            .await?;
                        self.forget_network(&execution).await?;
                    }
                }
                Ok(json!({"cleaned": true}))
            }
            Command::Network {
                execution,
                config,
                driver,
            } => {
                self.network(NetworkRecord {
                    execution,
                    config,
                    driver,
                })
                .await
            }
        }
    }

    async fn recover(&self) -> Result<()> {
        for entry in std::fs::read_dir(&self.networks_dir).map_err(|_| Error::Unavailable)? {
            let path = entry.map_err(|_| Error::Unavailable)?.path();
            if path.extension().is_none_or(|s| s != "json") {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|_| Error::Unavailable)?;
            let record: NetworkRecord =
                serde_json::from_slice(&bytes).map_err(|_| Error::InvalidContract)?;
            if path.file_stem().and_then(|s| s.to_str()) != Some(&network_key(&record.execution)?) {
                return Err(Error::InvalidContract);
            }
            // Recover connections only, never restart an application. Keep a
            // failed record for explicit retry when Docker is temporarily down.
            if self.network(record).await.is_err() {
                eprintln!("shim connector recovery deferred");
            }
        }
        Ok(())
    }

    async fn connection(&self, mut socket: UnixStream) -> Result<()> {
        let uid = std::fs::metadata(&self.networks_dir)
            .map_err(|_| Error::Unavailable)?
            .uid();
        if socket.peer_cred().map_err(|_| Error::Untrusted)?.uid() != uid {
            return Err(Error::Untrusted);
        }
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            (&mut socket)
                .take((MAX_REQUEST + 1) as u64)
                .read_to_end(&mut bytes),
        )
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unavailable)?;
        let result = if bytes.len() > MAX_REQUEST {
            Err(Error::InvalidContract)
        } else {
            match serde_json::from_slice::<Request>(&bytes) {
                Ok(request) => self.execute(request).await,
                Err(_) => Err(Error::InvalidContract),
            }
        };
        let response = match result {
            Ok(result) => json!({"protocol": PROTOCOL, "result": result}),
            Err(error) => json!({"protocol": PROTOCOL, "error": error.to_string()}),
        };
        let bytes = serde_json::to_vec(&response).map_err(|_| Error::InvalidContract)?;
        tokio::time::timeout(Duration::from_secs(5), socket.write_all(&bytes))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)
    }
}

/// Independently supervised service, accessible only to the owning OS user.
/// Shutdown closes connectors but never stops containers or releases allocations.
pub async fn serve(state: &Path, node_id: String, stop: CancellationToken) -> Result<()> {
    serve_configured(state, node_id, DaemonConfig::default(), stop).await
}

pub async fn serve_configured(
    state: &Path,
    node_id: String,
    config: DaemonConfig,
    stop: CancellationToken,
) -> Result<()> {
    let machine = config.machine.resolve(crate::machine::detect()?)?;
    let machine_config_sha256 = config.machine.digest()?;
    if !state.is_absolute() || node_id.is_empty() {
        return Err(Error::InvalidContract);
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(state)
        .map_err(|_| Error::Unavailable)?;
    let metadata = std::fs::symlink_metadata(state).map_err(|_| Error::Unavailable)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Untrusted);
    }
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(state.join("daemon.lock"))
        .map_err(|_| Error::Unavailable)?;
    lock.try_lock_exclusive().map_err(|_| Error::Ownership)?;
    let driver = if machine.drivers.iter().any(|d| d == "docker") {
        Some(DockerDriver::new(state, node_id.clone())?)
    } else {
        // Keep existing allocations recoverable; changing node labels is not a migration.
        if DockerDriver::has_allocations(state)? {
            return Err(Error::Ownership);
        }
        None
    };
    #[cfg(feature = "ziren")]
    let tee = match config.machine.tee.clone() {
        Some(c) => Some(crate::tee::TeeDriver::connect(state, node_id.clone(), c).await?),
        None => None,
    };
    #[cfg(not(feature = "ziren"))]
    let tee = {
        if config.machine.tee.is_some() {
            return Err(Error::Unsupported);
        }
        None
    };
    if tee.is_none() && state.join("tee/profile.sha256").exists() {
        // A pending attestation may not have a Docker record yet. Preserve its
        // cleanup authority as well as the already-created workloads.
        return Err(Error::Ownership);
    }
    if config.openshell.is_none() && state.join("openshell.sqlite").exists() {
        return Err(Error::Ownership);
    }
    let openshell = config
        .openshell
        .map(|c| crate::openshell_daemon::OpenShellRuntime::open(state, node_id.clone(), c))
        .transpose()?;
    let socket_path = state.join("control.sock");
    match std::fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::Unavailable),
    }
    let listener = UnixListener::bind(&socket_path).map_err(|_| Error::Unavailable)?;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| Error::Unavailable)?;
    let networks_dir = state.join("networks");
    std::fs::create_dir_all(&networks_dir).map_err(|_| Error::Unavailable)?;
    std::fs::set_permissions(&networks_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|_| Error::Unavailable)?;
    let daemon = Arc::new(Daemon {
        driver,
        tee,
        machine,
        machine_config_sha256,
        openshell,
        node_id,
        creations: Mutex::new(()),
        networks_dir,
        networks: Mutex::new(HashMap::new()),
    });
    daemon.recover().await?;
    let slots = Arc::new(Semaphore::new(32));
    let mut requests = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = requests.join_next(), if !requests.is_empty() => {},
            incoming = listener.accept() => {
                let (socket, _) = incoming.map_err(|_| Error::Unavailable)?;
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue; };
                let daemon = daemon.clone();
                requests.spawn(async move { let _slot = slot; let _ = daemon.connection(socket).await; });
            }
        }
    }
    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
    // Finish accepted lifecycle operations before shutting down connectors.
    while requests.join_next().await.is_some() {}
    for (_, task) in daemon.networks.lock().await.drain() {
        task.stop.cancel();
        let _ = task.task.await;
    }
    drop(lock);
    Ok(())
}
