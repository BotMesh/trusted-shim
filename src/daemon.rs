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
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
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
    #[cfg(feature = "openshell")]
    pub openshell: Option<crate::openshell_daemon::OpenShellConfig>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverKind {
    #[default]
    Docker,
    #[cfg(feature = "openshell")]
    Openshell,
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
    #[cfg(feature = "openshell")]
    Allocate {
        execution: ExecutionIdentity,
        driver: DriverKind,
    },
    #[cfg(feature = "openshell")]
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
    },
}

pub fn capabilities() -> Value {
    json!({"protocol": PROTOCOL, "drivers": ["docker"], "features": [
        "data-plane-v1", "runtime-management-v1", "single-use-ingress-v1", "runtime-daemon-v1"
    ]})
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRecord {
    execution: ExecutionIdentity,
    config: NetworkConfig,
}

struct NetworkTask {
    record: Vec<u8>,
    stop: CancellationToken,
    task: JoinHandle<Result<()>>,
}

struct Daemon {
    driver: DockerDriver,
    #[cfg(feature = "openshell")]
    openshell: Option<crate::openshell_daemon::OpenShellRuntime>,
    node_id: String,
    networks_dir: PathBuf,
    networks: Mutex<HashMap<String, NetworkTask>>,
}

fn network_key(execution: &ExecutionIdentity) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(execution).map_err(|_| Error::InvalidContract)?,
    )))
}

impl Daemon {
    async fn network(&self, record: NetworkRecord) -> Result<Value> {
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
        if self.driver.inspect(&record.execution).await?.state != RuntimeState::Ready {
            return Err(Error::Ownership);
        }
        // Validate and acquire the port/ownership fence before acknowledging.
        // The worker takes the same lock when it begins; competing legacy
        // connectors cannot silently redirect or duplicate this allocation.
        data_plane::validate_config(&record.config)?;
        let probe = self.driver.network_lease(&record.execution).await?;
        drop(probe);
        let mut file =
            tempfile::NamedTempFile::new_in(&self.networks_dir).map_err(|_| Error::Unavailable)?;
        file.write_all(&bytes).map_err(|_| Error::Unavailable)?;
        file.as_file().sync_all().map_err(|_| Error::Unavailable)?;
        file.persist(self.networks_dir.join(format!("{key}.json")))
            .map_err(|_| Error::Unavailable)?;
        self.sync_networks()?;
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let driver = self.driver.clone();
        let task = tokio::spawn(async move {
            data_plane::serve(&driver, &record.execution, &record.config, worker_stop).await
        });
        networks.insert(
            key,
            NetworkTask {
                record: bytes,
                stop,
                task,
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
                #[cfg(feature = "openshell")]
                if let Some(native) = &self.openshell {
                    value["openshell_config_sha256"] = json!(native.configuration_sha256);
                    value["drivers"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("openshell"));
                    value["features"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("openshell-provisioning-v1"));
                    value["features"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("openshell-allocation-v1"));
                }
                value["pid"] = json!(std::process::id());
                Ok(value)
            }
            Command::Launch { request } => {
                serde_json::to_value(self.driver.launch(&request).await?)
                    .map_err(|_| Error::InvalidContract)
            }
            #[cfg(feature = "openshell")]
            Command::Allocate { execution, driver } => {
                if !matches!(driver, DriverKind::Openshell) {
                    return Err(Error::Unsupported);
                }
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
            #[cfg(feature = "openshell")]
            Command::Provision { payload } => serde_json::to_value(
                self.openshell
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .provision(*payload)
                    .await?,
            )
            .map_err(|_| Error::InvalidContract),
            Command::Inspect { execution, driver } => match driver {
                DriverKind::Docker => serde_json::to_value(self.driver.inspect(&execution).await?),
                #[cfg(feature = "openshell")]
                DriverKind::Openshell => serde_json::to_value(
                    self.openshell
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .driver
                        .inspect(&execution)
                        .await?,
                ),
            }
            .map_err(|_| Error::InvalidContract),
            Command::Stop { execution, driver } => {
                match driver {
                    DriverKind::Docker => {
                        self.driver.stop(&execution).await?;
                        self.forget_network(&execution).await?;
                    }
                    #[cfg(feature = "openshell")]
                    DriverKind::Openshell => {
                        self.openshell
                            .as_ref()
                            .ok_or(Error::Unsupported)?
                            .driver
                            .stop(&execution)
                            .await?
                    }
                }
                Ok(json!({"stopped": true}))
            }
            Command::Delete { execution, driver } => {
                match driver {
                    DriverKind::Docker => {
                        self.driver.delete(&execution).await?;
                        self.forget_network(&execution).await?;
                    }
                    #[cfg(feature = "openshell")]
                    DriverKind::Openshell => {
                        self.openshell
                            .as_ref()
                            .ok_or(Error::Unsupported)?
                            .driver
                            .delete(&execution)
                            .await?
                    }
                }
                Ok(json!({"cleaned": true}))
            }
            Command::Network { execution, config } => {
                self.network(NetworkRecord { execution, config }).await
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
    let driver = DockerDriver::new(state, node_id.clone())?;
    let metadata = std::fs::symlink_metadata(state).map_err(|_| Error::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
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
    #[cfg(feature = "openshell")]
    let openshell = config
        .openshell
        .map(|c| crate::openshell_daemon::OpenShellRuntime::open(state, node_id.clone(), c))
        .transpose()?;
    #[cfg(not(feature = "openshell"))]
    let _ = config;
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
        #[cfg(feature = "openshell")]
        openshell,
        node_id,
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
