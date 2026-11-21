//! Calls the unmodified OpenShell compute driver on a private, same-UID Unix
//! socket. The native driver owns workload/supervisor separation and isolation.
//! This transport never exposes the Docker socket or substitutes plain Docker.
use crate::{Error, Result};
use hyper_util::rt::TokioIo;
use openshell_core::{
    extension_protocol::{gateway_metadata, negotiate_metadata, ExtensionFamily},
    policy_identity::deterministic_policy_hash,
    proto::compute::v1::{compute_driver_client::ComputeDriverClient, *},
};
use prost::Message;
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tonic::transport::{Channel, Endpoint};

/// Operator configuration, separate from agent-supplied launch parameters.
/// Socket and admission policy are selected by the machine's existing config.
#[derive(Clone)]
pub struct NativeDriver {
    socket: PathBuf,
    admission_policy: String,
}

/// Exact upstream provisioning bytes, delivered by the central OpenShell
/// gateway after it mints split launch authentication. Deliberately no Debug.
pub struct NativeCreate {
    sandbox: DriverSandbox,
}

fn private_socket(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::InvalidContract);
    }
    let uid = unsafe { libc::geteuid() };
    let parent = std::fs::symlink_metadata(path.parent().ok_or(Error::InvalidContract)?)
        .map_err(|_| Error::Unavailable)?;
    let socket = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !parent.is_dir()
        || parent.uid() != uid
        || parent.permissions().mode() & 0o077 != 0
        || !socket.file_type().is_socket()
        || socket.uid() != uid
        || socket.permissions().mode() & 0o077 != 0
    {
        return Err(Error::Untrusted);
    }
    Ok(())
}

impl NativeCreate {
    /// Bind the native policy and every canonical workload input to the Fleet
    /// allocation. Resource strings are deliberately canonical at this boundary.
    pub fn decode(
        bytes: &[u8],
        request: &crate::runtime::LaunchRequest,
        policy_sha256: &str,
    ) -> Result<Self> {
        if bytes.len() > 1024 * 1024 || request.driver != "openshell" {
            return Err(Error::InvalidContract);
        }
        let sandbox = DriverSandbox::decode(bytes).map_err(|_| Error::InvalidContract)?;
        let spec = sandbox.spec.as_ref().ok_or(Error::InvalidContract)?;
        let template = spec.template.as_ref().ok_or(Error::InvalidContract)?;
        let policy = spec.policy.as_ref().ok_or(Error::InvalidContract)?;
        let limits = template.resources.as_ref().ok_or(Error::InvalidContract)?;
        let cpu = request
            .limits
            .cpu_millicores
            .filter(|v| *v > 0)
            .ok_or(Error::InvalidContract)?;
        let memory = request
            .limits
            .memory_bytes
            .filter(|v| *v >= 6 * 1024 * 1024)
            .ok_or(Error::InvalidContract)?;
        if sandbox.id.is_empty()
            || sandbox.name.is_empty()
            || sandbox.status.is_some()
            || sandbox.namespace != request.execution.namespace
            || template.image != request.image
            || spec.command != request.command
            || spec
                .environment
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                != request.environment.iter().collect()
            || !template.environment.is_empty()
            || deterministic_policy_hash(policy) != policy_sha256
            || spec.launch_authentication.is_empty()
            || spec.sandbox_token.is_empty()
            || limits.cpu_limit != format!("{cpu}m")
            || limits.cpu_request != limits.cpu_limit
            || limits.memory_limit != memory.to_string()
            || limits.memory_request != limits.memory_limit
        {
            return Err(Error::Untrusted);
        }
        // Fleet must explicitly map Ray's GPU allocation and every external
        // attachment before those features can be exposed by this adapter.
        if spec
            .resource_requirements
            .as_ref()
            .is_some_and(|r| r.gpu.is_some())
            || template.driver_config.is_some()
            || template.platform_config.is_some()
            || template.user_namespaces.is_some()
            || !template.agent_socket_path.is_empty()
            || !template.labels.is_empty()
            || spec.workload_identity.is_some()
            || spec.tty
            || spec.await_main_process_attachment
            || spec.isolation_backend.is_some()
            || !request.driver_options.is_null()
        {
            return Err(Error::Unsupported);
        }
        Ok(Self { sandbox })
    }
}

impl NativeDriver {
    pub fn new(socket: PathBuf, admission_policy: String) -> Result<Self> {
        if !socket.is_absolute() || admission_policy.is_empty() || admission_policy.len() > 65536 {
            return Err(Error::InvalidContract);
        }
        Ok(Self {
            socket,
            admission_policy,
        })
    }

    async fn client(&self) -> Result<ComputeDriverClient<Channel>> {
        private_socket(&self.socket)?;
        let path = self.socket.clone();
        let channel = Endpoint::from_static("http://[::]:50051")
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(120))
            .connect_with_connector(tower::service_fn(move |_| {
                let path = path.clone();
                async move {
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "driver peer UID mismatch",
                        ));
                    }
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut client = ComputeDriverClient::new(channel)
            .max_decoding_message_size(2 * 1024 * 1024)
            .max_encoding_message_size(2 * 1024 * 1024);
        let peer = gateway_metadata(ExtensionFamily::Compute);
        let capabilities = client
            .get_capabilities(GetCapabilitiesRequest {
                gateway: Some(peer.clone()),
            })
            .await
            .map_err(|_| Error::Unavailable)?
            .into_inner();
        negotiate_metadata("compute", "docker", &peer, capabilities.extension)
            .map_err(|_| Error::Untrusted)?;
        let limits = capabilities.resource_capabilities.ok_or(Error::Untrusted)?;
        if capabilities.driver_name != "docker"
            || capabilities.resource_admission_policy != self.admission_policy
            || !limits.cpu.is_some_and(|c| c.limit_supported)
            || !limits.memory.is_some_and(|m| m.limit_supported)
        {
            return Err(Error::Untrusted);
        }
        Ok(client)
    }

    /// The caller persists ownership and consumes its central proof-backed
    /// authorization before this mutation. A timeout is ambiguous: inspect the
    /// same sandbox ID; never silently retry or replace it with a new sandbox.
    pub async fn create(&self, approved: NativeCreate) -> Result<()> {
        let mut client = self.client().await?;
        client
            .validate_sandbox_create(ValidateSandboxCreateRequest {
                sandbox: Some(approved.sandbox.clone()),
            })
            .await
            .map_err(|_| Error::Untrusted)?;
        client
            .create_sandbox(CreateSandboxRequest {
                sandbox: Some(approved.sandbox),
            })
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    /// Return only an exact identity; an upstream name match cannot adopt a
    /// replacement. Missing resources are distinguished from driver failure.
    pub async fn inspect(&self, id: &str, name: &str) -> Result<Option<DriverSandbox>> {
        let mut client = self.client().await?;
        let reply = match client
            .get_sandbox(GetSandboxRequest {
                sandbox_id: id.into(),
                name: name.into(),
            })
            .await
        {
            Ok(v) => v.into_inner().sandbox.ok_or(Error::Untrusted)?,
            Err(s) if s.code() == tonic::Code::NotFound => return Ok(None),
            Err(_) => return Err(Error::Unavailable),
        };
        if reply.id != id || reply.name != name {
            return Err(Error::Ownership);
        }
        Ok(Some(reply))
    }

    pub async fn stop(&self, id: &str, name: &str) -> Result<()> {
        if self.inspect(id, name).await?.is_none() {
            return Ok(());
        }
        self.client()
            .await?
            .stop_sandbox(StopSandboxRequest {
                sandbox_id: id.into(),
                name: name.into(),
            })
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    pub async fn delete(&self, id: &str, name: &str) -> Result<()> {
        if self.inspect(id, name).await?.is_some() {
            self.client()
                .await?
                .delete_sandbox(DeleteSandboxRequest {
                    sandbox_id: id.into(),
                    name: name.into(),
                })
                .await
                .map_err(|_| Error::Unavailable)?;
        }
        if self.inspect(id, name).await?.is_some() {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}
