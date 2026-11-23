//! Calls the unmodified OpenShell compute driver on a private, same-UID Unix
//! socket. The native driver owns workload/supervisor separation and isolation.
//! This transport never exposes the Docker socket or substitutes plain Docker.
pub mod access;
pub mod attachments;
pub mod daemon;
pub(crate) mod data_plane;
pub mod gateway;
pub mod lifecycle;
pub mod network;
pub mod services;

use crate::{Error, Result};
use hyper_util::rt::TokioIo;
use openshell_core::{
    extension_protocol::{gateway_metadata, negotiate_metadata, ExtensionFamily},
    policy_identity::deterministic_policy_hash,
    proto::compute::v1::{compute_driver_client::ComputeDriverClient, *},
};
use prost::Message;
use sha2::{Digest, Sha256};
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
    pub(crate) sandbox: DriverSandbox,
    pub(crate) launch_sha256: String,
    pub(crate) native_sha256: String,
    pub(crate) policy_sha256: String,
}

/// Keep native negotiation/validation before central grant consumption, leaving
/// only the mutation itself after the last authorization freshness check.
pub(crate) struct NativeDispatch {
    client: ComputeDriverClient<Channel>,
    approved: NativeCreate,
}
impl NativeDispatch {
    pub(crate) async fn send(mut self) -> Result<()> {
        self.client
            .create_sandbox(CreateSandboxRequest {
                sandbox: Some(self.approved.sandbox),
            })
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
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
    /// Commitment to the exact private protobuf bytes, safe for durable journals.
    pub fn native_sha256(&self) -> &str {
        &self.native_sha256
    }
    /// Bind the native policy and every canonical workload input to the Fleet
    /// allocation. Resource strings are deliberately canonical at this boundary.
    pub fn decode(
        bytes: &[u8],
        request: &crate::runtime::LaunchRequest,
        policy_sha256: &str,
    ) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(Error::InvalidContract);
        }
        let sandbox = DriverSandbox::decode(bytes).map_err(|_| Error::InvalidContract)?;
        Self::validate(&sandbox, request, policy_sha256, true)?;
        Ok(Self {
            sandbox,
            launch_sha256: trusted_rail::rego::commitment("trusted-shim.launch.v1", request)
                .map_err(|_| Error::InvalidContract)?,
            native_sha256: hex::encode(Sha256::digest(bytes)),
            policy_sha256: policy_sha256.into(),
        })
    }

    /// The gateway validates a proposal before minting launch credentials. This
    /// shares all workload bindings with dispatch but does not authorize Create.
    pub(crate) fn validate_proposal(
        sandbox: &DriverSandbox,
        request: &crate::runtime::LaunchRequest,
        policy_sha256: &str,
    ) -> Result<()> {
        Self::validate(sandbox, request, policy_sha256, false)
    }

    fn validate(
        sandbox: &DriverSandbox,
        request: &crate::runtime::LaunchRequest,
        policy_sha256: &str,
        credentials_required: bool,
    ) -> Result<()> {
        crate::access::native_policy(request, policy_sha256)?;
        attachments::validate(request)?;
        if sandbox.encoded_len() > 1024 * 1024
            || !matches!(
                request.driver.as_str(),
                "docker" | "tee" | "tee-simulation" | "openshell"
            )
        {
            return Err(Error::InvalidContract);
        }
        crate::openshell_services::ServiceOptions::from_request(request)?;
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
        // The native driver enforces CPU and memory limits but has no CPU
        // weight. Refuse one rather than create the sandbox without it.
        if request.limits.cpu_shares.is_some() {
            return Err(Error::Unsupported);
        }
        if sandbox.id.is_empty()
            || sandbox.name.is_empty()
            // The stock gateway leaves the platform namespace empty; the
            // driver chooses it from its operator configuration. Workspace is
            // the tenant boundary and must match Fleet's canonical namespace.
            || !sandbox.namespace.is_empty()
            || sandbox.workspace != crate::openshell_gateway::workspace_name(&request.execution.namespace)
            || sandbox.status.as_ref().is_some_and(|s| {
                // The gateway supplies a pending configuration observation on
                // create. It cannot supply an existing runtime or readiness.
                s.name != sandbox.name
                    || !s.instance_id.is_empty()
                    || !s.agent_fd.is_empty()
                    || !s.sandbox_fd.is_empty()
                    || s.deleting
                    || s.resolved_identity.is_some()
                    || s.fence_evidence.is_some()
                    || s.conditions.iter().any(|c| !matches!(c.status.as_str(), "False" | "Unknown"))
            })
            || template.image != request.image
            || spec.command != request.command
            || spec
                .environment
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                != request.environment.iter().collect()
            || !template.environment.is_empty()
            || deterministic_policy_hash(policy) != policy_sha256
            || (credentials_required
                && (spec.launch_authentication.is_empty() || spec.sandbox_token.is_empty()))
            || limits.cpu_limit != format!("{cpu}m")
            // Fleet/Ray own scheduling requests. The native Docker compute
            // driver accepts hard limits and rejects Kubernetes-style requests.
            || !limits.cpu_request.is_empty()
            || limits.memory_limit != memory.to_string()
            || !limits.memory_request.is_empty()
        {
            return Err(Error::Untrusted);
        }
        // The native gateway always supplies these selectors, including an
        // empty pair for image defaults. Bind them to the committed policy;
        // resolution to a non-root UID/GID remains the upstream driver's job.
        let user = policy
            .process
            .as_ref()
            .map_or("", |p| p.run_as_user.as_str());
        let group = policy
            .process
            .as_ref()
            .map_or("", |p| p.run_as_group.as_str());
        if spec
            .workload_identity
            .as_ref()
            .map_or(!user.is_empty() || !group.is_empty(), |i| {
                i.user != user || i.group != group
            })
        {
            return Err(Error::Untrusted);
        }
        // GPUs and storage must be exactly Fleet's grant: the CDI devices Ray
        // assigned with a matching count (never a driver-chosen default) and
        // the workload-scoped volumes. Nothing else may enter driver_config.
        let gpu = spec
            .resource_requirements
            .as_ref()
            .and_then(|r| r.gpu.as_ref());
        if gpu.map(|g| g.count) != attachments::gpu_count(request).map(Some)
            || template.driver_config != attachments::driver_config(request)?
        {
            return Err(Error::Untrusted);
        }
        if template.platform_config.is_some()
            || template.user_namespaces.is_some()
            || !template.agent_socket_path.is_empty()
            || !template.labels.is_empty()
            || spec.tty
            || spec.await_main_process_attachment
            || spec.isolation_backend.is_some()
        {
            return Err(Error::Unsupported);
        }
        Ok(())
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
        self.prepare_dispatch(approved).await?.send().await
    }

    pub(crate) async fn prepare_dispatch(&self, approved: NativeCreate) -> Result<NativeDispatch> {
        let mut client = self.client().await?;
        client
            .validate_sandbox_create(ValidateSandboxCreateRequest {
                sandbox: Some(approved.sandbox.clone()),
            })
            .await
            .map_err(|_| Error::Untrusted)?;
        Ok(NativeDispatch { client, approved })
    }

    /// Provision this launch's workload-scoped volumes before native admission,
    /// which requires them to exist with this node's admission labels.
    pub async fn ensure_volumes(&self, request: &crate::runtime::LaunchRequest) -> Result<()> {
        attachments::ensure_volumes(request, &self.admission_policy).await
    }

    /// Read-only admission check; never consumes a grant or creates resources.
    pub async fn validate(&self, approved: &NativeCreate) -> Result<()> {
        self.client()
            .await?
            .validate_sandbox_create(ValidateSandboxCreateRequest {
                sandbox: Some(approved.sandbox.clone()),
            })
            .await
            .map_err(|_| Error::Untrusted)?;
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
