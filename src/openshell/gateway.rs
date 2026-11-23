//! Stateless translation at the stock gateway's ComputeDriver boundary.
//! Fleet owns allocation, proof jobs, delivery and lifecycle. This adapter owns
//! no queue, scheduler, credentials store or additional configuration file.
use crate::{
    attestation::AttestationRequirement, openshell::NativeCreate, proof::ProofRequirement,
    runtime::LaunchRequest, Error, Result,
};
use openshell_core::proto;
use prost::Message;
use prost_types::{value::Kind, Struct, Value};
use trusted_contracts::ExecutionIdentity;
use trusted_rail::rego::commitment;

pub use openshell_core::policy_identity::deterministic_policy_hash;
pub use openshell_core::proto as protocol;
pub use openshell_core::proto::{compute::v1::DriverSandbox, sandbox::v1::SandboxPolicy};
pub use openshell_core::{extension_protocol, resource_admission};

/// Stock gateway workspace names are routable labels capped at 19 bytes.
/// Preserve compatible names; map canonical Fleet IDs without changing the
/// full execution identity bound by Rail. The control plane must reject any
/// mapping collision between different canonical namespaces.
pub fn workspace_name(namespace: &str) -> String {
    if !namespace.is_empty()
        && namespace.len() <= 19
        && namespace
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !namespace.starts_with('-')
        && !namespace.ends_with('-')
        && !namespace.contains("--")
    {
        return namespace.into();
    }
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"trusted-shim.openshell.workspace.v1\0");
    hash.update(namespace.as_bytes());
    format!("w{}", &hex::encode(hash.finalize())[..18])
}

/// Safe compute observation for the central gateway. Workload configuration,
/// credentials, local endpoints and platform diagnostics never enter heartbeats.
pub fn control_observation(sandbox: &DriverSandbox) -> Result<DriverSandbox> {
    let mut result = sandbox.clone();
    result.spec = None;
    if let Some(s) = result.status.as_mut() {
        s.agent_fd.clear();
        s.sandbox_fd.clear();
        for condition in &mut s.conditions {
            condition.message.clear();
        }
    }
    if result.encoded_len() > 16 * 1024 {
        return Err(Error::InvalidContract);
    }
    Ok(result)
}

/// Construct only from the control plane's admitted allocation and policy.
/// Contains workload environment; deliberately no Debug or Serialize impl.
pub struct GatewayLaunch {
    launch: LaunchRequest,
    policy: SandboxPolicy,
    name: String,
    policy_sha256: String,
}

impl GatewayLaunch {
    pub fn execution_name(execution: &ExecutionIdentity) -> Result<String> {
        let digest = commitment("trusted-shim.openshell.gateway-name.v1", execution)
            .map_err(|_| Error::InvalidContract)?;
        Ok(format!("f{}", &digest[..18]))
    }
    pub fn new(launch: LaunchRequest, policy: SandboxPolicy) -> Result<Self> {
        let e = &launch.execution;
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
            || launch.image.is_empty()
            // An omitted command makes the stock gateway request an interactive
            // TTY. This provisioning profile intentionally excludes TTY launches.
            || launch.command.is_empty()
            || launch.limits.cpu_millicores.is_none_or(|v| v == 0)
            || launch
                .limits
                .memory_bytes
                .is_none_or(|v| v < 6 * 1024 * 1024)
            || policy.encoded_len() > 1024 * 1024
        {
            return Err(Error::InvalidContract);
        }
        // This is the same initial native profile admitted at the node. No
        // unsupported request may silently turn into a weaker public API call.
        crate::access::native_policy(&launch, &deterministic_policy_hash(&policy))?;
        let attestation_valid = match (&launch.trust.attestation, &launch.trust.attestation_proof) {
            (AttestationRequirement::SkipNonTee, ProofRequirement::NotRequired) => true,
            (AttestationRequirement::Required { profile }, ProofRequirement::Required) => {
                matches!(profile.as_str(), "snp" | "tdx" | "sample")
            }
            _ => false,
        };
        if !matches!(
            launch.driver.as_str(),
            "docker" | "tee" | "tee-simulation" | "openshell"
        ) || !attestation_valid
            || launch.trust.policy_proof != ProofRequirement::NotRequired
        {
            return Err(Error::Unsupported);
        }
        crate::openshell_services::ServiceOptions::from_request(&launch)?;
        crate::openshell::attachments::validate(&launch)?;
        let result = Self {
            // Stock gateway routable names are limited to 19 characters. This
            // is a lookup hint, not authority: the full execution remains bound
            // in the launch commitment and proof, including on a name collision.
            name: Self::execution_name(e)?,
            policy_sha256: deterministic_policy_hash(&policy),
            policy,
            launch,
        };
        if result.request().encoded_len() > 1024 * 1024 {
            return Err(Error::InvalidContract);
        }
        Ok(result)
    }

    /// Pass to the authenticated stock gateway configured with Fleet's compute
    /// extension. This is not a call to a machine-local Docker driver. The
    /// gateway remains responsible for minting its own launch credentials.
    pub fn request(&self) -> proto::CreateSandboxRequest {
        use crate::openshell::attachments;
        let string = |v: String| Value {
            kind: Some(Kind::StringValue(v)),
        };
        let resources = Struct {
            fields: [(
                "limits".into(),
                Value {
                    kind: Some(Kind::StructValue(Struct {
                        fields: [
                            (
                                "cpu".into(),
                                string(format!("{}m", self.launch.limits.cpu_millicores.unwrap())),
                            ),
                            (
                                "memory".into(),
                                string(self.launch.limits.memory_bytes.unwrap().to_string()),
                            ),
                        ]
                        .into(),
                    })),
                },
            )]
            .into(),
        };
        proto::CreateSandboxRequest {
            name: self.name.clone(),
            workspace_scope: Some(proto::workspace_selector(workspace_name(
                &self.launch.execution.namespace,
            ))),
            spec: Some(proto::SandboxSpec {
                command: self.launch.command.clone(),
                environment: self.launch.environment.clone().into_iter().collect(),
                policy: Some(self.policy.clone()),
                resource_requirements: attachments::gpu_count(&self.launch).map(|count| {
                    proto::ResourceRequirements {
                        gpu: Some(proto::GpuResourceRequirements { count: Some(count) }),
                    }
                }),
                template: Some(proto::SandboxTemplate {
                    image: self.launch.image.clone(),
                    resources: Some(resources),
                    // Validated in `new`; translation of admitted inputs only.
                    driver_config: attachments::public_driver_config(&self.launch)
                        .expect("validated attachments"),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    /// Used by ValidateSandboxCreate, before the gateway mints credentials.
    /// The extension resolves this binding through Fleet's current allocation;
    /// no user-provided node, driver options or labels select a destination.
    pub fn validate_proposal(&self, sandbox: &DriverSandbox) -> Result<()> {
        self.check_name(sandbox)?;
        NativeCreate::validate_proposal(sandbox, &self.launch, &self.policy_sha256)
    }

    /// Used by CreateSandbox. Preserve these exact protobuf bytes for the proof
    /// commitment and existing private delivery envelope; never log them.
    pub fn bind(&self, bytes: &[u8]) -> Result<NativeCreate> {
        let native = NativeCreate::decode(bytes, &self.launch, &self.policy_sha256)?;
        self.check_name(&native.sandbox)?;
        Ok(native)
    }

    fn check_name(&self, sandbox: &DriverSandbox) -> Result<()> {
        if sandbox.name != self.name {
            return Err(Error::Ownership);
        }
        Ok(())
    }
}
