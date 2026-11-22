//! Native execution inside the persistent shim daemon. Operator configuration
//! chooses the private driver and central ledger; launch envelopes cannot change
//! either endpoint. Credentials live only for a single accepted call.
use crate::{
    ledger_transport::RemoteLedger,
    openshell::NativeDriver,
    openshell_lifecycle::{ManagedNativeDriver, ProvisioningStatus},
    provisioning::ProvisionRequest,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

/// Populated from the node's existing runtime configuration, not a new file.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenShellConfig {
    pub socket: PathBuf,
    pub admission_policy: String,
    pub ledger_endpoint: String,
    #[serde(default)]
    pub ledger_ca_file: Option<PathBuf>,
    /// Immutable local Docker image ID of the supervisor containing the socket
    /// helper. Omit to retain provisioning-only operation and its config digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_image: Option<String>,
}

pub(crate) struct OpenShellRuntime {
    pub driver: ManagedNativeDriver,
    pub configuration_sha256: String,
    endpoint: Endpoint,
    pub supervisor_image: Option<String>,
}

impl OpenShellRuntime {
    pub fn open(state: &Path, node_id: String, config: OpenShellConfig) -> Result<Self> {
        if config.supervisor_image.as_ref().is_some_and(|s| {
            !s.strip_prefix("sha256:").is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        }) {
            return Err(Error::InvalidContract);
        }
        use sha2::{Digest, Sha256};
        let value = serde_json::to_value(&config).map_err(|_| Error::InvalidContract)?;
        let configuration_sha256 = hex::encode(Sha256::digest(
            trusted_rail::rego::canonical_bytes(&value).map_err(|_| Error::InvalidContract)?,
        ));
        let mut endpoint =
            RemoteLedger::endpoint(&config.ledger_endpoint).map_err(|_| Error::InvalidContract)?;
        if let Some(path) = config.ledger_ca_file {
            if !path.is_absolute() || !config.ledger_endpoint.starts_with("https://") {
                return Err(Error::InvalidContract);
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| Error::Unavailable)?;
            let m = file.metadata().map_err(|_| Error::Unavailable)?;
            if !m.is_file()
                || ![0, unsafe { libc::geteuid() }].contains(&m.uid())
                || m.permissions().mode() & 0o022 != 0
            {
                return Err(Error::Untrusted);
            }
            let mut pem = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut pem)
                .map_err(|_| Error::Unavailable)?;
            if pem.is_empty() || pem.len() > 1024 * 1024 {
                return Err(Error::InvalidContract);
            }
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem)))
                .map_err(|_| Error::InvalidContract)?;
        }
        let native = NativeDriver::new(config.socket, config.admission_policy)?;
        Ok(Self {
            driver: ManagedNativeDriver::open(state.to_owned(), node_id, native)?,
            endpoint,
            configuration_sha256,
            supervisor_image: config.supervisor_image,
        })
    }

    pub async fn provision(&self, payload: ProvisionRequest) -> Result<ProvisioningStatus> {
        if !payload.request.services.is_empty() && self.supervisor_image.is_none() {
            return Err(Error::Unsupported);
        }
        let native = payload.validate_native()?;
        // A lazy channel leaves idempotent inspection/cleanup independent of a
        // gateway outage. First-time dispatch still requires successful Consume.
        let ledger = RemoteLedger::from_channel(
            self.endpoint.connect_lazy(),
            &payload.ledger_token,
            payload.request.execution.clone(),
        )
        .map_err(|_| Error::Untrusted)?;
        self.driver
            .launch(
                &payload.request,
                native,
                &payload.authorization,
                &payload.grant()?,
                &ledger,
            )
            .await
    }
}
