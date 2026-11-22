//! Native execution inside the persistent shim daemon. Operator configuration
//! chooses the private driver and central ledger; launch envelopes cannot change
//! either endpoint. Credentials live only for a single accepted call.
use crate::{
    ledger_transport::RemoteLedger,
    openshell::{NativeCreate, NativeDriver},
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
}

pub(crate) struct OpenShellRuntime {
    pub driver: ManagedNativeDriver,
    pub configuration_sha256: String,
    endpoint: Endpoint,
}

impl OpenShellRuntime {
    pub fn open(state: &Path, node_id: String, config: OpenShellConfig) -> Result<Self> {
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
        })
    }

    pub async fn provision(&self, payload: ProvisionRequest) -> Result<ProvisioningStatus> {
        payload.validate()?;
        let native = NativeCreate::decode(
            &payload.native_bytes()?,
            &payload.request,
            &payload.native_policy_sha256,
        )?;
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
