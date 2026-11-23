//! Admitted native service targets. This metadata is part of the launch proof,
//! not a destination selected by the router or by a later network command.
use crate::{openshell::NativeCreate, runtime::LaunchRequest, Error, Result};
use serde::{Deserialize, Serialize};
use trusted_data_router::{Protocol, ServiceSpec};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOptions {
    pub container_port: u16,
    pub health_path: String,
    /// Required for TCP: confirm application bytes, not just the local tunnel's
    /// accept. Stock supervisor SSH acknowledges channels before target connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_tcp_banner: Option<String>,
}

impl ServiceOptions {
    /// All services share one target and protocol. TCP services must supply an
    /// application banner (for SSH, `SSH-2.0-`) as their readiness check.
    pub fn from_request(request: &LaunchRequest) -> Result<Option<Self>> {
        if request.services.is_empty() {
            return if request.driver_options.is_null() {
                Ok(None)
            } else {
                Err(Error::Unsupported)
            };
        }
        let value: Self = serde_json::from_value(request.driver_options.clone())
            .map_err(|_| Error::InvalidContract)?;
        let protocol = &request.services[0].protocol;
        let health_valid = match protocol {
            Protocol::Http1 => value.health_tcp_banner.is_none(),
            Protocol::Tcp => {
                value.health_path == "/"
                    && value.health_tcp_banner.as_ref().is_some_and(|s| {
                        !s.is_empty()
                            && s.len() <= 128
                            && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                    })
            }
            _ => false,
        };
        let mut names = std::collections::HashSet::new();
        if !health_valid
            || value.container_port == 0
            || !value.health_path.starts_with('/')
            || value.health_path.starts_with("//")
            || value.health_path.len() > 2048
            || value
                .health_path
                .bytes()
                .any(|b| b.is_ascii_control() || b == b'\\' || b == b'#')
            || request.services.len() > 8
            || request.services.iter().any(|s| {
                s.id.namespace != request.execution.namespace
                    || s.id.workload != request.execution.workload
                    || s.endpoint_ref != "app"
                    || &s.protocol != protocol
                    || s.id.service == "control"
                    || s.id.service.is_empty()
                    || s.id.service.len() > 64
                    || !s
                        .id
                        .service
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    || !names.insert(&s.id.service)
            })
        {
            return Err(Error::InvalidContract);
        }
        Ok(Some(value))
    }
}

/// Stored with the exact allocation. Contains public identity only; never the
/// native auth bundle, host private key, environment or application credentials.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdmittedServices {
    pub options: ServiceOptions,
    pub services: Vec<ServiceSpec>,
    pub host_key_fingerprint: String,
}

impl AdmittedServices {
    pub fn prepare(request: &LaunchRequest, native: &NativeCreate) -> Result<Option<Self>> {
        let Some(options) = ServiceOptions::from_request(request)? else {
            return Ok(None);
        };
        let auth: openshell_core::jwt::SandboxLaunchAuthentication = serde_json::from_slice(
            &native
                .sandbox
                .spec
                .as_ref()
                .ok_or(Error::InvalidContract)?
                .launch_authentication,
        )
        .map_err(|_| Error::Untrusted)?;
        auth.validate().map_err(|_| Error::Untrusted)?;
        let private = auth
            .supervisor
            .ssh_host_private_key
            .as_ref()
            .ok_or(Error::Untrusted)?;
        let key = russh::keys::decode_secret_key(private.expose_secret(), None)
            .map_err(|_| Error::Untrusted)?;
        Ok(Some(Self {
            options,
            services: request.services.clone(),
            host_key_fingerprint: key
                .public_key()
                .fingerprint(russh::keys::HashAlg::Sha256)
                .to_string(),
        }))
    }
}

pub(crate) struct NativeNetworkLease {
    pub fence: crate::data_plane::NetworkFence,
    pub sandbox: openshell_core::proto::compute::v1::DriverSandbox,
    pub binding: AdmittedServices,
}
