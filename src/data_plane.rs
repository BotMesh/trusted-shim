//! Per-allocation connector ownership. The runtime's persisted service map is
//! authoritative; a gateway response cannot redirect the local target.
use crate::{
    contracts::ExecutionIdentity,
    docker::DockerDriver,
    runtime::{RuntimeDriver, RuntimeState},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use trusted_data_router::ServiceSpec;
use trusted_router_transport::{
    edge,
    grants::{self, Purpose, Verifier},
};

/// Node-owned settings inside Fleet's existing apps.yaml, never agent input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub gateway_url: String,
    pub relay_url: String,
    pub token_file: PathBuf,
    pub public_key_file: PathBuf,
    pub issuer: String,
}

pub(crate) fn validate_config(config: &NetworkConfig) -> Result<()> {
    endpoint(&config.gateway_url, "https", "http")?;
    endpoint(&config.relay_url, "wss", "ws")?;
    Verifier::from_file(config.public_key_file.clone(), config.issuer.clone())
        .map_err(|_| Error::InvalidContract)?;
    read_private(&config.token_file)?;
    Ok(())
}

pub struct NetworkLease {
    pub(crate) _file: File,
    pub(crate) closed: PathBuf,
    pub(crate) services: Vec<ServiceSpec>,
    pub(crate) target: SocketAddr,
    pub(crate) ingress: std::collections::BTreeMap<String, crate::management::Ingress>,
}
impl NetworkLease {
    async fn cancelled(&self) {
        loop {
            // An unreadable fence is also a reason to close network access.
            if !matches!(self.closed.try_exists(), Ok(false)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn read_private(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(Error::InvalidContract);
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| Error::Unavailable)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() > 16384 {
        return Err(Error::InvalidContract);
    }
    let value = std::fs::read_to_string(path).map_err(|_| Error::Unavailable)?;
    let token = value.trim();
    if token.is_empty() || token.contains(['\r', '\n']) {
        return Err(Error::InvalidContract);
    }
    Ok(token.to_owned())
}

fn endpoint(value: &str, secure: &str, local: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| Error::InvalidContract)?;
    if url.scheme() != secure
        && !(url.scheme() == local && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::InvalidContract);
    }
    Ok(url)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    token: String,
}

async fn grant(
    config: &NetworkConfig,
    verifier: &Verifier,
    client: &reqwest::Client,
    execution: &ExecutionIdentity,
    service: &ServiceSpec,
) -> Result<(String, String, u64)> {
    let mut response = client
        .post(format!(
            "{}/v1/runtime/registration",
            config.gateway_url.trim_end_matches('/')
        ))
        .bearer_auth(read_private(&config.token_file)?)
        .json(&serde_json::json!({"execution": execution, "service": service}))
        .send()
        .await
        .map_err(|_| Error::Unavailable)?;
    if !response.status().is_success() {
        return Err(Error::Untrusted);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
        if bytes.len() + chunk.len() > 16384 {
            return Err(Error::Untrusted);
        }
        bytes.extend_from_slice(&chunk);
    }
    let registration: Registration =
        serde_json::from_slice(&bytes).map_err(|_| Error::Untrusted)?;
    let permit = verifier
        .verify(&registration.token, Purpose::Register)
        .map_err(|_| Error::Untrusted)?;
    if &permit.execution != execution
        || permit.service != service.id
        || permit.exp <= grants::now() + 15
    {
        return Err(Error::Untrusted);
    }
    Ok((
        format!(
            "{}/v1/connect/{}",
            config.relay_url.trim_end_matches('/'),
            permit.route_id()
        ),
        registration.token,
        permit.exp,
    ))
}

// Refresh the registration lease on the existing transport. Access grants on
// individual application streams keep their own expiry/revocation semantics.
async fn renew_registration(
    config: &NetworkConfig,
    verifier: &Verifier,
    client: &reqwest::Client,
    execution: &ExecutionIdentity,
    service: &ServiceSpec,
    connection_url: &str,
    mut expires_at: u64,
) {
    let mut renew_url = match reqwest::Url::parse(connection_url) {
        Ok(url) => url,
        Err(_) => return,
    };
    let scheme = if renew_url.scheme() == "wss" {
        "https"
    } else {
        "http"
    };
    if renew_url.set_scheme(scheme).is_err() {
        return;
    }
    renew_url.set_path(&format!("{}/renew", renew_url.path()));
    let mut delay = (expires_at.saturating_sub(grants::now()) / 2).clamp(1, 30);
    loop {
        let remaining = expires_at.saturating_sub(grants::now());
        if remaining == 0 {
            return;
        }
        let attempt = async {
            tokio::time::sleep(Duration::from_secs(delay)).await;
            let (url, token, next_expiry) =
                grant(config, verifier, client, execution, service).await?;
            if url != connection_url {
                return Err(Error::Untrusted);
            }
            let response = client
                .post(renew_url.clone())
                .bearer_auth(token)
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if response.status() != reqwest::StatusCode::NO_CONTENT {
                return Err(Error::Untrusted);
            }
            Ok(next_expiry)
        };
        match tokio::time::timeout(Duration::from_secs(remaining), attempt).await {
            Ok(Ok(next)) => {
                expires_at = expires_at.max(next);
                delay = (expires_at.saturating_sub(grants::now()) / 2).clamp(1, 30);
            }
            Ok(Err(_)) => delay = 1,
            Err(_) => return,
        }
    }
}

/// Blocks for this allocation's lifetime. The supervisor may restart the
/// connector, but cannot restart or substitute a missing/stopped runtime.
pub async fn serve(
    driver: &DockerDriver,
    execution: &ExecutionIdentity,
    config: &NetworkConfig,
    stop: CancellationToken,
) -> Result<()> {
    endpoint(&config.gateway_url, "https", "http")?;
    endpoint(&config.relay_url, "wss", "ws")?;
    let verifier = Verifier::from_file(config.public_key_file.clone(), config.issuer.clone())
        .map_err(|_| Error::InvalidContract)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| Error::Unavailable)?;
    let lease = driver.network_lease(execution).await?;
    let mut tasks = tokio::task::JoinSet::new();
    let children = CancellationToken::new();
    let _cancel_on_error = children.clone().drop_guard();
    let mut servers = Vec::new();
    for service in lease.services.clone() {
        let config = config.clone();
        let verifier = verifier.clone();
        let client = client.clone();
        let execution = execution.clone();
        let target = if service.endpoint_ref == "app" {
            lease.target
        } else {
            let (target, server) = crate::management::bind(
                driver.clone(),
                execution.clone(),
                service.clone(),
                verifier.clone(),
                lease.ingress.get(&service.id.service).cloned(),
                lease.target,
                children.clone(),
            )
            .await?;
            servers.push(server);
            target
        };
        let shutdown = children.clone();
        tasks.spawn(async move {
            let mut backoff = 1;
            loop {
                let registration = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    registration = grant(&config, &verifier, &client, &execution, &service) => registration,
                };
                if let Ok((url, token, exp)) = registration
                {
                    let started = tokio::time::Instant::now();
                    let active_stop = CancellationToken::new();
                    let active = edge::connect(&url, &token, target, active_stop.clone());
                    tokio::pin!(active);
                    tokio::select! {
                        _ = &mut active => {},
                        _ = shutdown.cancelled() => { active_stop.cancel(); let _ = active.await; return; },
                        _ = renew_registration(&config, &verifier, &client, &execution, &service, &url, exp) => {
                            active_stop.cancel(); let _ = active.await;
                        },
                    }
                    if started.elapsed() > Duration::from_secs(30) {
                        backoff = 1;
                    }
                }
                tokio::select! { _ = shutdown.cancelled() => return, _ = tokio::time::sleep(Duration::from_secs(backoff)) => {} }
                backoff = (backoff * 2).min(30);
            }
        });
    }
    let monitor = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if !matches!(driver.inspect(execution).await, Ok(status) if status.state == RuntimeState::Ready)
            {
                return;
            }
        }
    };
    tokio::select! { _ = stop.cancelled() => {}, _ = lease.cancelled() => {}, _ = monitor => {}, _ = tasks.join_next() => {} }
    children.cancel();
    while tasks.join_next().await.is_some() {}
    // Transport streams are closed before releasing the port. Cancel idle HTTP
    // servers too; lifecycle ownership locks fence any queued administration.
    for server in servers {
        server.abort();
        let _ = server.await;
    }
    // Only now can cleanup acquire the network lock and reassign the host port.
    drop(lease);
    Ok(())
}
