//! Outbound native connectors owned by the persistent shim. The registration
//! authority must independently join gateway policy readiness with Fleet intent;
//! a successful local health probe does not authorize a route.
use crate::{
    data_plane::{self, NetworkConfig},
    openshell_lifecycle::ManagedNativeDriver,
    Error, Result,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use trusted_contracts::ExecutionIdentity;
use trusted_router_transport::grants::Verifier;

async fn probe(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    options: &crate::openshell_services::ServiceOptions,
) -> bool {
    if let Some(banner) = &options.health_tcp_banner {
        use tokio::io::AsyncReadExt;
        // No application credentials or commands are sent by this probe. A
        // closed/missing target or an SSH channel ACK is never readiness.
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            let mut bytes = vec![0; banner.len()];
            socket.read_exact(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes == banner.as_bytes())
        })
        .await
        .is_ok_and(|r| matches!(r, Ok(true)))
    } else {
        client
            .get(format!("http://{address}{}", options.health_path))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
    }
}

/// Local application health only. Never persisted and never derived from a
/// registration grant: Fleet must independently join central policy readiness.
#[derive(Default)]
pub(crate) struct Health(Mutex<Option<Instant>>);
impl Health {
    pub fn ready(&self) -> bool {
        self.0
            .lock()
            .is_ok_and(|v| v.is_some_and(|t| t.elapsed() < Duration::from_secs(6)))
    }
    fn mark(&self) {
        if let Ok(mut value) = self.0.lock() {
            *value = Some(Instant::now());
        }
    }
    fn clear(&self) {
        if let Ok(mut value) = self.0.lock() {
            *value = None;
        }
    }
}

pub(crate) async fn serve(
    driver: &ManagedNativeDriver,
    execution: &ExecutionIdentity,
    config: &NetworkConfig,
    supervisor_image: &str,
    stop: CancellationToken,
    health: Arc<Health>,
) -> Result<()> {
    data_plane::validate_config(config)?;
    loop {
        let result = serve_once(
            driver,
            execution,
            config,
            supervisor_image,
            stop.clone(),
            &health,
        )
        .await;
        if stop.is_cancelled() {
            return Ok(());
        }
        // Local health and driver outages can recover without a Ray process.
        // Ownership/tombstone/configuration failures require reconciliation.
        if matches!(
            result,
            Err(Error::Ownership | Error::Unsupported | Error::InvalidContract | Error::Untrusted)
        ) {
            return result;
        }
        tokio::select! { _ = stop.cancelled() => return Ok(()),
        _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
    }
}

async fn serve_once(
    driver: &ManagedNativeDriver,
    execution: &ExecutionIdentity,
    config: &NetworkConfig,
    supervisor_image: &str,
    stop: CancellationToken,
    application: &Health,
) -> Result<()> {
    application.clear();
    struct Reset<'a>(&'a Health);
    impl Drop for Reset<'_> {
        fn drop(&mut self) {
            self.0.clear();
        }
    }
    let _reset = Reset(application);
    let health_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|_| Error::Unavailable)?;
    let lease = driver.network_lease(execution).await?;
    let children = CancellationToken::new();
    let _cancel = children.clone().drop_guard();
    let sandbox = lease.sandbox.clone();
    let service = crate::openshell_network::bind(
        lease.sandbox,
        supervisor_image,
        &lease.binding.host_key_fingerprint,
        lease.binding.options.container_port,
        children.clone(),
    )
    .await?;
    let health = async {
        loop {
            if service.is_finished() {
                return Err(Error::Unavailable);
            }
            if probe(&health_client, service.address(), &lease.binding.options).await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };
    let ready = tokio::select! {
        _ = stop.cancelled() => Err(Error::Unavailable),
        _ = lease.fence.cancelled() => Err(Error::Ownership),
        ready = health => ready,
    };
    let mut tasks = tokio::task::JoinSet::new();
    let mut servers = Vec::new();
    let result = async {
        ready?;
        application.mark();
        let verifier = Verifier::from_file(config.public_key_file.clone(), config.issuer.clone())
            .map_err(|_| Error::InvalidContract)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::Unavailable)?;
        for spec in lease.binding.services {
            // Ingress rules and logs-only control sit in front of the same
            // supervisor-forwarded target; plain services reach it directly.
            let target = if spec.endpoint_ref == "app" {
                service.address()
            } else {
                let (target, server) = crate::management::bind_runtime(
                    crate::management::Runtime::Native(Box::new(crate::management::NativeTarget {
                        sandbox: sandbox.clone(),
                        journal: driver.invocation_journal(),
                    })),
                    execution.clone(),
                    spec.clone(),
                    verifier.clone(),
                    lease.binding.options.ingress.get(&spec.id.service).cloned(),
                    service.address(),
                    children.clone(),
                )
                .await?;
                servers.push(server);
                target
            };
            tasks.spawn(data_plane::connect_service(
                config.clone(),
                verifier.clone(),
                client.clone(),
                execution.clone(),
                spec,
                target,
                children.clone(),
            ));
        }
        // Local health loss closes active streams as well as future registration.
        let monitor = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if service.is_finished()
                    || !matches!(driver.inspect(execution).await, Ok(s) if s.platform_ready)
                    || !probe(&health_client, service.address(), &lease.binding.options).await
                {
                    return;
                }
                application.mark();
            }
        };
        tokio::select! {
            _ = stop.cancelled() => {}, _ = lease.fence.cancelled() => {},
            _ = monitor => {}, _ = tasks.join_next() => {},
        }
        Ok(())
    }
    .await;
    application.clear();
    children.cancel();
    while tasks.join_next().await.is_some() {}
    // Idle HTTP listeners too, before the shared target and lease are released.
    for server in servers {
        server.abort();
        let _ = server.await;
    }
    service.close().await;
    // Cleanup waits for this guard: transport shutdown precedes native deletion.
    drop(lease.fence);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn tcp_readiness_requires_application_banner_not_tunnel_accept() {
        use tokio::io::AsyncWriteExt;
        let client = reqwest::Client::new();
        let options = crate::openshell_services::ServiceOptions {
            container_port: 22,
            health_path: "/".into(),
            health_tcp_banner: Some("SSH-2.0-".into()),
            ingress: Default::default(),
        };
        // An accepted tunnel can subsequently close, return unrelated bytes,
        // or stall because the supervisor never connected to the workload.
        for (bytes, healthy) in [
            (b"SSH-2.0-test\r\n".as_slice(), true),
            (b"HTTP/1.1 200", false),
            (b"SSH-2.", false),
            (b"", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                connection.write_all(bytes).await.unwrap();
            });
            assert_eq!(probe(&client, address, &options).await, healthy);
            peer.await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        assert!(!probe(&client, address, &options).await);
        peer.abort();
    }
    #[test]
    fn health_requires_recent_probe_and_is_not_restored_from_disk() {
        let health = Health::default();
        assert!(!health.ready());
        health.mark();
        assert!(health.ready());
        *health.0.lock().unwrap() = Some(Instant::now() - Duration::from_secs(6));
        assert!(!health.ready());
        health.mark();
        health.clear();
        assert!(!health.ready());
    }
}
