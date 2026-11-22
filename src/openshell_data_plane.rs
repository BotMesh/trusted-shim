//! Outbound native connectors owned by the persistent shim. The registration
//! authority must independently join gateway policy readiness with Fleet intent;
//! a successful local health probe does not authorize a route.
use crate::{
    data_plane::{self, NetworkConfig},
    openshell_lifecycle::ManagedNativeDriver,
    Error, Result,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use trusted_contracts::ExecutionIdentity;
use trusted_router_transport::grants::Verifier;

pub(crate) async fn serve(
    driver: &ManagedNativeDriver,
    execution: &ExecutionIdentity,
    config: &NetworkConfig,
    supervisor_image: &str,
    stop: CancellationToken,
) -> Result<()> {
    data_plane::validate_config(config)?;
    loop {
        let result = serve_once(driver, execution, config, supervisor_image, stop.clone()).await;
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
) -> Result<()> {
    let health_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|_| Error::Unavailable)?;
    let lease = driver.network_lease(execution).await?;
    let children = CancellationToken::new();
    let _cancel = children.clone().drop_guard();
    let service = crate::openshell_network::bind(
        lease.sandbox,
        supervisor_image,
        &lease.binding.host_key_fingerprint,
        lease.binding.options.container_port,
        children.clone(),
    )
    .await?;
    let url = format!(
        "http://{}{}",
        service.address(),
        lease.binding.options.health_path
    );
    let health = async {
        loop {
            if service.is_finished() {
                return Err(Error::Unavailable);
            }
            if health_client
                .get(&url)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
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
    let result = async {
        ready?;
        let verifier = Verifier::from_file(config.public_key_file.clone(), config.issuer.clone())
            .map_err(|_| Error::InvalidContract)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::Unavailable)?;
        for spec in lease.binding.services {
            tasks.spawn(data_plane::connect_service(
                config.clone(),
                verifier.clone(),
                client.clone(),
                execution.clone(),
                spec,
                service.address(),
                children.clone(),
            ));
        }
        // Local health loss closes active streams as well as future registration.
        let monitor = async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if service.is_finished()
                    || !matches!(driver.inspect(execution).await, Ok(s) if s.platform_ready)
                    || !health_client
                        .get(&url)
                        .send()
                        .await
                        .is_ok_and(|r| r.status().is_success())
                {
                    return;
                }
            }
        };
        tokio::select! {
            _ = stop.cancelled() => {}, _ = lease.fence.cancelled() => {},
            _ = monitor => {}, _ = tasks.join_next() => {},
        }
        Ok(())
    }
    .await;
    children.cancel();
    while tasks.join_next().await.is_some() {}
    service.close().await;
    // Cleanup waits for this guard: transport shutdown precedes native deletion.
    drop(lease.fence);
    result
}
