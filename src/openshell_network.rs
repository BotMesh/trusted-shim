//! Machine-local application access through the stock supervisor's SSH API.
//!
//! Callers supply an owned native observation, the gateway's public host-key
//! fingerprint, and an operator-pinned supervisor image. Only the selected
//! workload loopback port is forwarded. No gateway RPC carries application bytes.
//! Route admission and application readiness remain the caller's responsibility.
use crate::{Error, Result};
use openshell_core::{driver_utils::*, proto::compute::v1::DriverSandbox};
use russh::{
    client,
    keys::{HashAlg, PublicKeyOrCertificate},
};
use serde_json::Value;
use std::{net::SocketAddr, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    process::{Child, Command},
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;

const ROLE: &str = "openshell.ai/isolation-role";
const TIMEOUT: Duration = Duration::from_secs(10);
const HELPER: &str = "/opt/trusted-shim/socket";

fn docker() -> Command {
    let mut command = Command::new("/usr/bin/docker");
    // No remote Docker context or inherited client credentials can redirect this
    // adapter. All targets belong to the machine-local native driver.
    command
        .args(["--host", "unix:///var/run/docker.sock"])
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .kill_on_drop(true);
    command
}

async fn output(args: &[&str]) -> Result<Vec<u8>> {
    let mut child = docker()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    tokio::time::timeout(TIMEOUT, async {
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or(Error::Unavailable)?
            .take(65537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| Error::Unavailable)?;
        if bytes.len() > 65536
            || !child
                .wait()
                .await
                .map_err(|_| Error::Unavailable)?
                .success()
        {
            return Err(Error::Unavailable);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| Error::Unavailable)?
}

fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_target(sandbox: &DriverSandbox, image: &str, fingerprint: &str, port: u16) -> Result<()> {
    let status = sandbox.status.as_ref().ok_or(Error::Ownership)?;
    if port == 0
        || !image.strip_prefix("sha256:").is_some_and(id)
        || !fingerprint.strip_prefix("SHA256:").is_some_and(|v| {
            use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
            STANDARD_NO_PAD
                .decode(v)
                .is_ok_and(|bytes| bytes.len() == 32)
        })
    {
        return Err(Error::InvalidContract);
    }
    if !id(&status.instance_id)
        || status.deleting
        || !status
            .conditions
            .iter()
            .any(|c| c.r#type == "Ready" && c.status == "True")
        || [
            &sandbox.id,
            &sandbox.name,
            &sandbox.namespace,
            &sandbox.workspace,
        ]
        .iter()
        .any(|v| v.is_empty() || v.len() > 256 || v.contains(['\0', '\n', '\r']))
    {
        return Err(Error::Ownership);
    }
    Ok(())
}

async fn inspect(container: &str) -> Result<Value> {
    if !id(container) {
        return Err(Error::Ownership);
    }
    // Never collect environment, command, mounts or native authentication files.
    let bytes = output(&["inspect", "--type", "container", "--format",
        r#"{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"readonly":{{json .HostConfig.ReadonlyRootfs}}}"#,
        container]).await?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)
}

fn owned(value: &Value, sandbox: &DriverSandbox, role: &str) -> Result<()> {
    let labels = &value["labels"];
    if value["running"] != true
        || labels[LABEL_MANAGED_BY] != LABEL_MANAGED_BY_VALUE
        || labels[LABEL_SANDBOX_ID] != sandbox.id
        || labels[LABEL_SANDBOX_NAME] != sandbox.name
        || labels[LABEL_SANDBOX_NAMESPACE] != sandbox.namespace
        || labels[ROLE] != role
        || (role == "sandbox"
            && (labels[LABEL_SANDBOX_WORKSPACE] != sandbox.workspace
                || value["id"] != sandbox.status.as_ref().ok_or(Error::Ownership)?.instance_id))
    {
        return Err(Error::Ownership);
    }
    Ok(())
}

async fn supervisor(sandbox: &DriverSandbox, image: &str) -> Result<String> {
    let workload = &sandbox.status.as_ref().ok_or(Error::Ownership)?.instance_id;
    owned(&inspect(workload).await?, sandbox, "sandbox")?;
    let filters = [
        format!("label={LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}"),
        format!("label={LABEL_SANDBOX_ID}={}", sandbox.id),
        format!("label={LABEL_SANDBOX_NAMESPACE}={}", sandbox.namespace),
        format!("label={ROLE}=supervisor"),
    ];
    let mut args = vec!["ps", "-q", "--no-trunc"];
    for filter in &filters {
        args.extend(["--filter", filter]);
    }
    let bytes = output(&args).await?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Unavailable)?;
    let ids: Vec<_> = text.split_whitespace().collect();
    let [container] = ids.as_slice() else {
        return Err(Error::Ownership);
    };
    let value = inspect(container).await?;
    owned(&value, sandbox, "supervisor")?;
    if value["image"] != image || value["readonly"] != true {
        return Err(Error::Untrusted);
    }
    Ok((*container).to_owned())
}

struct HostKey(String);
impl client::Handler for HostKey {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. }
            if key.fingerprint(HashAlg::Sha256).to_string() == self.0))
    }
}

/// Private loopback endpoint for the existing outbound Data Router connector.
/// Drop or cancellation closes every active stream and the local SSH transport.
/// No host port is published by Docker, and workload networking remains untouched.
pub struct LocalService {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    stop: CancellationToken,
}
impl LocalService {
    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
    pub async fn close(mut self) {
        self.stop.cancel();
        let _ = (&mut self.task).await;
    }
}
impl Drop for LocalService {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// Privileged adapter API; never expose its parameters directly to app clients.
/// `sandbox` must be the fresh native observation for the full owned allocation;
/// fingerprint comes from that sandbox's authenticated gateway control response.
/// The port comes from the admitted local service map, never a router token.
pub async fn bind(
    sandbox: DriverSandbox,
    supervisor_image: &str,
    host_key_fingerprint: &str,
    port: u16,
    stop: CancellationToken,
) -> Result<LocalService> {
    valid_target(&sandbox, supervisor_image, host_key_fingerprint, port)?;
    // Closing one endpoint must not cancel siblings sharing the caller's token.
    let stop = stop.child_token();
    if stop.is_cancelled() {
        return Err(Error::Unavailable);
    }
    let container = supervisor(&sandbox, supervisor_image).await?;
    let mut child = docker()
        .args(["exec", "-i", &container, HELPER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    let io = tokio::io::join(
        child.stdout.take().ok_or(Error::Unavailable)?,
        child.stdin.take().ok_or(Error::Unavailable)?,
    );
    let config = client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 2,
        ..Default::default()
    };
    let session = tokio::time::timeout(TIMEOUT, async {
        let mut session =
            client::connect_stream(Arc::new(config), io, HostKey(host_key_fingerprint.into()))
                .await
                .map_err(|_| Error::Untrusted)?;
        // The native server authenticates this private Docker/Unix path. Agent
        // users never receive the SSH socket, Docker API or an SSH session.
        if !session
            .authenticate_none("shim")
            .await
            .map_err(|_| Error::Untrusted)?
            .success()
        {
            return Err(Error::Untrusted);
        }
        Ok(session)
    })
    .await
    .map_err(|_| Error::Unavailable)??;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| Error::Unavailable)?;
    let address = listener.local_addr().map_err(|_| Error::Unavailable)?;
    let image = supervisor_image.to_owned();
    let task = tokio::spawn(serve(
        listener,
        Arc::new(session),
        child,
        sandbox,
        container,
        image,
        port,
        stop.clone(),
    ));
    Ok(LocalService {
        address,
        task,
        stop,
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    listener: TcpListener,
    session: Arc<client::Handle<HostKey>>,
    mut child: Child,
    sandbox: DriverSandbox,
    container: String,
    image: String,
    port: u16,
    stop: CancellationToken,
) {
    let mut tasks = tokio::task::JoinSet::new();
    let slots = Arc::new(Semaphore::new(256));
    let monitor = async {
        loop {
            if session.is_closed()
                || !matches!(supervisor(&sandbox, &image).await, Ok(id) if id == container)
            {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    };
    tokio::pin!(monitor);
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            _ = child.wait() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            _ = &mut monitor => break,
            accepted = listener.accept() => {
                let Ok((mut tcp, _)) = accepted else { break };
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                let session = session.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    if let Ok(Ok(channel)) = tokio::time::timeout(TIMEOUT,
                        session.channel_open_direct_tcpip("127.0.0.1", u32::from(port), "127.0.0.1", 0)).await {
                        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut channel.into_stream()).await;
                    }
                });
            },
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let _ = child.kill().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::compute::v1::{DriverCondition, DriverSandboxStatus};
    use serde_json::json;

    fn fixture() -> DriverSandbox {
        DriverSandbox {
            id: "sandbox-1".into(),
            name: "agent-1".into(),
            namespace: "driver-1".into(),
            workspace: "tenant-1".into(),
            status: Some(DriverSandboxStatus {
                instance_id: "a".repeat(64),
                conditions: vec![DriverCondition {
                    r#type: "Ready".into(),
                    status: "True".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn local_target_requires_ready_immutable_instance_image_and_host_key() {
        let sandbox = fixture();
        let image = format!("sha256:{}", "b".repeat(64));
        let key = format!("SHA256:{}", "A".repeat(43));
        valid_target(&sandbox, &image, &key, 8090).unwrap();
        for (image, key, port) in [
            ("supervisor:latest", key.as_str(), 8090),
            (image.as_str(), "", 8090),
            (image.as_str(), "SHA256:invalid", 8090),
            (image.as_str(), key.as_str(), 0),
        ] {
            assert!(valid_target(&sandbox, image, key, port).is_err());
        }
        for mutate in 0..5 {
            let mut changed = sandbox.clone();
            match mutate {
                0 => changed.status.as_mut().unwrap().instance_id = "container-name".into(),
                1 => changed.status.as_mut().unwrap().deleting = true,
                2 => changed.status.as_mut().unwrap().conditions[0].status = "False".into(),
                3 => changed.workspace.clear(),
                _ => changed.namespace.push('\n'),
            }
            assert!(valid_target(&changed, &image, &key, 8090).is_err());
        }
    }

    #[test]
    fn native_identity_binds_workspace_role_driver_and_exact_container() {
        let sandbox = fixture();
        let value = json!({"id":"a".repeat(64), "running":true, "labels":{
            LABEL_MANAGED_BY: LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID: sandbox.id,
            LABEL_SANDBOX_NAME: sandbox.name, LABEL_SANDBOX_NAMESPACE: sandbox.namespace,
            LABEL_SANDBOX_WORKSPACE: sandbox.workspace, ROLE:"sandbox"
        }});
        owned(&value, &sandbox, "sandbox").unwrap();
        for label in [
            LABEL_MANAGED_BY,
            LABEL_SANDBOX_ID,
            LABEL_SANDBOX_NAME,
            LABEL_SANDBOX_NAMESPACE,
            LABEL_SANDBOX_WORKSPACE,
            ROLE,
        ] {
            let mut foreign = value.clone();
            foreign["labels"][label] = json!("other");
            assert!(owned(&foreign, &sandbox, "sandbox").is_err());
        }
        let mut replaced = value.clone();
        replaced["id"] = json!("b".repeat(64));
        assert!(owned(&replaced, &sandbox, "sandbox").is_err());
        let mut stopped = value;
        stopped["running"] = json!(false);
        assert!(owned(&stopped, &sandbox, "sandbox").is_err());
    }
}
