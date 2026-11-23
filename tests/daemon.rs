use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tokio_util::sync::CancellationToken;

async fn call(path: &Path, request: Value) -> Value {
    let mut stream = UnixStream::connect(path).await.unwrap();
    stream
        .write_all(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn one_shot_runtime_advertises_the_cpu_weight() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_trusted-shim-runtime"))
        .arg("--capabilities")
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["features"]
        .as_array()
        .unwrap()
        .contains(&json!("runtime-cpu-shares-v1")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_protocol_survives_clients_and_rejects_incompatible_takeover() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let socket = state.join("control.sock");
    let stop = CancellationToken::new();
    let daemon_stop = stop.clone();
    let daemon_state = state.clone();
    let daemon = tokio::spawn(async move {
        trusted_shim::daemon::serve(&daemon_state, "node-one".into(), daemon_stop).await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let request = json!({"protocol":1,"node_id":"node-one","command":{"operation":"capabilities"}});
    let before = call(&socket, request.clone()).await;
    assert_eq!(before["result"]["protocol"], 1);
    // Fleet resumes a crashed runtime only where the daemon advertises it.
    assert!(before["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("runtime-resume-v1")));
    // Fleet sends limits.cpu_shares only where the daemon advertises it.
    assert!(before["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("runtime-cpu-shares-v1")));
    // TEE resume is advertised separately, and only by a node with a TEE driver;
    // this one has none, so it refuses a TEE resume.
    assert!(!before["result"]["features"]
        .as_array()
        .unwrap()
        .contains(&json!("runtime-resume-tee-v1")));
    let tee_resume = json!({"protocol":1,"node_id":"node-one","command":{"operation":"resume",
        "execution":{"namespace":"test","workload":"daemon","allocation_id":"tee","lease_id":"one",
            "generation":1,"node_id":"node-one"},"driver":"tee"}});
    assert!(call(&socket, tee_resume).await.get("error").is_some());
    assert!(
        trusted_shim::daemon::serve(&state, "node-one".into(), CancellationToken::new())
            .await
            .is_err()
    );
    // A failed second daemon must not unlink the first daemon's socket.
    assert_eq!(call(&socket, request.clone()).await, before);
    for invalid in [
        json!({"protocol":2,"node_id":"node-one","command":{"operation":"capabilities"}}),
        json!({"protocol":1,"node_id":"other-node","command":{"operation":"capabilities"}}),
        json!({"protocol":1,"node_id":"node-one","command":{"operation":"shell","command":"false"}}),
    ] {
        assert!(call(&socket, invalid).await.get("error").is_some());
    }
    // A client can exit halfway through a request without terminating workers.
    let mut broken = UnixStream::connect(&socket).await.unwrap();
    broken.write_all(b"{\"protocol\":").await.unwrap();
    drop(broken);
    assert_eq!(call(&socket, request).await, before);
    stop.cancel();
    daemon.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local Docker and preloaded alpine:3.21"]
async fn disconnected_client_and_daemon_restart_do_not_restart_the_container() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let socket = state.join("control.sock");
    let stop = CancellationToken::new();
    let daemon_stop = stop.clone();
    let daemon_state = state.clone();
    let daemon = tokio::spawn(async move {
        trusted_shim::daemon::serve(&daemon_state, "node-one".into(), daemon_stop).await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let execution = json!({"namespace":"test","workload":"daemon","allocation_id":root.path().file_name().unwrap().to_str().unwrap(),
        "lease_id":"one","generation":1,"node_id":"node-one"});
    let envelope = |command| json!({"protocol":1,"node_id":"node-one","command":command});
    let launch = envelope(json!({"operation":"launch","request":{
        "execution":execution,"driver":"docker","image":"alpine:3.21","command":["sleep","300"],"environment":{},
        "limits":{"cpu_millicores":250,"memory_bytes":33554432},
        "policy":{"issuer":"test","policy_id":"no-policy-claim","version":0,"sha256":""},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},
        "services":[],"driver_options":{"stop_timeout_s":1}}}));
    let mut client = UnixStream::connect(&socket).await.unwrap();
    client
        .write_all(&serde_json::to_vec(&launch).unwrap())
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    drop(client);
    let inspect = envelope(json!({"operation":"inspect","execution":execution}));
    let mut status = Value::Null;
    for _ in 0..100 {
        status = call(&socket, inspect.clone()).await;
        if status["result"]["state"] == "ready" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(status["result"]["state"], "ready");
    let name = status["result"]["runtime_id"].as_str().unwrap().to_owned();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .output();
        }
    }
    let _cleanup = Cleanup(name.clone());
    let snapshot = || {
        let output = std::process::Command::new("docker")
            .args(["inspect", &name])
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&output.stdout).unwrap()[0]["State"].clone()
    };
    let before = snapshot();
    stop.cancel();
    daemon.await.unwrap().unwrap();
    assert_eq!(snapshot(), before);
    let stop = CancellationToken::new();
    let daemon_stop = stop.clone();
    let daemon = tokio::spawn(async move {
        trusted_shim::daemon::serve(&state, "node-one".into(), daemon_stop).await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(call(&socket, launch).await, status);
    assert_eq!(snapshot(), before);
    // Only the supervisor's explicit resume brings a crashed runtime back.
    let resume = envelope(json!({"operation":"resume","execution":execution}));
    assert_eq!(
        call(&socket, resume.clone()).await["result"]["state"],
        "ready"
    );
    assert_eq!(snapshot(), before);
    assert!(std::process::Command::new("docker")
        .args(["kill", &name])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        call(&socket, inspect.clone()).await["result"]["state"],
        "stopped"
    );
    assert_eq!(
        call(&socket, resume.clone()).await["result"]["state"],
        "ready"
    );
    assert_eq!(snapshot()["Running"], true);
    assert_eq!(
        call(
            &socket,
            envelope(json!({"operation":"stop","execution":execution}))
        )
        .await["result"]["stopped"],
        true
    );
    assert!(call(&socket, resume).await.get("error").is_some());
    assert_eq!(snapshot()["Running"], false);
    assert_eq!(
        call(
            &socket,
            envelope(json!({"operation":"delete","execution":execution}))
        )
        .await["result"]["cleaned"],
        true
    );
    stop.cancel();
    daemon.await.unwrap().unwrap();
}
