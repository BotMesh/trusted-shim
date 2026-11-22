use axum::{
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use trusted_router_transport::{
    grants::{self, Grant, Purpose, Verifier, AUDIENCE},
    relay::Relay,
};
use trusted_shim::{
    contracts::{PolicyRef, ServiceId},
    data_plane::{self, NetworkConfig},
    docker::DockerDriver,
    runtime::{LaunchRequest, RuntimeDriver},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Docker and preloaded python:3.12-slim"]
async fn real_runtime_drains_network_before_releasing_its_port() {
    let temp = tempfile::tempdir().unwrap();
    let private = temp.path().join("key.pem");
    let public = temp.path().join("pub.pem");
    assert!(std::process::Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&private)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&private)
        .args(["-pubout", "-out"])
        .arg(&public)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(private).unwrap();
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
    let issuer = "test-gateway";
    let relay = Relay::new(
        Verifier::new(&std::fs::read(&public).unwrap(), issuer.into()).unwrap(),
        &temp.path().join("routes.db"),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let relay_task = tokio::spawn(relay.serve(listener));
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let suffix = temp.path().file_name().unwrap().to_string_lossy();
    let request: LaunchRequest = serde_json::from_value(json!({
        "execution":{"namespace":"film","workload":"comfy-test","allocation_id":suffix,"lease_id":"lease","generation":1,"node_id":"local-edge"},
        "driver":"docker","image":"python:3.12-slim","command":["python","-u","-c",
            "from http.server import BaseHTTPRequestHandler,HTTPServer\nimport time\nclass Handler(BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers()\n  try:\n   while True:\n    self.wfile.write(b'data: stream\\n\\n');self.wfile.flush();time.sleep(.05)\n  except (BrokenPipeError,ConnectionResetError): pass\n def log_message(self,*args): pass\nHTTPServer(('0.0.0.0',8080),Handler).serve_forever()"],
        "environment":{},"limits":{"cpu_millicores":250,"memory_bytes":134217728},
        "policy":{"issuer":"fleet","policy_id":"no-policy-claim","version":0,"sha256":""},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},
        "services":[{"id":{"namespace":"film","workload":"comfy-test","service":"http"},"protocol":"http1","endpoint_ref":"app"}],
        "driver_options":{"port":port,"container_port":8080,"stop_timeout_s":1}
    })).unwrap();
    let grant = Grant {
        iss: issuer.into(),
        aud: AUDIENCE.into(),
        sub: "film-owner".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Register,
        http_request: None,
        access: None,
        execution: request.execution.clone(),
        service: ServiceId {
            namespace: "film".into(),
            workload: "comfy-test".into(),
            service: "http".into(),
        },
        policy: PolicyRef {
            issuer: issuer.into(),
            policy_id: "service-access".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let token = grants::sign(&key, &grant).unwrap();
    let expected = json!({"execution":request.execution,"service":request.services[0]});
    let handler = move |headers: HeaderMap, Json(body): Json<serde_json::Value>| {
        let token = token.clone();
        let expected = expected.clone();
        async move {
            if headers.get("authorization").and_then(|v| v.to_str().ok())
                != Some("Bearer test-node-bootstrap")
                || body != expected
            {
                return Err(StatusCode::FORBIDDEN);
            }
            Ok(Json(json!({"token":token})))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();
    let gateway_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/v1/runtime/registration", post(handler)),
        )
        .await
        .unwrap();
    });
    let node_key = temp.path().join("node.token");
    std::fs::write(&node_key, "test-node-bootstrap").unwrap();
    std::fs::set_permissions(&node_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = NetworkConfig {
        gateway_url: format!("http://{gateway_addr}"),
        relay_url: format!("ws://{relay_addr}"),
        token_file: node_key,
        public_key_file: public,
        issuer: issuer.into(),
    };
    let driver =
        Arc::new(DockerDriver::new(temp.path().join("state"), "local-edge".into()).unwrap());
    let status = driver.launch(&request).await.unwrap();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .output();
        }
    }
    let _cleanup = Cleanup(status.runtime_id);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    for _ in 0..80 {
        if http
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let execution = request.execution.clone();
    let node_driver = driver.clone();
    let network = tokio::spawn(async move {
        data_plane::serve(&node_driver, &execution, &config, CancellationToken::new()).await
    });
    let access = grants::sign(
        &key,
        &Grant {
            purpose: Purpose::Access,
            http_request: None,
            access: None,
            ..grant.clone()
        },
    )
    .unwrap();
    let url = format!("http://{relay_addr}/v1/http/{}/", grant.route_id());
    let mut response = None;
    for _ in 0..80 {
        if let Ok(r) = http
            .get(&url)
            .header("x-trusted-access", &access)
            .send()
            .await
        {
            if r.status() == 200 {
                response = Some(r);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut response = response.expect("route became live");
    assert!(response
        .chunk()
        .await
        .unwrap()
        .unwrap()
        .starts_with(b"data: stream"));
    driver.delete(&request.execution).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), network)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(driver.network_lease(&request.execution).await.is_err());
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Ok(Some(_)) = response.chunk().await {}
    })
    .await
    .unwrap();
    let _reused = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    assert_eq!(
        http.get(&url)
            .header("x-trusted-access", &access)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    relay_task.abort();
    gateway_task.abort();
}
