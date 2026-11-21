use base64::Engine as _;
use serde_json::json;
use std::{process::Command, time::Duration};
use tokio_util::sync::CancellationToken;
use trusted_router_transport::grants::{self, Grant, Purpose, Verifier};
use trusted_shim::{
    contracts::PolicyRef,
    docker::DockerDriver,
    management,
    runtime::{LaunchRequest, RuntimeDriver},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Docker and preloaded python:3.12-slim"]
async fn exact_allocation_administration_and_native_credential_ingress() {
    let tmp = tempfile::tempdir().unwrap();
    let keyfile = tmp.path().join("key");
    let public = tmp.path().join("public");
    assert!(Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&keyfile)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&keyfile)
        .args(["-pubout", "-out"])
        .arg(&public)
        .status()
        .unwrap()
        .success());
    let key = std::fs::read(keyfile).unwrap();
    let verifier = Verifier::new(&std::fs::read(public).unwrap(), "test".into()).unwrap();
    let request:LaunchRequest=serde_json::from_value(json!({
        "execution":{"namespace":"clawup","workload":"agent-test","allocation_id":tmp.path().file_name().unwrap().to_string_lossy(),"lease_id":"lease","generation":1,"node_id":"local"},
        "driver":"docker","image":"python:3.12-slim","command":["python","-u","-c",
            "from http.server import BaseHTTPRequestHandler,HTTPServer\nclass Handler(BaseHTTPRequestHandler):\n def do_POST(self):\n  body=self.headers.get('Authorization','').encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n def log_message(self,*args):pass\nHTTPServer(('0.0.0.0',8080),Handler).serve_forever()"],
        "environment":{"NATIVE_TOKEN":"node-only-secret"},"limits":{"cpu_millicores":250,"memory_bytes":134217728},
        "policy":{"issuer":"fleet","policy_id":"unproved","version":0,"sha256":""},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},
        "services":[{"id":{"namespace":"clawup","workload":"agent-test","service":"control"},"protocol":"http1","endpoint_ref":"control"},
            {"id":{"namespace":"clawup","workload":"agent-test","service":"chat"},"protocol":"http1","endpoint_ref":"ingress:chat"}],
        "driver_options":{"port":0,"container_port":8080,"stop_timeout_s":1,
            "ingress":{"chat":{"paths":["/v1/chat/completions"],"methods":["POST"],"bearer_env":"NATIVE_TOKEN"}}}
    })).unwrap();
    let driver = DockerDriver::new(tmp.path().join("state"), "local".into()).unwrap();
    let runtime = driver.launch(&request).await.unwrap();
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.0])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    let _cleanup = Cleanup(runtime.runtime_id);
    let port = runtime.port.unwrap();
    assert!(port > 0);
    assert!(tmp
        .path()
        .join("state")
        .join(format!("port-{port}.json"))
        .exists());
    let grant = |index: usize| Grant {
        iss: "test".into(),
        aud: grants::AUDIENCE.into(),
        sub: "test-admin".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Access,
        execution: request.execution.clone(),
        service: request.services[index].id.clone(),
        policy: PolicyRef {
            issuer: "test".into(),
            policy_id: "route-acl".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let control = grants::sign(&key, &grant(0)).unwrap();
    let chat = grants::sign(&key, &grant(1)).unwrap();
    let stop = CancellationToken::new();
    let target = ([127, 0, 0, 1], port).into();
    let (admin, admin_task) = management::bind(
        driver.clone(),
        request.execution.clone(),
        request.services[0].clone(),
        verifier.clone(),
        None,
        target,
        stop.clone(),
    )
    .await
    .unwrap();
    let ingress =
        serde_json::from_value(request.driver_options["ingress"]["chat"].clone()).unwrap();
    let (app, app_task) = management::bind(
        driver.clone(),
        request.execution.clone(),
        request.services[1].clone(),
        verifier,
        Some(ingress),
        target,
        stop.clone(),
    )
    .await
    .unwrap();
    let relay = trusted_router_transport::relay::Relay::new(
        Verifier::new(
            &std::fs::read(tmp.path().join("public")).unwrap(),
            "test".into(),
        )
        .unwrap(),
        &tmp.path().join("relay.db"),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_address = listener.local_addr().unwrap();
    let relay_task = tokio::spawn(relay.serve(listener));
    let mut registration = grant(1);
    registration.purpose = Purpose::Register;
    let registration_token = grants::sign(&key, &registration).unwrap();
    let route = registration.route_id();
    let edge_stop = stop.clone();
    let edge_task = tokio::spawn(async move {
        trusted_router_transport::edge::connect(
            &format!("ws://{relay_address}/v1/connect/{route}"),
            &registration_token,
            app,
            edge_stop,
        )
        .await
    });
    let relay_base = format!("http://{relay_address}/v1/http/{}", grant(1).route_id());
    let http = reqwest::Client::new();
    assert_eq!(
        http.get(format!("http://{admin}/metadata"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.get(format!("http://{admin}/metadata"))
            .header("x-trusted-route", &chat)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let output:management::ExecResponse=http.post(format!("http://{admin}/exec")).header("x-trusted-route",&control)
        .json(&json!({"command":["sh","-c","cat; printf error >&2; exit 7"],"stdin":base64::engine::general_purpose::STANDARD.encode("input"),"timeout_seconds":10}))
        .send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert_eq!(output.exit_code, 7);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(output.stdout)
            .unwrap(),
        b"input"
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(output.stderr)
            .unwrap(),
        b"error"
    );
    for _ in 0..100 {
        if http
            .post(format!("http://{app}/v1/chat/completions"))
            .header("x-trusted-route", &chat)
            .send()
            .await
            .unwrap()
            .status()
            == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        http.post(format!("http://{app}/v1/chat/completions"))
            .header("x-trusted-route", &chat)
            .bearer_auth("client-attempted-override")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap(),
        "Bearer node-only-secret"
    );
    assert_eq!(
        http.post(format!("http://{app}/exec"))
            .header("x-trusted-route", &chat)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        http.get(format!("http://{app}/v1/chat/completions"))
            .header("x-trusted-route", &chat)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let mut relayed = None;
    for _ in 0..100 {
        let response = http
            .post(format!("{relay_base}/v1/chat/completions"))
            .header("x-trusted-access", &chat)
            .header("x-trusted-route", "forged-client-header")
            .send()
            .await
            .unwrap();
        if response.status() == 200 {
            relayed = Some(response.text().await.unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(relayed.as_deref(), Some("Bearer node-only-secret"));
    let mut stale = grant(1);
    stale.execution.lease_id = "different-lease".into();
    assert_eq!(
        http.post(format!("http://{app}/v1/chat/completions"))
            .header("x-trusted-route", grants::sign(&key, &stale).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let before = driver.inspect(&request.execution).await.unwrap().port;
    http.post(format!("http://{admin}/restart"))
        .header("x-trusted-route", &control)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        driver.inspect(&request.execution).await.unwrap().port,
        before
    );
    driver.delete(&request.execution).await.unwrap();
    assert!(!tmp
        .path()
        .join("state")
        .join(format!("port-{port}.json"))
        .exists());
    assert_eq!(
        http.get(format!("http://{admin}/metadata"))
            .header("x-trusted-route", &control)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    stop.cancel();
    edge_task.await.unwrap().unwrap();
    relay_task.abort();
    admin_task.abort();
    app_task.abort();
}
