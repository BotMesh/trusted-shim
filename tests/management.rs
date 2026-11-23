use base64::Engine as _;
use serde_json::json;
use std::{os::unix::fs::PermissionsExt, process::Command, time::Duration};
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
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
    let verifier = Verifier::from_file(public.clone(), "test".into()).unwrap();
    let request:LaunchRequest=serde_json::from_value(json!({
        "execution":{"namespace":"clawup","workload":"agent-test","allocation_id":tmp.path().file_name().unwrap().to_string_lossy(),"lease_id":"lease","generation":1,"node_id":"local"},
        "driver":"docker","image":"python:3.12-slim","command":["python","-u","-c",
            "import sys\nprint(\"x\"*300000+\"\\nstdout-log\");print(\"stderr-log\",file=sys.stderr)\nfrom http.server import BaseHTTPRequestHandler,HTTPServer\nclass Handler(BaseHTTPRequestHandler):\n def do_POST(self):\n  body=self.headers.get('Authorization','').encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)\n def log_message(self,*args):pass\nHTTPServer(('0.0.0.0',8080),Handler).serve_forever()"],
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
        http_request: None,
        access: None,
        execution: request.execution.clone(),
        service: request.services[index].id.clone(),
        policy: PolicyRef {
            issuer: "test".into(),
            policy_id: "route-acl".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let mut control = grants::sign(&key, &grant(0)).unwrap();
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
        verifier.clone(),
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
    for (token, status) in [(None, 401), (Some(&chat), 403)] {
        let mut request = http.get(format!("http://{admin}/logs?tail=10"));
        if let Some(token) = token {
            request = request.header("x-trusted-route", token);
        }
        assert_eq!(request.send().await.unwrap().status(), status);
    }
    let mut foreign = grant(0);
    foreign.execution.namespace = "another-tenant".into();
    foreign.service.namespace = "another-tenant".into();
    assert_eq!(
        http.get(format!("http://{admin}/logs?tail=10"))
            .header("x-trusted-route", grants::sign(&key, &foreign).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    for query in ["tail=0", "tail=5001", "tail=all", "tail=10&follow=true"] {
        assert_eq!(
            http.get(format!("http://{admin}/logs?{query}"))
                .header("x-trusted-route", &control)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
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
    let logs: management::LogsResponse = http
        .get(format!("http://{admin}/logs?tail=5000"))
        .header("x-trusted-route", &control)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(logs.stdout)
        .unwrap();
    let stderr = base64::engine::general_purpose::STANDARD
        .decode(logs.stderr)
        .unwrap();
    assert_eq!(stdout.len(), 128 * 1024);
    assert!(stdout.ends_with(b"stdout-log\n"));
    assert_eq!(stderr, b"stderr-log\n");
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
    // Browser ingress requires per-request approval and commits replay state
    // before forwarding, including across concurrent requests and restarts.
    use sha2::{Digest, Sha256};
    let mut once: management::Ingress =
        serde_json::from_value(request.driver_options["ingress"]["chat"].clone()).unwrap();
    once.single_use = true;
    let (bound_app, bound_task) = management::bind(
        driver.clone(),
        request.execution.clone(),
        request.services[1].clone(),
        verifier.clone(),
        Some(once.clone()),
        target,
        stop.clone(),
    )
    .await
    .unwrap();
    let bound_url = format!("http://{bound_app}/v1/chat/completions");
    assert_eq!(
        http.post(&bound_url)
            .header("x-trusted-route", &chat)
            .body("approved")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let mut bound = grant(1);
    bound.sub = "12".repeat(32);
    bound.access = Some(trusted_router_transport::authorization::AccessBinding {
        principal: bound.sub.clone(),
        session: "34".repeat(32),
        policy_version: 2,
        policy_sha256: "56".repeat(32),
    });
    bound.http_request = Some(trusted_router_transport::grants::HttpRequestBinding {
        id: "aa".repeat(32),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        body_sha256: hex::encode(Sha256::digest(b"approved")),
    });
    let capability = grants::sign(&key, &bound).unwrap();
    assert_eq!(
        http.post(&bound_url)
            .header("x-trusted-route", &capability)
            .body("changed")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let attempts = futures::future::join_all((0..20).map(|_| {
        http.post(&bound_url)
            .header("x-trusted-route", &capability)
            .body("approved")
            .send()
    }))
    .await;
    let codes = attempts
        .into_iter()
        .map(|r| r.unwrap().status().as_u16())
        .collect::<Vec<_>>();
    assert_eq!(codes.iter().filter(|&&v| v == 200).count(), 1, "{codes:?}");
    assert_eq!(codes.iter().filter(|&&v| v == 409).count(), 19, "{codes:?}");
    bound_task.abort();
    let recovered = DockerDriver::new(tmp.path().join("state"), "local".into()).unwrap();
    let (recovered_app, recovered_task) = management::bind(
        recovered,
        request.execution.clone(),
        request.services[1].clone(),
        verifier.clone(),
        Some(once),
        target,
        stop.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        http.post(format!("http://{recovered_app}/v1/chat/completions"))
            .header("x-trusted-route", &capability)
            .body("approved")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    recovered_task.abort();
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
    // The running shim listeners must reload the existing trust file too;
    // accepting a new relay signer only at the relay would break node ingress.
    let next_key = tmp.path().join("next-key");
    let next_public = tmp.path().join("next-public");
    assert!(Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&next_key)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("openssl")
        .args(["pkey", "-in"])
        .arg(&next_key)
        .args(["-pubout", "-out"])
        .arg(&next_public)
        .status()
        .unwrap()
        .success());
    let next = grants::sign(&std::fs::read(next_key).unwrap(), &grant(0)).unwrap();
    assert_eq!(
        http.get(format!("http://{admin}/metadata"))
            .header("x-trusted-route", &next)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let old_public = std::fs::read(&public).unwrap();
    let new_public = std::fs::read(next_public).unwrap();
    let replace = |bytes: &[u8]| {
        use std::io::Write;
        let mut temp = tempfile::NamedTempFile::new_in(tmp.path()).unwrap();
        temp.write_all(bytes).unwrap();
        temp.as_file().sync_all().unwrap();
        temp.persist(&public).unwrap();
    };
    replace(&[old_public.as_slice(), new_public.as_slice()].concat());
    for token in [&control, &next] {
        assert_eq!(
            http.get(format!("http://{admin}/metadata"))
                .header("x-trusted-route", token)
                .send()
                .await
                .unwrap()
                .status(),
            200
        );
    }
    replace(&new_public);
    assert_eq!(
        http.get(format!("http://{admin}/metadata"))
            .header("x-trusted-route", &control)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        driver.inspect(&request.execution).await.unwrap().port,
        before
    );
    control = next;
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
    assert_eq!(
        http.get(format!("http://{admin}/logs?tail=10"))
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

/// Native listeners need no Docker: control serves only logs, and ingress
/// forwards the caller's own credential with durable single-use approval.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_listener_is_logs_only_and_forwards_the_callers_credential() {
    use sha2::{Digest, Sha256};
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
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
    let verifier = Verifier::from_file(public, "test".into()).unwrap();

    // The application: echoes the Authorization it received, counts calls.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = calls.clone();
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                headers
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned())
                    .unwrap_or_default()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let app_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let execution: trusted_shim::contracts::ExecutionIdentity = serde_json::from_value(json!({
        "namespace":"clawup","workload":"agent-native","allocation_id":"a1","lease_id":"lease",
        "generation":1,"node_id":"local"}))
    .unwrap();
    let spec = |service: &str, endpoint: &str| -> trusted_shim::ServiceSpec {
        serde_json::from_value(json!({"id":{"namespace":"clawup","workload":"agent-native",
            "service":service},"protocol":"http1","endpoint_ref":endpoint}))
        .unwrap()
    };
    let (control_spec, chat_spec) = (spec("control", "control"), spec("chat", "ingress:chat"));
    let grant = |service: &trusted_shim::ServiceSpec| Grant {
        iss: "test".into(),
        aud: grants::AUDIENCE.into(),
        sub: "test-admin".into(),
        nbf: grants::now(),
        exp: grants::now() + 120,
        purpose: Purpose::Access,
        http_request: None,
        access: None,
        execution: execution.clone(),
        service: service.id.clone(),
        policy: PolicyRef {
            issuer: "test".into(),
            policy_id: "route-acl".into(),
            version: 1,
            sha256: "ab".repeat(32),
        },
    };
    let control = grants::sign(&key, &grant(&control_spec)).unwrap();
    let chat = grants::sign(&key, &grant(&chat_spec)).unwrap();
    let journal = tmp.path().join("native-http-invocations.sqlite");
    let stop = CancellationToken::new();
    let bind = |declaration: trusted_shim::ServiceSpec, ingress: Option<management::Ingress>| {
        management::bind_native(
            Default::default(),
            journal.clone(),
            execution.clone(),
            declaration,
            verifier.clone(),
            ingress,
            target,
            stop.clone(),
        )
    };
    let rule: management::Ingress =
        serde_json::from_value(json!({"paths":["/v1/chat/completions"],"methods":["POST"]}))
            .unwrap();

    // A node holds no application credential to inject.
    let mut injected = rule.clone();
    injected.bearer_env = Some("OPENCLAW_GATEWAY_TOKEN".into());
    assert!(bind(chat_spec.clone(), Some(injected)).await.is_err());

    // Native control is logs only: no exec, restart or metadata surface.
    let http = reqwest::Client::new();
    let (admin, admin_task) = bind(control_spec.clone(), None).await.unwrap();
    for (method, path) in [
        ("POST", "/exec"),
        ("POST", "/restart"),
        ("GET", "/metadata"),
    ] {
        let status = http
            .request(method.parse().unwrap(), format!("http://{admin}{path}"))
            .header("x-trusted-route", &control)
            .json(&json!({"command":["true"],"timeout_seconds":1}))
            .send()
            .await
            .unwrap()
            .status();
        assert!(status == 404 || status == 405, "{path}: {status}");
    }
    for (token, query, status) in [
        (None, "tail=10", 401),
        (Some(&chat), "tail=10", 403),
        (Some(&control), "tail=0", 400),
        (Some(&control), "tail=5001", 400),
    ] {
        let mut request = http.get(format!("http://{admin}/logs?{query}"));
        if let Some(token) = token {
            request = request.header("x-trusted-route", token);
        }
        assert_eq!(request.send().await.unwrap().status(), status, "{query}");
    }
    // An unobserved sandbox is never resolved to some other container.
    assert!(!http
        .get(format!("http://{admin}/logs?tail=10"))
        .header("x-trusted-route", &control)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    // Ingress forwards exactly the caller's own credential, or none.
    let (app_addr, app_listener) = bind(chat_spec.clone(), Some(rule.clone())).await.unwrap();
    let url = format!("http://{app_addr}/v1/chat/completions");
    for authorization in [Some("Bearer caller-token"), None] {
        let mut request = http.post(&url).header("x-trusted-route", &chat).body("{}");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        let response = request.send().await.unwrap().error_for_status().unwrap();
        assert_eq!(response.text().await.unwrap(), authorization.unwrap_or(""));
    }
    for (method, path, token) in [
        ("GET", "/v1/chat/completions", &chat),
        ("POST", "/admin", &chat),
        ("POST", "/v1/chat/completions", &control),
    ] {
        let status = http
            .request(method.parse().unwrap(), format!("http://{app_addr}{path}"))
            .header("x-trusted-route", token)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 403, "{method} {path}");
    }
    app_listener.abort();

    // Single-use approval is body-bound and survives a listener restart.
    let mut once = rule;
    once.single_use = true;
    let (bound_addr, bound_task) = bind(chat_spec.clone(), Some(once.clone())).await.unwrap();
    let bound_url = format!("http://{bound_addr}/v1/chat/completions");
    let mut bound = grant(&chat_spec);
    bound.http_request = Some(grants::HttpRequestBinding {
        id: "aa".repeat(32),
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        body_sha256: hex::encode(Sha256::digest(b"approved")),
    });
    let capability = grants::sign(&key, &bound).unwrap();
    for (token, body) in [(&chat, "approved"), (&capability, "changed")] {
        let status = http
            .post(&bound_url)
            .header("x-trusted-route", token)
            .body(body)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 403, "{body}");
    }
    let before = calls.load(std::sync::atomic::Ordering::SeqCst);
    let attempts = futures::future::join_all((0..20).map(|_| {
        http.post(&bound_url)
            .header("x-trusted-route", &capability)
            .header("authorization", "Bearer caller-token")
            .body("approved")
            .send()
    }))
    .await;
    let codes: Vec<_> = attempts
        .into_iter()
        .map(|r| r.unwrap().status().as_u16())
        .collect();
    assert_eq!(codes.iter().filter(|&&v| v == 200).count(), 1, "{codes:?}");
    assert_eq!(codes.iter().filter(|&&v| v == 409).count(), 19, "{codes:?}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), before + 1);
    bound_task.abort();
    let (again, again_task) = bind(chat_spec, Some(once)).await.unwrap();
    assert_eq!(
        http.post(format!("http://{again}/v1/chat/completions"))
            .header("x-trusted-route", &capability)
            .body("approved")
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    stop.cancel();
    for task in [admin_task, again_task, app_task] {
        task.abort();
    }
}
