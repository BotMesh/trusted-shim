//! An authenticated, unmodified gateway must produce bytes the shim accepts.
//! The compute extension captures and refuses creation, so this tests the real
//! control protocol and credentials, not workload isolation or application readiness.
use super::*;
use std::{path::Path, process::Command, time::Duration};

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "test certificate generation failed"
    );
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
#[ignore = "requires the pinned unmodified OPENSHELL_GATEWAY_BINARY and openssl"]
async fn stock_gateway_mints_private_launch_for_shim_with_workspace_isolation() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let binary = std::env::var_os("OPENSHELL_GATEWAY_BINARY").expect("native gateway binary");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=shim-test-ca",
        ],
    );
    for (name, subject, extension) in [
        (
            "server",
            "/CN=localhost",
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        ),
        (
            "client",
            "/CN=shim-test/OU=operator",
            "extendedKeyUsage=clientAuth\n",
        ),
    ] {
        openssl(
            root,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                subject,
            ],
        );
        std::fs::write(root.join(format!("{name}.ext")), extension).unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "1",
                "-out",
                &format!("{name}.pem"),
                "-extfile",
                &format!("{name}.ext"),
            ],
        );
    }
    openssl(
        root,
        &["genpkey", "-algorithm", "ED25519", "-out", "jwt.key"],
    );
    openssl(
        root,
        &["pkey", "-in", "jwt.key", "-pubout", "-out", "jwt.pub"],
    );
    std::fs::write(root.join("jwt.kid"), "shim-acceptance").unwrap();
    let config = format!(
        "[openshell]\nversion=2\n[openshell.gateway.gateway_jwt]\nsigning_key_path={:?}\npublic_key_path={:?}\nkid_path={:?}\ngateway_id=\"shim-acceptance\"\n",
        root.join("jwt.key"), root.join("jwt.pub"), root.join("jwt.kid")
    );
    std::fs::write(root.join("gateway.toml"), config).unwrap();
    let socket = root.join("compute.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let capture = Arc::new(Mutex::new(None));
    let (mut launch, mut native, _) = fixture();
    launch.image = "alpine:3.21".into();
    launch.command = vec!["/bin/true".into()];
    let policy = native.spec.as_mut().unwrap().policy.as_mut().unwrap();
    policy.version = 1;
    policy.process = Some(openshell_core::proto::sandbox::v1::ProcessPolicy {
        run_as_user: "1000".into(),
        run_as_group: "1000".into(),
    });
    let policy_hash = deterministic_policy_hash(policy);
    launch.access_policy_sha256 = Some(policy_hash.clone());
    let binding = Arc::new(GatewayLaunch::new(launch.clone(), policy.clone()).unwrap());
    let service = Service {
        capture: Some(capture.clone()),
        gateway_launch: Some(binding.clone()),
        ..Default::default()
    };
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ComputeDriverServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await
            .unwrap()
    });
    let api_port = port();
    let log = std::fs::File::create(root.join("gateway.log")).unwrap();
    let mut gateway = tokio::process::Command::new(binary)
        .args([
            "--bind-address",
            "127.0.0.1",
            "--port",
            &api_port.to_string(),
            "--health-port",
            &port().to_string(),
            "--metrics-port",
            &port().to_string(),
            "--enable-mtls-auth",
            "true",
            "--enable-operator-auth",
            "true",
            "--compute-driver",
            "docker",
        ])
        .arg("--compute-driver-socket")
        .arg(&socket)
        .arg("--config")
        .arg(root.join("gateway.toml"))
        .arg("--db-url")
        .arg(format!(
            "sqlite://{}?mode=rwc",
            root.join("gateway.db").display()
        ))
        .arg("--tls-cert")
        .arg(root.join("server.pem"))
        .arg("--tls-key")
        .arg(root.join("server.key"))
        .arg("--tls-client-ca")
        .arg(root.join("ca.pem"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("config"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let tls = tonic::transport::ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(
            std::fs::read(root.join("ca.pem")).unwrap(),
        ))
        .identity(tonic::transport::Identity::from_pem(
            std::fs::read(root.join("client.pem")).unwrap(),
            std::fs::read(root.join("client.key")).unwrap(),
        ));
    let endpoint = tonic::transport::Endpoint::from_shared(format!("https://127.0.0.1:{api_port}"))
        .unwrap()
        .tls_config(tls)
        .unwrap();
    let connected = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if let Ok(c) = endpoint.connect().await {
                break c;
            }
            assert!(
                gateway.try_wait().unwrap().is_none(),
                "native gateway exited: {}",
                std::fs::read_to_string(root.join("gateway.log")).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("native gateway readiness");
    let mut client = openshell_core::proto::open_shell_client::OpenShellClient::new(connected);
    client
        .create_workspace(openshell_core::proto::CreateWorkspaceRequest {
            name: "test".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    // An unrelated public request cannot select the reserved allocation even
    // with the operator's mTLS identity. It fails before credentials are minted.
    let mut wrong = binding.request();
    wrong.spec.as_mut().unwrap().command.push("injected".into());
    assert!(client.create_sandbox(wrong).await.is_err());
    assert!(capture.lock().unwrap().is_none());
    let result = client.create_sandbox(binding.request()).await;
    // The extension deliberately refuses every create after capturing it.
    assert!(result.is_err());
    assert!(
        capture.lock().unwrap().is_some(),
        "gateway failed before capture: {:?}",
        result.err().map(|s| (s.code(), s.message().to_owned()))
    );
    let captured = capture
        .lock()
        .unwrap()
        .take()
        .expect("gateway must reach the private compute extension");
    let prepared = binding.bind(&captured.encode_to_vec()).unwrap();
    assert_eq!(
        prepared.authorization_resource(),
        format!("openshell/sandbox/{}", captured.id)
    );
    let private = captured.spec.as_ref().unwrap();
    assert!(!private.sandbox_token.is_empty() && !private.launch_authentication.is_empty());
    assert!(captured.namespace.is_empty());
    launch.execution.namespace = "other-tenant".into();
    assert!(NativeCreate::decode(&captured.encode_to_vec(), &launch, &policy_hash).is_err());
    gateway.kill().await.unwrap();
    gateway.wait().await.unwrap();
    task.abort();
}
