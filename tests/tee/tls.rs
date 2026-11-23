//! Actual mTLS handshake tests; the AS response is a protocol fixture, not a proof.
use super::*;
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use trusted_shim::tee::{trustee::TlsConfig, Binding};

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

#[tokio::test]
async fn trustee_mtls_validates_both_peers_and_private_key_files() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for name in ["ca", "other-ca"] {
        openssl(
            root,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.pem"),
                "-days",
                "1",
                "-subj",
                &format!("/CN={name}"),
            ],
        );
    }
    for (name, ca, extensions) in [
        (
            "server",
            "ca",
            "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n",
        ),
        ("client", "ca", "extendedKeyUsage=clientAuth\n"),
        ("unknown", "other-ca", "extendedKeyUsage=clientAuth\n"),
    ] {
        openssl(
            root,
            &[
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                &format!("{name}.key"),
                "-out",
                &format!("{name}.csr"),
                "-subj",
                &format!("/CN={name}"),
            ],
        );
        std::fs::write(root.join("extensions"), extensions).unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{name}.csr"),
                "-CA",
                &format!("{ca}.pem"),
                "-CAkey",
                &format!("{ca}.key"),
                "-CAcreateserial",
                "-out",
                &format!("{name}.pem"),
                "-days",
                "1",
                "-extfile",
                "extensions",
            ],
        );
        std::fs::set_permissions(
            root.join(format!("{name}.key")),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let read = |name: &str| std::fs::read(root.join(name)).unwrap();
    let server_tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(read("server.pem"), read("server.key")))
        .client_ca_root(Certificate::from_pem(read("ca.pem")));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .unwrap()
            .add_service(
                wire::attestation_service_server::AttestationServiceServer::new(
                    support::ProtocolTrustee,
                ),
            )
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    struct Cleanup(tokio::task::JoinHandle<()>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _cleanup = Cleanup(server);
    let mut tls = TlsConfig {
        ca_file: root.join("ca.pem"),
        cert_file: root.join("client.pem"),
        key_file: root.join("client.key"),
    };
    let binding = Binding {
        domain: "test".into(),
        mode: Mode::Simulation,
        platform: "sample".into(),
        expected_measurement: "abcde".into(),
        init_data_sha256: "11".repeat(32),
        endpoint_key_sha256: "22".repeat(32),
        execution: request("tls").execution,
        request_sha256: "33".repeat(32),
        nonce: "challenge".into(),
        expires_at: 1,
    };
    let evidence = serde_json::to_vec(&json!({"svn":"1","report_data":STANDARD.encode(Sha256::digest(canonical(&binding).unwrap()))})).unwrap();
    let client = Trustee::connect(&endpoint, vec!["default".into()], Some(&tls))
        .await
        .unwrap();
    client.evaluate(&binding, &evidence).await.unwrap();
    assert!(Trustee::connect(&endpoint, vec![], None).await.is_err());
    assert!(Trustee::connect("http://127.0.0.1:1", vec![], Some(&tls))
        .await
        .is_err());
    assert!(
        Trustee::connect("http://remote.example:50004", vec![], None)
            .await
            .is_err()
    );
    tls.ca_file = root.join("other-ca.pem");
    assert!(
        Trustee::connect(&endpoint, vec!["default".into()], Some(&tls))
            .await
            .unwrap()
            .evaluate(&binding, &evidence)
            .await
            .is_err()
    );
    tls.ca_file = root.join("ca.pem");
    tls.cert_file = root.join("unknown.pem");
    tls.key_file = root.join("unknown.key");
    assert!(
        Trustee::connect(&endpoint, vec!["default".into()], Some(&tls))
            .await
            .unwrap()
            .evaluate(&binding, &evidence)
            .await
            .is_err()
    );
    tls.cert_file = root.join("client.pem");
    tls.key_file = root.join("client.key");
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Trustee::connect(&endpoint, vec![], Some(&tls))
        .await
        .is_err());
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&tls.key_file, root.join("linked.key")).unwrap();
    tls.key_file = root.join("linked.key");
    assert!(Trustee::connect(&endpoint, vec![], Some(&tls))
        .await
        .is_err());
}
