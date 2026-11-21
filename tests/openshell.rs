#![cfg(feature = "openshell")]
use openshell_core::{
    extension_protocol::{extension_metadata, ExtensionFamily},
    policy_identity::deterministic_policy_hash,
    proto::compute::v1::{
        compute_driver_server::{ComputeDriver, ComputeDriverServer},
        *,
    },
    proto::sandbox::v1::SandboxPolicy,
};
use prost::Message;
use std::{
    os::unix::fs::PermissionsExt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tonic::{Request, Response, Status};
use trusted_shim::{
    openshell::{NativeCreate, NativeDriver},
    runtime::LaunchRequest,
};

fn fixture() -> (LaunchRequest, DriverSandbox, String) {
    let request: LaunchRequest = serde_json::from_value(serde_json::json!({
        "execution":{"namespace":"test","workload":"agent","allocation_id":"agent-0","lease_id":"one","generation":1,"node_id":"node"},
        "driver":"openshell","image":"agent@sha256:approved","command":["agent","serve"],"environment":{"MODEL":"test"},
        "limits":{"cpu_millicores":500,"memory_bytes":67108864},
        "policy":{"issuer":"central","policy_id":"create","version":1,"sha256":"a".repeat(64)},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},"services":[]
    })).unwrap();
    let policy = SandboxPolicy::default();
    let hash = deterministic_policy_hash(&policy);
    let sandbox = DriverSandbox {
        id: "sandbox-1".into(),
        name: "agent-1".into(),
        namespace: "test".into(),
        spec: Some(DriverSandboxSpec {
            environment: request.environment.clone().into_iter().collect(),
            command: request.command.clone(),
            policy: Some(policy),
            launch_authentication: b"synthetic-split-auth".to_vec(),
            sandbox_token: "synthetic-bootstrap".into(),
            template: Some(DriverSandboxTemplate {
                image: request.image.clone(),
                resources: Some(DriverResourceRequirements {
                    cpu_limit: "500m".into(),
                    cpu_request: "500m".into(),
                    memory_limit: "67108864".into(),
                    memory_request: "67108864".into(),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    (request, sandbox, hash)
}
#[test]
fn native_launch_binds_policy_resources_command_and_environment() {
    let (r, s, p) = fixture();
    assert!(NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_ok());
    assert!(NativeCreate::decode(&s.encode_to_vec(), &r, &"f".repeat(64)).is_err());
    for change in 0..5 {
        let mut s = s.clone();
        match change {
            0 => s.namespace = "other".into(),
            1 => s.spec.as_mut().unwrap().command.push("injected".into()),
            2 => s
                .spec
                .as_mut()
                .unwrap()
                .environment
                .insert("OTHER".into(), "secret".into())
                .map(|_| ())
                .unwrap_or(()),
            3 => {
                s.spec
                    .as_mut()
                    .unwrap()
                    .template
                    .as_mut()
                    .unwrap()
                    .resources
                    .as_mut()
                    .unwrap()
                    .cpu_limit = "1000m".into()
            }
            _ => s.spec.as_mut().unwrap().launch_authentication.clear(),
        }
        assert!(NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_err());
    }
    let mut custom = s.clone();
    custom
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .user_namespaces = Some(false);
    assert!(NativeCreate::decode(&custom.encode_to_vec(), &r, &p).is_err());
}

#[derive(Clone, Default)]
struct Service {
    current: Arc<Mutex<Option<DriverSandbox>>>,
    created: Arc<AtomicUsize>,
    wrong_admission: Arc<AtomicBool>,
    wrong_identity: Arc<AtomicBool>,
    retain_on_delete: Arc<AtomicBool>,
}
#[tonic::async_trait]
impl ComputeDriver for Service {
    type WatchSandboxesStream =
        tokio_stream::wrappers::ReceiverStream<std::result::Result<WatchSandboxesEvent, Status>>;
    async fn get_capabilities(
        &self,
        _: Request<GetCapabilitiesRequest>,
    ) -> std::result::Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCapabilitiesResponse {
            driver_name: "docker".into(),
            resource_admission_policy: if self.wrong_admission.load(Ordering::SeqCst) {
                "different"
            } else {
                "approved"
            }
            .into(),
            extension: Some(extension_metadata(
                ExtensionFamily::Compute,
                "openshell/docker",
                "test",
                [],
            )),
            resource_capabilities: Some(ResourceCapabilities {
                cpu: Some(CpuResourceCapabilities {
                    limit_supported: true,
                }),
                memory: Some(MemoryResourceCapabilities {
                    limit_supported: true,
                }),
                gpu: None,
            }),
            ..Default::default()
        }))
    }
    async fn validate_sandbox_create(
        &self,
        _: Request<ValidateSandboxCreateRequest>,
    ) -> std::result::Result<Response<ValidateSandboxCreateResponse>, Status> {
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }
    async fn create_sandbox(
        &self,
        r: Request<CreateSandboxRequest>,
    ) -> std::result::Result<Response<CreateSandboxResponse>, Status> {
        self.created.fetch_add(1, Ordering::SeqCst);
        *self.current.lock().unwrap() = r.into_inner().sandbox;
        Ok(Response::new(CreateSandboxResponse::default()))
    }
    async fn get_sandbox(
        &self,
        _: Request<GetSandboxRequest>,
    ) -> std::result::Result<Response<GetSandboxResponse>, Status> {
        let mut s = self
            .current
            .lock()
            .unwrap()
            .clone()
            .ok_or(Status::not_found("absent"))?;
        if self.wrong_identity.load(Ordering::SeqCst) {
            s.id = "replacement".into();
        }
        Ok(Response::new(GetSandboxResponse { sandbox: Some(s) }))
    }
    async fn stop_sandbox(
        &self,
        _: Request<StopSandboxRequest>,
    ) -> std::result::Result<Response<StopSandboxResponse>, Status> {
        Ok(Response::new(StopSandboxResponse {}))
    }
    async fn delete_sandbox(
        &self,
        _: Request<DeleteSandboxRequest>,
    ) -> std::result::Result<Response<DeleteSandboxResponse>, Status> {
        if !self.retain_on_delete.load(Ordering::SeqCst) {
            *self.current.lock().unwrap() = None;
        }
        Ok(Response::new(DeleteSandboxResponse { deleted: true }))
    }
    async fn authenticate_sandbox(
        &self,
        _: Request<AuthenticateSandboxRequest>,
    ) -> std::result::Result<Response<AuthenticateSandboxResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn list_sandboxes(
        &self,
        _: Request<ListSandboxesRequest>,
    ) -> std::result::Result<Response<ListSandboxesResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn start_sandbox(
        &self,
        _: Request<StartSandboxRequest>,
    ) -> std::result::Result<Response<StartSandboxResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn suspend_sandbox(
        &self,
        _: Request<SuspendSandboxRequest>,
    ) -> std::result::Result<Response<SuspendSandboxResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn ensure_workspace(
        &self,
        _: Request<EnsureWorkspaceRequest>,
    ) -> std::result::Result<Response<EnsureWorkspaceResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn delete_workspace(
        &self,
        _: Request<DeleteWorkspaceRequest>,
    ) -> std::result::Result<Response<DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented("test"))
    }
    async fn watch_sandboxes(
        &self,
        _: Request<WatchSandboxesRequest>,
    ) -> std::result::Result<Response<Self::WatchSandboxesStream>, Status> {
        Err(Status::unimplemented("test"))
    }
}

#[tokio::test]
async fn private_native_rpc_negotiates_policy_checks_identity_and_confirms_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("driver.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let service = Service::default();
    let server = service.clone();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ComputeDriverServer::new(server))
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await
            .unwrap()
    });
    let driver = NativeDriver::new(socket.clone(), "approved".into()).unwrap();
    let (r, s, p) = fixture();
    service.wrong_admission.store(true, Ordering::SeqCst);
    assert!(driver
        .create(NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap())
        .await
        .is_err());
    assert_eq!(service.created.load(Ordering::SeqCst), 0);
    service.wrong_admission.store(false, Ordering::SeqCst);
    driver
        .create(NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap())
        .await
        .unwrap();
    assert_eq!(service.created.load(Ordering::SeqCst), 1);
    assert!(driver.inspect(&s.id, &s.name).await.unwrap().is_some());
    service.wrong_identity.store(true, Ordering::SeqCst);
    assert!(driver.stop(&s.id, &s.name).await.is_err());
    assert!(driver.delete(&s.id, &s.name).await.is_err());
    service.wrong_identity.store(false, Ordering::SeqCst);
    service.retain_on_delete.store(true, Ordering::SeqCst);
    assert!(driver.delete(&s.id, &s.name).await.is_err());
    service.retain_on_delete.store(false, Ordering::SeqCst);
    driver.delete(&s.id, &s.name).await.unwrap();
    assert!(driver.inspect(&s.id, &s.name).await.unwrap().is_none());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(driver.inspect(&s.id, &s.name).await.is_err());
    task.abort();
}
