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
        workspace: "test".into(),
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
                    cpu_request: String::new(),
                    memory_limit: "67108864".into(),
                    memory_request: String::new(),
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
    for change in 0..7 {
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
            4 => s.spec.as_mut().unwrap().launch_authentication.clear(),
            5 => s.workspace = "other".into(),
            _ => {
                s.spec
                    .as_mut()
                    .unwrap()
                    .template
                    .as_mut()
                    .unwrap()
                    .resources
                    .as_mut()
                    .unwrap()
                    .cpu_request = "500m".into()
            }
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
    lose_create_reply: Arc<AtomicBool>,
    missing_after_create: Arc<AtomicBool>,
    retain_on_stop: Arc<AtomicBool>,
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
        let mut sandbox = r.into_inner().sandbox.unwrap();
        sandbox.status = Some(DriverSandboxStatus {
            instance_id: "instance-1".into(),
            conditions: vec![DriverCondition {
                r#type: "Ready".into(),
                status: "True".into(),
                reason: "BackendReady".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        if !self.missing_after_create.load(Ordering::SeqCst) {
            *self.current.lock().unwrap() = Some(sandbox);
        }
        if self.lose_create_reply.load(Ordering::SeqCst) {
            return Err(Status::unavailable("ambiguous creation"));
        }
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
        if !self.retain_on_stop.load(Ordering::SeqCst) {
            if let Some(sandbox) = &mut *self.current.lock().unwrap() {
                sandbox.status.as_mut().unwrap().conditions = vec![DriverCondition {
                    r#type: "Ready".into(),
                    status: "False".into(),
                    reason: "ContainerExited".into(),
                    ..Default::default()
                }];
            }
        }
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

// A transport/ledger test double, never a proof verifier. Cryptographic receipt
// validation is covered by the separate Ziren and central-ledger tests.
#[derive(Default)]
struct CentralLedger {
    consumed: Mutex<std::collections::HashSet<String>>,
    reject: AtomicBool,
}
#[async_trait::async_trait]
impl trusted_rail::AuthorizationLedger for CentralLedger {
    async fn reserve(
        &self,
        _: &trusted_rail::DecisionRecord,
        _: Option<&[u8]>,
    ) -> trusted_rail::Result<trusted_rail::ExecutionGrant> {
        Err(trusted_rail::Error::Unsupported)
    }
    async fn consume(
        &self,
        grant: &trusted_rail::ExecutionGrant,
        execution: &trusted_shim::contracts::ExecutionIdentity,
        digest: &str,
    ) -> trusted_rail::Result<()> {
        if self.reject.load(Ordering::SeqCst)
            || grant.credential != [7]
            || &grant.execution != execution
            || grant.request_sha256 != digest
        {
            return Err(trusted_rail::Error::Rejected);
        }
        if !self.consumed.lock().unwrap().insert(grant.id.clone()) {
            return Err(trusted_rail::Error::Conflict);
        }
        Ok(())
    }
}

fn authorization(
    request: &LaunchRequest,
    prepared: &NativeCreate,
    id: &str,
) -> (
    trusted_rail::EvaluationRequest,
    trusted_rail::ExecutionGrant,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = trusted_rail::EvaluationRequest {
        execution: request.execution.clone(),
        principal: "fleet-gateway".into(),
        action_id: id.into(),
        operation: "runtime.create".into(),
        resource: prepared.authorization_resource(),
        parameters: prepared.authorization_parameters(),
        context: serde_json::json!({}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: now,
        validity: trusted_shim::contracts::Validity {
            not_before: now - 1,
            expires_at: now + 120,
        },
    };
    let grant = trusted_rail::ExecutionGrant {
        id: id.into(),
        credential: vec![7],
        execution: request.execution.clone(),
        request_sha256: trusted_rail::rego::request_digest(&request).unwrap(),
        validity: request.validity.clone(),
    };
    (request, grant)
}

struct Harness {
    _dir: tempfile::TempDir,
    native: NativeDriver,
    state: std::path::PathBuf,
    service: Service,
    ledger: Arc<CentralLedger>,
    task: tokio::task::JoinHandle<()>,
}
impl Harness {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("driver.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = Service::default();
        let server = service.clone();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(ComputeDriverServer::new(server))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await
                .unwrap();
        });
        Self {
            _dir: dir,
            state,
            native: NativeDriver::new(socket, "approved".into()).unwrap(),
            service,
            ledger: Arc::new(CentralLedger::default()),
            task,
        }
    }
    fn driver(&self) -> trusted_shim::openshell_lifecycle::ManagedNativeDriver {
        trusted_shim::openshell_lifecycle::ManagedNativeDriver::open(
            self.state.clone(),
            "node".into(),
            self.native.clone(),
            self.ledger.clone(),
        )
        .unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn managed_native_lifecycle_survives_restart_fences_generations_and_keeps_secrets_out_of_state(
) {
    use trusted_shim::openshell_lifecycle::ProvisioningPhase;
    let h = Harness::new().await;
    let (r, s, p) = fixture();
    let bytes = s.encode_to_vec();
    let prepared = || NativeCreate::decode(&bytes, &r, &p).unwrap();
    let (a, g) = authorization(&r, &prepared(), "one");
    let status = h.driver().launch(&r, prepared(), &a, &g).await.unwrap();
    assert_eq!(status.phase, ProvisioningPhase::Created);
    assert!(status.platform_ready);
    let public = serde_json::to_string(&status).unwrap();
    assert!(!public.contains("synthetic"));
    // Reopen durable state with a fresh driver and replay the exact request.
    let recovered = h.driver();
    recovered.launch(&r, prepared(), &a, &g).await.unwrap();
    assert_eq!(h.service.created.load(Ordering::SeqCst), 1);
    assert_eq!(h.ledger.consumed.lock().unwrap().len(), 1);
    for field in ["namespace", "workload", "lease_id", "node_id"] {
        let mut value = serde_json::to_value(&r.execution).unwrap();
        value[field] = "other".into();
        let other = serde_json::from_value(value).unwrap();
        assert!(recovered.inspect(&other).await.is_err());
        assert!(recovered.stop(&other).await.is_err());
        assert!(recovered.delete(&other).await.is_err());
    }
    // A replacement with the same sandbox ID/name but another physical instance
    // must not be stopped or deleted on behalf of the old allocation.
    h.service
        .current
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .status
        .as_mut()
        .unwrap()
        .instance_id = "replacement".into();
    assert!(recovered.delete(&r.execution).await.is_err());
    h.service
        .current
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .status
        .as_mut()
        .unwrap()
        .instance_id = "instance-1".into();
    h.service.retain_on_stop.store(true, Ordering::SeqCst);
    assert!(recovered.stop(&r.execution).await.is_err());
    assert_eq!(
        recovered.inspect(&r.execution).await.unwrap().phase,
        ProvisioningPhase::Stopping
    );
    h.service.retain_on_stop.store(false, Ordering::SeqCst);
    recovered.stop(&r.execution).await.unwrap();
    h.service.retain_on_delete.store(true, Ordering::SeqCst);
    assert!(recovered.delete(&r.execution).await.is_err());
    h.service.retain_on_delete.store(false, Ordering::SeqCst);
    recovered.delete(&r.execution).await.unwrap();
    assert!(!recovered.inspect(&r.execution).await.unwrap().present);
    assert!(recovered.launch(&r, prepared(), &a, &g).await.is_err());
    let mut next = r.clone();
    next.execution.lease_id = "two".into();
    let mut sandbox = s.clone();
    sandbox.id = "sandbox-2".into();
    sandbox.name = "agent-2".into();
    let bytes = sandbox.encode_to_vec();
    let native = NativeCreate::decode(&bytes, &next, &p).unwrap();
    let (a, g) = authorization(&next, &native, "two");
    assert!(recovered.launch(&next, native, &a, &g).await.is_err()); // same generation
    next.execution.generation += 1;
    let native = NativeCreate::decode(&bytes, &next, &p).unwrap();
    let (a, g) = authorization(&next, &native, "two");
    recovered.launch(&next, native, &a, &g).await.unwrap();
    assert!(recovered.delete(&r.execution).await.is_err());
    // Inspect persisted SQLite/WAL files, not just the public JSON serializer.
    for entry in std::fs::read_dir(&h.state).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(entry.metadata().unwrap().permissions().mode() & 0o077, 0);
        let bytes = std::fs::read(entry.path()).unwrap();
        for secret in [
            b"synthetic-bootstrap".as_slice(),
            b"synthetic-split-auth",
            b"MODEL",
        ] {
            assert!(!bytes.windows(secret.len()).any(|part| part == secret));
        }
    }
}

#[tokio::test]
async fn managed_launch_checks_exact_authorization_before_dispatch_and_never_refunds() {
    let h = Harness::new().await;
    let (r, s, p) = fixture();
    let bytes = s.encode_to_vec();
    let prepared = || NativeCreate::decode(&bytes, &r, &p).unwrap();
    for change in 0..5 {
        let (mut a, mut g) = authorization(&r, &prepared(), "one");
        match change {
            0 => a.parameters["native_policy_sha256"] = "f".repeat(64).into(),
            1 => a.resource = "openshell/sandbox/other".into(),
            2 => a.execution.namespace = "other".into(),
            3 => g.validity.expires_at = 1,
            _ => a.operation = "runtime.exec".into(),
        }
        if change != 3 {
            g.request_sha256 = trusted_rail::rego::request_digest(&a).unwrap();
            g.execution = a.execution.clone();
        }
        assert!(h.driver().launch(&r, prepared(), &a, &g).await.is_err());
    }
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
    assert!(h.ledger.consumed.lock().unwrap().is_empty());
    let (a, g) = authorization(&r, &prepared(), "one");
    h.ledger.reject.store(true, Ordering::SeqCst);
    assert!(h.driver().launch(&r, prepared(), &a, &g).await.is_err());
    h.ledger.reject.store(false, Ordering::SeqCst);
    assert!(h.driver().launch(&r, prepared(), &a, &g).await.is_err());
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
    h.driver().delete(&r.execution).await.unwrap();
}

#[tokio::test]
async fn ambiguous_create_is_never_repeated_or_released_while_absent() {
    let h = Harness::new().await;
    let (r, s, p) = fixture();
    let bytes = s.encode_to_vec();
    let prepared = || NativeCreate::decode(&bytes, &r, &p).unwrap();
    let (a, g) = authorization(&r, &prepared(), "one");
    h.service.lose_create_reply.store(true, Ordering::SeqCst);
    h.service.missing_after_create.store(true, Ordering::SeqCst);
    assert!(h.driver().launch(&r, prepared(), &a, &g).await.is_err());
    let recovered = h.driver();
    assert!(
        !recovered
            .launch(&r, prepared(), &a, &g)
            .await
            .unwrap()
            .present
    );
    assert!(recovered.delete(&r.execution).await.is_err());
    assert!(recovered.stop(&r.execution).await.is_err());
    assert_eq!(h.service.created.load(Ordering::SeqCst), 1);
    assert_eq!(h.ledger.consumed.lock().unwrap().len(), 1);
    // The original operation becomes observable; native deletion can now cancel
    // and confirm cleanup for the same identity, without resending create.
    *h.service.current.lock().unwrap() = Some(s);
    recovered.delete(&r.execution).await.unwrap();
}

/// Run against the pinned, unmodified upstream binary. This checks native
/// negotiation and validation only; it never creates a sandbox or mints launch
/// credentials. Full isolation still requires an authenticated native gateway.
#[tokio::test]
#[ignore = "requires an operator-started native OpenShell driver on a private socket"]
async fn unmodified_native_driver_admits_canonical_inputs_and_rejects_wrong_operator_policy() {
    let socket =
        std::env::var_os("OPENSHELL_NATIVE_DRIVER_SOCKET").expect("private native driver socket");
    let policy =
        openshell_core::resource_admission::DriverAdmissionConfig::default().acknowledgement();
    let native = NativeDriver::new(socket.clone().into(), policy).unwrap();
    let (mut r, mut s, p) = fixture();
    r.image = "alpine:3.21".into();
    s.spec.as_mut().unwrap().template.as_mut().unwrap().image = r.image.clone();
    let bytes = s.encode_to_vec();
    // Exercise the exact upstream validation RPC too, so native rejection codes
    // are visible for these synthetic inputs without logging production secrets.
    let path = std::path::PathBuf::from(socket.clone());
    let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .unwrap();
    let mut client = compute_driver_client::ComputeDriverClient::new(channel);
    client
        .validate_sandbox_create(ValidateSandboxCreateRequest {
            sandbox: Some(s.clone()),
        })
        .await
        .unwrap();
    let caps = client
        .get_capabilities(GetCapabilitiesRequest {
            gateway: Some(openshell_core::extension_protocol::gateway_metadata(
                ExtensionFamily::Compute,
            )),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        caps.resource_admission_policy,
        openshell_core::resource_admission::DriverAdmissionConfig::default().acknowledgement()
    );
    native
        .validate(&NativeCreate::decode(&bytes, &r, &p).unwrap())
        .await
        .unwrap();
    assert!(NativeDriver::new(socket.into(), "unapproved".into())
        .unwrap()
        .validate(&NativeCreate::decode(&bytes, &r, &p).unwrap())
        .await
        .is_err());
    r.image.clear();
    s.spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .image
        .clear();
    assert!(native
        .validate(&NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap())
        .await
        .is_err());
}
