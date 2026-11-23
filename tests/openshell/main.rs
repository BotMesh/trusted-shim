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
    openshell_gateway::GatewayLaunch,
    runtime::LaunchRequest,
};

#[test]
fn gateway_workspace_mapping_keeps_full_canonical_identity_bound() {
    use trusted_shim::openshell_gateway::workspace_name;
    for namespace in [
        "test",
        "a".repeat(32).as_str(),
        "User.Namespace",
        "double--hyphen",
    ] {
        let (mut launch, mut sandbox, _) = fixture();
        launch.execution.namespace = namespace.into();
        let policy = sandbox.spec.as_ref().unwrap().policy.clone().unwrap();
        let binding = GatewayLaunch::new(launch.clone(), policy).unwrap();
        let mapped = workspace_name(namespace);
        assert!(mapped.len() <= 19 && !mapped.contains("--"));
        sandbox.workspace = mapped.clone();
        sandbox.name = binding.request().name;
        sandbox.status.as_mut().unwrap().name = sandbox.name.clone();
        binding.bind(&sandbox.encode_to_vec()).unwrap();
        assert_eq!(workspace_name(namespace), mapped);
        if namespace == "test" {
            assert_eq!(mapped, namespace);
        }
        let mut other = launch;
        other.execution.namespace.push('x');
        assert!(
            NativeCreate::decode(&sandbox.encode_to_vec(), &other, binding.policy_sha256())
                .is_err()
        );
    }
}

mod native_gateway;

fn fixture() -> (LaunchRequest, DriverSandbox, String) {
    let mut request: LaunchRequest = serde_json::from_value(serde_json::json!({
        "execution":{"namespace":"test","workload":"agent","allocation_id":"agent-0","lease_id":"one","generation":1,"node_id":"node"},
        "driver":"docker","image":"agent@sha256:approved","command":["agent","serve"],"environment":{"MODEL":"test"},
        "limits":{"cpu_millicores":500,"memory_bytes":67108864},
        "policy":{"issuer":"central","policy_id":"create","version":1,"sha256":"a".repeat(64)},
        "trust":{"attestation":{"mode":"skip_non_tee"},"policy_proof":"not_required","attestation_proof":"not_required"},"services":[]
    })).unwrap();
    let policy = SandboxPolicy::default();
    let hash = deterministic_policy_hash(&policy);
    request.access_policy_sha256 = Some(hash.clone());
    let sandbox = DriverSandbox {
        id: "sandbox-1".into(),
        name: "agent-1".into(),
        // Matches the stock gateway's driver_sandbox_from_public conversion:
        // platform namespace is driver-owned; workspace is the tenant.
        namespace: String::new(),
        workspace: "test".into(),
        status: Some(DriverSandboxStatus {
            name: "agent-1".into(),
            conditions: vec![DriverCondition {
                r#type: "ConfigurationReady".into(),
                status: "False".into(),
                reason: "ConfigurationPending".into(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        spec: Some(DriverSandboxSpec {
            environment: request.environment.clone().into_iter().collect(),
            command: request.command.clone(),
            policy: Some(policy),
            launch_authentication: b"synthetic-split-auth".to_vec(),
            sandbox_token: "synthetic-bootstrap".into(),
            workload_identity: Some(WorkloadIdentityRequest::default()),
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
    };
    (request, sandbox, hash)
}

#[test]
fn native_service_targets_are_admitted_and_bound_to_the_create_proof() {
    let (mut launch, sandbox, policy_hash) = fixture();
    launch.services = serde_json::from_value(serde_json::json!([{
        "id":{"namespace":"test","workload":"agent","service":"http"},
        "protocol":"http1","endpoint_ref":"app"
    }]))
    .unwrap();
    launch.driver_options = serde_json::json!({"container_port":8090,"health_path":"/health"});
    let native = NativeCreate::decode(&sandbox.encode_to_vec(), &launch, &policy_hash).unwrap();
    let (authorization, _) = authorization(&launch, &native, "services");
    native
        .validate_authorization(&launch, &authorization)
        .unwrap();
    for changed in [
        serde_json::json!({"container_port":8091,"health_path":"/health"}),
        serde_json::json!({"container_port":8090,"health_path":"/different"}),
    ] {
        let mut other = launch.clone();
        other.driver_options = changed;
        assert!(native
            .validate_authorization(&other, &authorization)
            .is_err());
    }
    for mutation in 0..9 {
        let mut bad = launch.clone();
        match mutation {
            0 => bad.services[0].id.namespace = "another-tenant".into(),
            1 => bad.services[0].id.workload = "another-app".into(),
            2 => bad.services[0].id.service = "control".into(),
            3 => bad.services[0].endpoint_ref = "http://arbitrary-host".into(),
            4 => bad.services.push(bad.services[0].clone()),
            5 => bad.driver_options["container_port"] = 0.into(),
            6 => bad.driver_options["health_path"] = "//another-host/".into(),
            7 => bad.driver_options["image"] = "unapproved".into(),
            _ => bad.services[0].protocol = trusted_data_router::Protocol::Tcp,
        }
        assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &bad, &policy_hash).is_err());
    }
}

#[test]
fn native_tcp_services_bind_protocol_and_readiness_to_authorization() {
    let (mut launch, sandbox, hash) = fixture();
    launch.services = serde_json::from_value(serde_json::json!([{
        "id":{"namespace":"test","workload":"agent","service":"ssh"},
        "protocol":"tcp","endpoint_ref":"app"
    }]))
    .unwrap();
    launch.driver_options =
        serde_json::json!({"container_port":22,"health_path":"/","health_tcp_banner":"SSH-2.0-"});
    let native = NativeCreate::decode(&sandbox.encode_to_vec(), &launch, &hash).unwrap();
    let (authorization, _) = authorization(&launch, &native, "tcp");
    native
        .validate_authorization(&launch, &authorization)
        .unwrap();
    for field in 0..3 {
        let mut changed = launch.clone();
        match field {
            0 => changed.driver_options["health_tcp_banner"] = "other".into(),
            1 => changed.driver_options["container_port"] = 2222.into(),
            _ => {
                changed.services[0].protocol = trusted_data_router::Protocol::Http1;
                changed
                    .driver_options
                    .as_object_mut()
                    .unwrap()
                    .remove("health_tcp_banner");
            }
        }
        assert!(native
            .validate_authorization(&changed, &authorization)
            .is_err());
    }
    for banner in [
        serde_json::Value::Null,
        serde_json::json!(""),
        serde_json::json!("a".repeat(129)),
        serde_json::json!("SSH\n"),
        serde_json::json!("非ASCII"),
    ] {
        let mut bad = launch.clone();
        bad.driver_options["health_tcp_banner"] = banner;
        assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &bad, &hash).is_err());
    }
    let mut mixed = launch.clone();
    let mut http = mixed.services[0].clone();
    http.id.service = "http".into();
    http.protocol = trusted_data_router::Protocol::Http1;
    mixed.services.push(http);
    assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &mixed, &hash).is_err());
    launch.driver_options["health_path"] = "/ignored".into();
    assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &launch, &hash).is_err());
}

#[test]
fn native_ingress_and_logs_control_are_admitted_only_as_declared() {
    let (mut launch, sandbox, hash) = fixture();
    launch.services = serde_json::from_value(serde_json::json!([
        {"id":{"namespace":"test","workload":"agent","service":"chat"},"protocol":"http1","endpoint_ref":"ingress:chat"},
        {"id":{"namespace":"test","workload":"agent","service":"api"},"protocol":"http1","endpoint_ref":"app"},
        {"id":{"namespace":"test","workload":"agent","service":"control"},"protocol":"http1","endpoint_ref":"control"}
    ]))
    .unwrap();
    launch.driver_options = serde_json::json!({"container_port":18789,"health_path":"/health",
        "ingress":{"chat":{"paths":["/v1/chat/completions"],"methods":["POST"],"single_use":true}}});
    let native = NativeCreate::decode(&sandbox.encode_to_vec(), &launch, &hash).unwrap();
    let options = trusted_shim::openshell_services::ServiceOptions::from_request(&launch)
        .unwrap()
        .unwrap();
    assert!(options.ingress["chat"].single_use && options.ingress["chat"].bearer_env.is_none());
    // The rules are part of the authorized launch, not a later network choice.
    let (authorization, _) = authorization(&launch, &native, "ingress");
    native
        .validate_authorization(&launch, &authorization)
        .unwrap();
    let mut widened = launch.clone();
    widened.driver_options["ingress"]["chat"]["paths"] =
        serde_json::json!(["/v1/chat/completions", "/admin"]);
    assert!(native
        .validate_authorization(&widened, &authorization)
        .is_err());
    for mutation in 0..10 {
        let mut bad = launch.clone();
        match mutation {
            // A node holds no application credential to inject.
            0 => {
                bad.driver_options["ingress"]["chat"]["bearer_env"] =
                    "OPENCLAW_GATEWAY_TOKEN".into()
            }
            1 => bad.services[0].endpoint_ref = "app".into(),
            2 => bad.services[1].endpoint_ref = "ingress:api".into(),
            3 => bad.services[2].endpoint_ref = "app".into(),
            4 => bad.services[2].protocol = trusted_data_router::Protocol::Tcp,
            5 => bad.services.push(bad.services[2].clone()),
            6 => {
                bad.driver_options["ingress"]["missing"] =
                    bad.driver_options["ingress"]["chat"].clone()
            }
            7 => bad.driver_options["ingress"]["chat"]["paths"] = serde_json::json!(["/a/../b"]),
            8 => bad.services.clear(),
            _ => bad.services.drain(..2).for_each(drop),
        }
        assert!(
            NativeCreate::decode(&sandbox.encode_to_vec(), &bad, &hash).is_err(),
            "{mutation}"
        );
    }
    // Ingress is HTTP only; logs-only control stays HTTP beside a TCP service.
    let mut tcp = launch.clone();
    tcp.services.remove(0);
    tcp.services[0].protocol = trusted_data_router::Protocol::Tcp;
    tcp.driver_options =
        serde_json::json!({"container_port":22,"health_path":"/","health_tcp_banner":"SSH-2.0-"});
    NativeCreate::decode(&sandbox.encode_to_vec(), &tcp, &hash).unwrap();
    tcp.driver_options["ingress"] = serde_json::json!({"api":{"paths":["/"],"methods":["GET"]}});
    assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &tcp, &hash).is_err());
}

#[test]
fn control_observation_strips_native_credentials_endpoints_and_diagnostics() {
    let (_, mut s, _) = fixture();
    let status = s.status.as_mut().unwrap();
    status.agent_fd = "127.0.0.1:secret".into();
    status.sandbox_fd = "unix:///private/supervisor".into();
    status.conditions[0].message = "secret diagnostic".into();
    status.instance_id = "native-instance".into();
    status.fence_evidence = Some(DriverFenceEvidence {
        generation: "generation".into(),
        evidence_digest: "a".repeat(64),
        resource_claims: Default::default(),
    });
    let safe = trusted_shim::openshell_gateway::control_observation(&s).unwrap();
    assert!(safe.spec.is_none());
    let status = safe.status.as_ref().unwrap();
    assert!(status.agent_fd.is_empty() && status.sandbox_fd.is_empty());
    assert!(status.conditions[0].message.is_empty());
    assert_eq!(status.instance_id, "native-instance");
    assert_eq!(
        status.fence_evidence,
        s.status.as_ref().unwrap().fence_evidence
    );
    assert_eq!(
        trusted_shim::openshell_gateway::control_observation(&safe).unwrap(),
        safe
    );
    s.status.as_mut().unwrap().instance_id = "x".repeat(16385);
    assert!(trusted_shim::openshell_gateway::control_observation(&s).is_err());
}

#[test]
fn native_gateway_pending_status_and_identity_selectors_cannot_claim_execution_authority() {
    use openshell_core::proto::sandbox::v1::ProcessPolicy;
    let (mut r, mut sandbox, _) = fixture();
    let spec = sandbox.spec.as_mut().unwrap();
    spec.policy.as_mut().unwrap().process = Some(ProcessPolicy {
        run_as_user: "1000".into(),
        run_as_group: "1000".into(),
    });
    spec.workload_identity = Some(WorkloadIdentityRequest {
        user: "1000".into(),
        group: "1000".into(),
    });
    let p = deterministic_policy_hash(spec.policy.as_ref().unwrap());
    r.access_policy_sha256 = Some(p.clone());
    assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &r, &p).is_ok());
    for change in 0..11 {
        let mut s = sandbox.clone();
        match change {
            0 => s.workspace = "another-tenant".into(),
            1 => s.status.as_mut().unwrap().name = "another-sandbox".into(),
            2 => s.status.as_mut().unwrap().instance_id = "existing-runtime".into(),
            3 => s.status.as_mut().unwrap().agent_fd = "127.0.0.1:1234".into(),
            4 => s.status.as_mut().unwrap().sandbox_fd = "127.0.0.1:1234".into(),
            5 => s.status.as_mut().unwrap().deleting = true,
            6 => s.status.as_mut().unwrap().conditions[0].status = "True".into(),
            7 => {
                s.status.as_mut().unwrap().resolved_identity =
                    Some(ResolvedWorkloadIdentity::default())
            }
            8 => s.status.as_mut().unwrap().fence_evidence = Some(DriverFenceEvidence::default()),
            9 => {
                s.spec
                    .as_mut()
                    .unwrap()
                    .workload_identity
                    .as_mut()
                    .unwrap()
                    .user = "0".into()
            }
            _ => s.spec.as_mut().unwrap().workload_identity = None,
        }
        assert!(
            NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_err(),
            "change {change}"
        );
    }
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

#[test]
fn native_launch_refuses_a_cpu_weight_it_cannot_enforce() {
    // The native driver takes CPU and memory hard limits only. A requested
    // CPU weight is refused, never dropped from the create.
    let (mut r, s, p) = fixture();
    let policy = s.spec.as_ref().unwrap().policy.clone().unwrap();
    r.limits.cpu_shares = Some(64);
    assert!(matches!(
        NativeCreate::decode(&s.encode_to_vec(), &r, &p),
        Err(trusted_shim::Error::Unsupported)
    ));
    assert!(matches!(
        GatewayLaunch::new(r.clone(), policy.clone()),
        Err(trusted_shim::Error::Unsupported)
    ));
    r.limits.cpu_shares = None;
    assert!(NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_ok());
    assert!(GatewayLaunch::new(r, policy).is_ok());
}

#[test]
fn gateway_binding_fences_every_allocation_field_and_requires_native_credentials() {
    let (launch, mut sandbox, _) = fixture();
    let policy = sandbox.spec.as_ref().unwrap().policy.clone().unwrap();
    let binding = GatewayLaunch::new(launch.clone(), policy.clone()).unwrap();
    let request = binding.request();
    assert_eq!(request.name.len(), 19);
    sandbox.name = request.name.clone();
    sandbox.status.as_mut().unwrap().name = sandbox.name.clone();
    assert!(binding.bind(&sandbox.encode_to_vec()).is_ok());
    let mut proposal = sandbox.clone();
    proposal
        .spec
        .as_mut()
        .unwrap()
        .launch_authentication
        .clear();
    proposal.spec.as_mut().unwrap().sandbox_token.clear();
    binding.validate_proposal(&proposal).unwrap();
    assert!(binding.bind(&proposal.encode_to_vec()).is_err());
    for field in 0..6 {
        let mut changed = launch.clone();
        match field {
            0 => changed.execution.namespace.push('x'),
            1 => changed.execution.workload.push('x'),
            2 => changed.execution.allocation_id.push('x'),
            3 => changed.execution.lease_id.push('x'),
            4 => changed.execution.generation += 1,
            _ => changed.execution.node_id.push('x'),
        }
        let other = GatewayLaunch::new(changed, policy.clone()).unwrap();
        assert_ne!(other.request().name, request.name);
        assert!(other.validate_proposal(&proposal).is_err());
        assert!(other.bind(&sandbox.encode_to_vec()).is_err());
    }
    let mut changed_policy = policy.clone();
    changed_policy.version += 1;
    assert!(GatewayLaunch::new(launch.clone(), changed_policy).is_err());
    let mut unsupported = launch.clone();
    unsupported.driver_options = serde_json::json!({"privileged":true});
    assert!(GatewayLaunch::new(unsupported, policy.clone()).is_err());
    let mut unsupported = launch;
    unsupported.trust.policy_proof = trusted_shim::proof::ProofRequirement::Required;
    assert!(GatewayLaunch::new(unsupported, policy).is_err());
}

#[test]
fn private_envelope_rejects_native_substitution_even_with_matching_request_digest() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let (launch, sandbox, policy) = fixture();
    let bytes = sandbox.encode_to_vec();
    let native = NativeCreate::decode(&bytes, &launch, &policy).unwrap();
    let make = |authorization, grant| {
        trusted_shim::provisioning::ProvisionRequest::new(
            launch.clone(),
            &bytes,
            policy.clone(),
            authorization,
            grant,
            "b".repeat(64),
        )
        .unwrap()
    };
    let (a, g) = authorization(&launch, &native, "one");
    let mut envelope = make(a, g);
    envelope.validate_native().unwrap();
    let mut replaced = sandbox;
    replaced.spec.as_mut().unwrap().sandbox_token = "substituted-native-credential".into();
    envelope.native_create_base64 = STANDARD.encode(replaced.encode_to_vec());
    assert!(envelope.validate_native().is_err());
    for field in 0..3 {
        let (mut a, mut g) = authorization(&launch, &native, "one");
        match field {
            0 => a.resource = "openshell/sandbox/another".into(),
            1 => a.parameters["native_sha256"] = "f".repeat(64).into(),
            _ => a.parameters["launch_sha256"] = "f".repeat(64).into(),
        }
        // The envelope/grant pair agrees with itself, but not the native input.
        g.request_sha256 = trusted_rail::rego::request_digest(&a).unwrap();
        let envelope = make(a, g);
        envelope.validate().unwrap();
        assert!(envelope.validate_native().is_err());
    }
}

#[derive(Clone, Default)]
struct Service {
    // The real gateway acceptance captures its private create message and
    // refuses provisioning; no synthetic credentials cross a native boundary.
    capture: Option<Arc<Mutex<Option<DriverSandbox>>>>,
    gateway_launch: Option<Arc<GatewayLaunch>>,
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
            resource_admission_policy: if self.capture.is_some() {
                openshell_core::resource_admission::DriverAdmissionConfig::default()
                    .acknowledgement()
            } else if self.wrong_admission.load(Ordering::SeqCst) {
                "different".into()
            } else {
                "approved".into()
            },
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
        r: Request<ValidateSandboxCreateRequest>,
    ) -> std::result::Result<Response<ValidateSandboxCreateResponse>, Status> {
        if let Some(binding) = &self.gateway_launch {
            binding
                .validate_proposal(
                    r.get_ref()
                        .sandbox
                        .as_ref()
                        .ok_or(Status::invalid_argument("missing sandbox"))?,
                )
                .map_err(|_| Status::permission_denied("launch does not match allocation"))?;
        }
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }
    async fn create_sandbox(
        &self,
        r: Request<CreateSandboxRequest>,
    ) -> std::result::Result<Response<CreateSandboxResponse>, Status> {
        self.created.fetch_add(1, Ordering::SeqCst);
        let mut sandbox = r.into_inner().sandbox.unwrap();
        if let Some(binding) = &self.gateway_launch {
            binding
                .bind(&sandbox.encode_to_vec())
                .map_err(|_| Status::permission_denied("launch does not match allocation"))?;
        }
        if let Some(capture) = &self.capture {
            *capture.lock().unwrap() = Some(sandbox);
            return Err(Status::failed_precondition(
                "acceptance capture; no runtime dispatched",
            ));
        }
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
        Ok(Response::new(ListSandboxesResponse { sandboxes: vec![] }))
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
        Ok(Response::new(EnsureWorkspaceResponse::default()))
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
async fn native_services_require_authenticated_host_identity_before_consumption() {
    let h = Harness::new().await;
    let (mut launch, sandbox, policy) = fixture();
    launch.services = serde_json::from_value(serde_json::json!([{
        "id":{"namespace":"test","workload":"agent","service":"http"},
        "protocol":"http1","endpoint_ref":"app"
    }]))
    .unwrap();
    launch.driver_options = serde_json::json!({"container_port":8090,"health_path":"/health"});
    let native = NativeCreate::decode(&sandbox.encode_to_vec(), &launch, &policy).unwrap();
    let (authorization, grant) = authorization(&launch, &native, "services");
    assert!(matches!(
        h.driver()
            .launch(&launch, native, &authorization, &grant, h.ledger.as_ref())
            .await,
        Err(trusted_shim::Error::Untrusted)
    ));
    assert!(h.ledger.consumed.lock().unwrap().is_empty());
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
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
    let status = h
        .driver()
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .unwrap();
    assert_eq!(status.phase, ProvisioningPhase::Created);
    assert!(status.platform_ready);
    let public = serde_json::to_string(&status).unwrap();
    assert!(!public.contains("synthetic"));
    // Reopen durable state with a fresh driver and replay the exact request.
    let recovered = h.driver();
    recovered
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .unwrap();
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
    assert!(recovered
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .is_err());
    let mut next = r.clone();
    next.execution.lease_id = "two".into();
    let mut sandbox = s.clone();
    sandbox.id = "sandbox-2".into();
    sandbox.name = "agent-2".into();
    sandbox.status.as_mut().unwrap().name = sandbox.name.clone();
    let bytes = sandbox.encode_to_vec();
    let native = NativeCreate::decode(&bytes, &next, &p).unwrap();
    let (a, g) = authorization(&next, &native, "two");
    assert!(recovered
        .launch(&next, native, &a, &g, h.ledger.as_ref())
        .await
        .is_err()); // same generation
    next.execution.generation += 1;
    let native = NativeCreate::decode(&bytes, &next, &p).unwrap();
    let (a, g) = authorization(&next, &native, "two");
    recovered
        .launch(&next, native, &a, &g, h.ledger.as_ref())
        .await
        .unwrap();
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
        assert!(h
            .driver()
            .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
            .await
            .is_err());
    }
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
    assert!(h.ledger.consumed.lock().unwrap().is_empty());
    let (a, g) = authorization(&r, &prepared(), "one");
    h.ledger.reject.store(true, Ordering::SeqCst);
    assert!(h
        .driver()
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .is_err());
    h.ledger.reject.store(false, Ordering::SeqCst);
    assert!(h
        .driver()
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .is_err());
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
    assert!(h
        .driver()
        .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
        .await
        .is_err());
    let recovered = h.driver();
    assert!(
        !recovered
            .launch(&r, prepared(), &a, &g, h.ledger.as_ref())
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

// Real central database and gRPC, with native-driver/proof doubles. This tests
// dispatch ordering and lost replies, not native isolation or ZK cryptography.
struct ProvisioningVerifier;
impl trusted_shim::proof::ReceiptVerifier for ProvisioningVerifier {
    fn verify(
        &self,
        _: &trusted_shim::proof::ProgramRef,
        receipt: &trusted_shim::proof::ProofReceipt,
        expected: &[u8],
    ) -> trusted_shim::Result<()> {
        if receipt.encoded_receipt == expected {
            Ok(())
        } else {
            Err(trusted_shim::Error::Untrusted)
        }
    }
}
struct ReplyLoss {
    inner: trusted_shim::ledger_transport::LedgerService,
    lose: bool,
}
#[tonic::async_trait]
impl trusted_shim::ledger_transport::wire::authorization_ledger_server::AuthorizationLedger
    for ReplyLoss
{
    async fn reserve(
        &self,
        r: Request<trusted_shim::ledger_transport::wire::ReserveRequest>,
    ) -> Result<Response<trusted_shim::ledger_transport::wire::Grant>, Status> {
        self.inner.reserve(r).await
    }
    async fn consume(
        &self,
        r: Request<trusted_shim::ledger_transport::wire::ConsumeRequest>,
    ) -> Result<Response<trusted_shim::ledger_transport::wire::ConsumeResponse>, Status> {
        let result = self.inner.consume(r).await?;
        if self.lose {
            Err(Status::unavailable("reply lost after commit"))
        } else {
            Ok(result)
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_dispatch_requires_unambiguous_consumption_at_remote_central_ledger() {
    native_dispatch_at_remote(false).await;
}

#[tokio::test]
async fn daemon_provisioning_survives_restarts_and_gateway_outages_without_storing_credentials() {
    native_dispatch_at_remote(true).await;
}

async fn native_dispatch_at_remote(via_daemon: bool) {
    use trusted_rail::{rego::*, *};
    use trusted_shim::{
        contracts::ProofKind,
        ledger::{LedgerPermission, SqliteLedger},
        ledger_transport::{wire, LedgerService, RemoteLedger},
        openshell_lifecycle::ManagedNativeDriver,
        proof::ProgramRef,
    };
    for lose in [false, true] {
        let h = Harness::new().await;
        let central_dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(central_dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let central = Arc::new(
            SqliteLedger::open(
                &central_dir.path().join("ledger.sqlite"),
                ProgramRef {
                    kind: ProofKind::PolicyEvaluation,
                    program_sha256: "1".repeat(64),
                    verifying_key_sha256: "2".repeat(64),
                },
                Arc::new(ProvisioningVerifier),
            )
            .unwrap(),
        );
        let (mut r, sandbox, native_policy) = fixture();
        let mut policy = PolicyBundle { policy: r.policy.clone(), engine: engine_profile(), modules: [("create.rego".into(), "package trusted\ndecision := {\"decision\":\"allow\",\"reason_codes\":[]} if { input.operation == \"runtime.create\" }".into())].into(), data: serde_json::json!({}) };
        policy.policy.sha256 = policy_digest(&policy).unwrap();
        r.policy = policy.policy.clone();
        let bytes = sandbox.encode_to_vec();
        let prepared = || NativeCreate::decode(&bytes, &r, &native_policy).unwrap();
        let (request, _) = authorization(&r, &prepared(), "remote-create");
        central.set_budget("create", 1).unwrap();
        central
            .activate(
                &request.execution,
                &policy,
                &request.context,
                &request.previous_state_root,
                "create",
            )
            .unwrap();
        central.stage("remote-create", &request, 1).unwrap();
        let decision = RegorusEngine.evaluate(&policy, &request).unwrap();
        let grant = central
            .reserve(&decision, Some(&encode_public_values(&decision).unwrap()))
            .await
            .unwrap();
        let token = central
            .issue_access(&r.execution, LedgerPermission::Execution, &request.validity)
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let rpc = ReplyLoss {
            inner: LedgerService::new(central.clone()),
            lose,
        };
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(wire::authorization_ledger_server::AuthorizationLedgerServer::new(rpc))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        if via_daemon {
            use serde_json::json;
            use tokio::{
                io::{AsyncReadExt, AsyncWriteExt},
                net::UnixStream,
            };
            use tokio_util::sync::CancellationToken;
            use trusted_shim::{
                daemon::{serve_configured, DaemonConfig},
                openshell_daemon::OpenShellConfig,
                provisioning::ProvisionRequest,
            };
            let socket = h.state.join("control.sock");
            let start = || {
                let state = h.state.clone();
                let stop = CancellationToken::new();
                let stopped = stop.clone();
                let config = DaemonConfig {
                    machine: Default::default(),
                    openshell: Some(OpenShellConfig {
                        socket: h._dir.path().join("driver.sock"),
                        admission_policy: "approved".into(),
                        ledger_endpoint: address.clone(),
                        ledger_ca_file: None,
                        supervisor_image: None,
                    }),
                };
                let task = tokio::spawn(async move {
                    serve_configured(&state, "node".into(), config, stopped).await
                });
                (stop, task)
            };
            let call = |command| {
                let socket = socket.clone();
                async move {
                    for _ in 0..100 {
                        if socket.exists() {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    let mut stream = UnixStream::connect(socket).await.unwrap();
                    let bytes = serde_json::to_vec(
                        &json!({"protocol":1,"node_id":"node","command":command}),
                    )
                    .unwrap();
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut bytes = Vec::new();
                    stream.read_to_end(&mut bytes).await.unwrap();
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
                }
            };
            let (stop, task) = start();
            let copy = trusted_rail::ExecutionGrant {
                id: grant.id.clone(),
                credential: grant.credential.clone(),
                execution: grant.execution.clone(),
                request_sha256: grant.request_sha256.clone(),
                validity: grant.validity.clone(),
            };
            let payload = ProvisionRequest::new(
                r.clone(),
                &bytes,
                native_policy.clone(),
                request.clone(),
                copy,
                token.clone(),
            )
            .unwrap();
            let command = json!({"operation":"provision","payload":payload});
            let caps = call(json!({"operation":"capabilities"})).await;
            let allocated =
                call(json!({"operation":"allocate","driver":"docker","execution":r.execution}))
                    .await;
            assert_eq!(allocated["result"]["phase"], "reserved");
            let mut stripped = r.clone();
            stripped.access_policy_sha256 = None;
            assert!(call(json!({"operation":"launch", "request":stripped}))
                .await
                .get("error")
                .is_some());
            assert_eq!(caps["result"]["drivers"], json!(["docker"]));
            assert_eq!(caps["result"]["access_policy"]["default"], "driver_bounds");
            assert!(caps["result"]["features"]
                .as_array()
                .unwrap()
                .contains(&json!("openshell-provisioning-v1")));
            // Attachments are advertised only by an allow_driver_config policy.
            assert!(!caps["result"]["features"]
                .as_array()
                .unwrap()
                .contains(&json!("openshell-attachments-v1")));
            for changed in ["execution", "native", "token", "endpoint"] {
                let mut bad = command.clone();
                match changed {
                    "execution" => {
                        bad["payload"]["request"]["execution"]["namespace"] = json!("other")
                    }
                    "native" => bad["payload"]["native_policy_sha256"] = json!("f".repeat(64)),
                    "token" => bad["payload"]["ledger_token"] = json!("f".repeat(64)),
                    _ => bad["payload"]["ledger_endpoint"] = json!("http://127.0.0.1:1"),
                }
                // A rejected Consume is durably fenced, so use malformed tokens
                // here to exercise pre-dispatch validation without claiming a slot.
                if changed == "token" {
                    bad["payload"]["ledger_token"] = json!("malformed");
                }
                assert!(call(bad).await.get("error").is_some());
                assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
            }
            assert_eq!(call(command.clone()).await.get("error").is_none(), !lose);
            assert!(central
                .consume(&grant, &grant.execution, &grant.request_sha256)
                .await
                .is_err());
            stop.cancel();
            task.await.unwrap().unwrap();
            central.revoke_access(&token).unwrap();
            server.abort();
            // Restart the shim with no live authority connection. No second
            // Consume/Create; inspection and cleanup still use durable ownership.
            let (stop, task) = start();
            assert_eq!(call(command).await.get("error").is_none(), !lose);
            let status =
                call(json!({"operation":"inspect","driver":"docker","execution":r.execution}))
                    .await;
            assert!(status.get("error").is_none());
            assert!(status["result"].get("ready").is_none()); // platform is not application readiness
            assert_eq!(h.service.created.load(Ordering::SeqCst), usize::from(!lose));
            let mut other = r.execution.clone();
            other.lease_id = "wrong".into();
            assert!(
                call(json!({"operation":"delete","driver":"docker","execution":other}))
                    .await
                    .get("error")
                    .is_some()
            );
            assert_eq!(
                call(json!({"operation":"delete","driver":"docker","execution":r.execution})).await
                    ["result"]["cleaned"],
                true
            );
            stop.cancel();
            task.await.unwrap().unwrap();
        } else {
            let remote = Arc::new(
                RemoteLedger::connect(&address, &token, r.execution.clone())
                    .await
                    .unwrap(),
            );
            let driver =
                ManagedNativeDriver::open(h.state.clone(), "node".into(), h.native.clone())
                    .unwrap();
            let result = driver
                .launch(&r, prepared(), &request, &grant, remote.as_ref())
                .await;
            assert_eq!(result.is_ok(), !lose);
            assert_eq!(h.service.created.load(Ordering::SeqCst), usize::from(!lose));
            assert!(central
                .consume(&grant, &grant.execution, &grant.request_sha256)
                .await
                .is_err());
            drop(driver);
            let driver =
                ManagedNativeDriver::open(h.state.clone(), "node".into(), h.native.clone())
                    .unwrap();
            assert_eq!(
                driver
                    .launch(&r, prepared(), &request, &grant, remote.as_ref())
                    .await
                    .is_ok(),
                !lose
            );
            assert_eq!(h.service.created.load(Ordering::SeqCst), usize::from(!lose));
            central.revoke_access(&token).unwrap();
            driver.delete(&r.execution).await.unwrap();
        }
        server.abort();
        // Neither the central bearer nor grant secret is persisted on the node.
        for entry in std::fs::read_dir(&h.state).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let bytes = std::fs::read(path).unwrap();
            assert!(!bytes
                .windows(token.len())
                .any(|part| part == token.as_bytes()));
            assert!(!bytes
                .windows(grant.credential.len())
                .any(|part| part == grant.credential));
        }
    }
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

#[tokio::test]
async fn reservations_survive_restart_and_cancel_without_native_or_ledger_access() {
    use trusted_shim::openshell_lifecycle::ProvisioningPhase;
    let h = Harness::new().await;
    let (mut request, sandbox, policy) = fixture();
    h.task.abort(); // Reserving/cancelling must work even with the compute driver down.
    let status = h.driver().reserve(&request.execution).await.unwrap();
    assert_eq!(status.phase, ProvisioningPhase::Reserved);
    assert!(!status.present && !status.platform_ready && status.sandbox_id.is_empty());
    assert_eq!(
        h.driver().reserve(&request.execution).await.unwrap().phase,
        ProvisioningPhase::Reserved
    );
    let mut future = request.execution.clone();
    future.generation += 1;
    future.lease_id = "next".into();
    assert!(h.driver().reserve(&future).await.is_err());
    h.driver().delete(&request.execution).await.unwrap();
    assert_eq!(
        h.driver().reserve(&request.execution).await.unwrap().phase,
        ProvisioningPhase::Deleted
    );
    let native = NativeCreate::decode(&sandbox.encode_to_vec(), &request, &policy).unwrap();
    let (a, g) = authorization(&request, &native, "late");
    assert!(h
        .driver()
        .launch(&request, native, &a, &g, h.ledger.as_ref())
        .await
        .is_err());
    assert!(h.ledger.consumed.lock().unwrap().is_empty());
    request.execution = future;
    assert_eq!(
        h.driver().reserve(&request.execution).await.unwrap().phase,
        ProvisioningPhase::Reserved
    );
    h.driver().stop(&request.execution).await.unwrap();
    assert_eq!(
        h.driver().reserve(&request.execution).await.unwrap().phase,
        ProvisioningPhase::Stopped
    );
    h.driver().delete(&request.execution).await.unwrap();
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reserved_allocation_is_created_once_under_concurrent_replay() {
    let h = Harness::new().await;
    let (r, s, p) = fixture();
    h.driver().reserve(&r.execution).await.unwrap();
    let bytes = s.encode_to_vec();
    let native = || NativeCreate::decode(&bytes, &r, &p).unwrap();
    let (a, g) = authorization(&r, &native(), "reserved");
    let one = h.driver();
    let two = h.driver();
    let (x, y) = tokio::join!(
        one.launch(&r, native(), &a, &g, h.ledger.as_ref()),
        two.launch(&r, native(), &a, &g, h.ledger.as_ref())
    );
    assert!(x.is_ok() && y.is_ok());
    assert_eq!(h.service.created.load(Ordering::SeqCst), 1);
    assert_eq!(h.ledger.consumed.lock().unwrap().len(), 1);
}

#[path = "../support/tee.rs"]
mod tee_support;

#[tokio::test]
async fn native_tee_gate_precedes_policy_consumption_and_create_and_survives_replay() {
    use tee_support::{Lab, ProofDouble};
    for bad_quote in [true, false] {
        let lab = Lab::start(bad_quote, None).await;
        let h = Harness::new().await;
        let proof = Arc::new(ProofDouble::default());
        let gate_root = tempfile::tempdir().unwrap();
        let tee = lab
            .driver(gate_root.path(), proof.clone(), !bad_quote)
            .await;
        let (r, s, p) = fixture();
        let native = NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap();
        let (a, g) = authorization(&r, &native, "rejected-ra");
        assert!(h
            .driver()
            .launch_with_attestation(&r, native, &a, &g, h.ledger.as_ref(), Some(tee.gate()))
            .await
            .is_err());
        assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
        assert!(h.ledger.consumed.lock().unwrap().is_empty());
    }
    let lab = Lab::start(false, None).await;
    let h = Harness::new().await;
    let proof = Arc::new(ProofDouble::default());
    let gate_root = tempfile::tempdir().unwrap();
    let tee = lab.driver(gate_root.path(), proof.clone(), false).await;
    let (r, s, p) = fixture();
    let bytes = s.encode_to_vec();
    let native = || NativeCreate::decode(&bytes, &r, &p).unwrap();
    let (a, g) = authorization(&r, &native(), "accepted-ra");
    h.driver()
        .launch_with_attestation(&r, native(), &a, &g, h.ledger.as_ref(), Some(tee.gate()))
        .await
        .unwrap();
    // A restart must only observe the existing native sandbox, even if the
    // proof service is unavailable. It cannot consume another grant or create.
    drop(tee);
    let tee = lab.driver(gate_root.path(), proof.clone(), true).await;
    drop(lab);
    h.driver()
        .launch_with_attestation(&r, native(), &a, &g, h.ledger.as_ref(), Some(tee.gate()))
        .await
        .unwrap();
    assert_eq!(h.service.created.load(Ordering::SeqCst), 1);
    assert_eq!(h.ledger.consumed.lock().unwrap().len(), 1);
    assert_eq!(proof.submitted.load(Ordering::SeqCst), 1);
    h.driver().delete(&r.execution).await.unwrap();
    assert!(h
        .driver()
        .launch_with_attestation(&r, native(), &a, &g, h.ledger.as_ref(), Some(tee.gate()))
        .await
        .is_err());
}

#[tokio::test]
async fn expired_native_ra_cannot_consume_a_grant_or_dispatch() {
    use sha2::{Digest, Sha256};
    use tee_support::{Lab, ProofDouble};
    let lab = Lab::start(false, None).await;
    let h = Harness::new().await;
    let proof = Arc::new(ProofDouble::default());
    let root = tempfile::tempdir().unwrap();
    let tee = lab.driver(root.path(), proof, false).await;
    let (r, s, p) = fixture();
    let native = NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap();
    let (a, g) = authorization(&r, &native, "expired-ra");
    tee.gate()
        .authorize(&r.execution, &native.authorization_parameters())
        .await
        .unwrap();
    let path = root.path().join("tee").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(
            trusted_shim::tee::canonical(&r.execution).unwrap()
        ))
    ));
    let mut pending: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    pending["binding"]["expires_at"] = 0.into();
    std::fs::write(path, serde_json::to_vec(&pending).unwrap()).unwrap();
    assert!(h
        .driver()
        .launch_with_attestation(&r, native, &a, &g, h.ledger.as_ref(), Some(tee.gate()))
        .await
        .is_err());
    assert_eq!(h.service.created.load(Ordering::SeqCst), 0);
    assert!(h.ledger.consumed.lock().unwrap().is_empty());
}

#[test]
fn user_access_policy_is_independent_of_driver_and_cannot_be_dropped_or_substituted() {
    let (mut request, sandbox, hash) = fixture();
    for driver in ["docker", "tee", "tee-simulation"] {
        request.driver = driver.into();
        NativeCreate::decode(&sandbox.encode_to_vec(), &request, &hash).unwrap();
        assert!(trusted_shim::access::driver_bounds(&request).is_err());
        let mut missing = request.clone();
        missing.access_policy_sha256 = None;
        trusted_shim::access::driver_bounds(&missing).unwrap();
        assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &missing, &hash).is_err());
        request.access_policy_sha256 = Some("ff".repeat(32));
        assert!(NativeCreate::decode(&sandbox.encode_to_vec(), &request, &hash).is_err());
        request.access_policy_sha256 = Some(hash.clone());
    }
}

fn attachments() -> (LaunchRequest, DriverSandbox, String) {
    use prost_types::{value::Kind, ListValue, Struct, Value};
    let (mut r, mut s, p) = fixture();
    r.gpus = vec!["0".into(), "3".into()];
    r.mounts = serde_json::from_value(serde_json::json!([
        {"name":"models","target":"/models","read_only":true},
        {"name":"state","target":"/var/lib/agent"}
    ]))
    .unwrap();
    let text = |v: &str| Value {
        kind: Some(Kind::StringValue(v.into())),
    };
    let list = |values: Vec<Value>| Value {
        kind: Some(Kind::ListValue(ListValue { values })),
    };
    // Built independently of the adapter: upstream's documented Docker schema.
    let volume = |name: &str, target: &str, read_only: bool| Value {
        kind: Some(Kind::StructValue(Struct {
            fields: [
                ("type".into(), text("volume")),
                (
                    "source".into(),
                    text(
                        &trusted_shim::openshell::attachments::volume_name(
                            &r,
                            &serde_json::from_value(
                                serde_json::json!({"name":name,"target":target}),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                ),
                ("target".into(), text(target)),
                (
                    "read_only".into(),
                    Value {
                        kind: Some(Kind::BoolValue(read_only)),
                    },
                ),
            ]
            .into(),
        })),
    };
    let spec = s.spec.as_mut().unwrap();
    spec.resource_requirements = Some(ResourceRequirements {
        gpu: Some(GpuResourceRequirements { count: Some(2) }),
    });
    spec.template.as_mut().unwrap().driver_config = Some(Struct {
        fields: [
            (
                "cdi_devices".into(),
                list(vec![text("nvidia.com/gpu=0"), text("nvidia.com/gpu=3")]),
            ),
            (
                "mounts".into(),
                list(vec![
                    volume("models", "/models", true),
                    volume("state", "/var/lib/agent", false),
                ]),
            ),
        ]
        .into(),
    });
    (r, s, p)
}

#[test]
fn native_gpus_and_durable_mounts_are_exactly_the_fleet_grant() {
    use prost_types::{value::Kind, Value};
    let (r, s, p) = attachments();
    assert!(NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_ok());

    // The public request carries the same grant in the driver-keyed envelope.
    let policy = s.spec.as_ref().unwrap().policy.clone().unwrap();
    let public = GatewayLaunch::new(r.clone(), policy.clone())
        .unwrap()
        .request()
        .spec
        .unwrap();
    assert_eq!(
        public.resource_requirements.unwrap().gpu.unwrap().count,
        Some(2)
    );
    let envelope = public.template.unwrap().driver_config.unwrap();
    assert_eq!(envelope.fields.len(), 1);
    assert_eq!(
        envelope.fields["docker"].kind,
        Some(Kind::StructValue(
            s.spec
                .as_ref()
                .unwrap()
                .template
                .as_ref()
                .unwrap()
                .driver_config
                .clone()
                .unwrap()
        ))
    );

    let config = |s: &mut DriverSandbox| {
        s.spec
            .as_mut()
            .unwrap()
            .template
            .as_mut()
            .unwrap()
            .driver_config
            .as_mut()
            .unwrap()
            .fields
            .clone()
    };
    for change in 0..9 {
        let mut s = s.clone();
        let mut fields = config(&mut s);
        let spec = s.spec.as_mut().unwrap();
        match change {
            // A driver-chosen default could pick a GPU Ray gave someone else.
            0 => {
                spec.resource_requirements.as_mut().unwrap().gpu =
                    Some(GpuResourceRequirements { count: None })
            }
            1 => spec.resource_requirements = None,
            2 => {
                fields.insert(
                    "cdi_devices".into(),
                    Value {
                        kind: Some(Kind::ListValue(prost_types::ListValue {
                            values: vec![
                                Value {
                                    kind: Some(Kind::StringValue("nvidia.com/gpu=0".into())),
                                },
                                Value {
                                    kind: Some(Kind::StringValue("nvidia.com/gpu=1".into())),
                                },
                            ],
                        })),
                    },
                );
            }
            3 => {
                fields.remove("mounts");
            }
            4 => {
                fields.remove("cdi_devices");
            }
            5 => {
                fields.insert(
                    "extra".into(),
                    Value {
                        kind: Some(Kind::BoolValue(true)),
                    },
                );
            }
            6 => spec.template.as_mut().unwrap().driver_config = None,
            7 => {
                // Another workload's volume, even in the same namespace.
                let mut other = r.clone();
                other.execution.workload = "other".into();
                let mut mounts = fields["mounts"].clone();
                if let Some(Kind::ListValue(list)) = mounts.kind.as_mut() {
                    if let Some(Kind::StructValue(v)) = list.values[0].kind.as_mut() {
                        v.fields.insert(
                            "source".into(),
                            Value {
                                kind: Some(Kind::StringValue(
                                    trusted_shim::openshell::attachments::volume_name(
                                        &other,
                                        &r.mounts[0],
                                    )
                                    .unwrap(),
                                )),
                            },
                        );
                    }
                }
                fields.insert("mounts".into(), mounts);
            }
            _ => {
                spec.resource_requirements.as_mut().unwrap().gpu =
                    Some(GpuResourceRequirements { count: Some(1) })
            }
        }
        if !matches!(change, 0 | 1 | 6 | 8) {
            spec.template
                .as_mut()
                .unwrap()
                .driver_config
                .as_mut()
                .unwrap()
                .fields = fields;
        }
        assert!(
            NativeCreate::decode(&s.encode_to_vec(), &r, &p).is_err(),
            "variation {change} must be rejected"
        );
    }

    // A launch without attachments admits no driver config or GPU request.
    let (plain, mut native, p) = fixture();
    native
        .spec
        .as_mut()
        .unwrap()
        .template
        .as_mut()
        .unwrap()
        .driver_config = s
        .spec
        .as_ref()
        .unwrap()
        .template
        .as_ref()
        .unwrap()
        .driver_config
        .clone();
    assert!(NativeCreate::decode(&native.encode_to_vec(), &plain, &p).is_err());

    // Volumes survive replacement generations and allocations of one workload.
    let name = |r: &LaunchRequest| {
        trusted_shim::openshell::attachments::volume_name(r, &r.mounts[0]).unwrap()
    };
    let mut next = r.clone();
    next.execution.generation += 1;
    next.execution.allocation_id = "agent-1".into();
    next.execution.lease_id = "two".into();
    assert_eq!(name(&next), name(&r));
    for (field, value) in [("namespace", "other"), ("workload", "other")] {
        let mut other = r.clone();
        match field {
            "namespace" => other.execution.namespace = value.into(),
            _ => other.execution.workload = value.into(),
        }
        assert_ne!(name(&other), name(&r));
    }

    // Shapes that cannot be safely translated are rejected before any proof.
    for bad in 0..7 {
        let mut b = r.clone();
        match bad {
            0 => b.gpus.push("0".into()),
            1 => b.gpus = vec!["0/../1".into()],
            2 => b.mounts[0].name = "Models".into(),
            3 => b.mounts[0].target = "models".into(),
            4 => b.mounts[0].target = "/models/../etc".into(),
            5 => b.mounts[1].target = "/models".into(),
            _ => b.mounts[1].name = "models".into(),
        }
        assert!(
            GatewayLaunch::new(b.clone(), policy.clone()).is_err(),
            "shape {bad}"
        );
        assert!(
            NativeCreate::decode(&s.encode_to_vec(), &b, &p).is_err(),
            "shape {bad}"
        );
    }
}

#[tokio::test]
#[ignore = "requires OPENSHELL_NATIVE_DRIVER_SOCKET for an unmodified driver with allow_driver_config"]
async fn unmodified_native_driver_admits_shim_provisioned_workload_volumes() {
    let socket =
        std::env::var_os("OPENSHELL_NATIVE_DRIVER_SOCKET").expect("private native driver socket");
    let admission = openshell_core::resource_admission::DriverAdmissionConfig {
        allow_driver_config: true,
        ..Default::default()
    };
    let native = NativeDriver::new(socket.into(), admission.acknowledgement()).unwrap();
    let (mut r, mut s, p) = attachments();
    // No CDI GPU inventory is assumed here; GPU admission needs a GPU node.
    r.gpus.clear();
    let spec = s.spec.as_mut().unwrap();
    spec.resource_requirements = None;
    let template = spec.template.as_mut().unwrap();
    template
        .driver_config
        .as_mut()
        .unwrap()
        .fields
        .remove("cdi_devices");
    r.image = "alpine:3.21".into();
    template.image = r.image.clone();
    // Unique tenant per run; every volume below is removed at the end.
    let tenant = format!("vol{}", std::process::id());
    r.execution.namespace = tenant.clone();
    s.workspace = tenant.clone();
    let names: Vec<_> = r
        .mounts
        .iter()
        .map(|m| trusted_shim::openshell::attachments::volume_name(&r, m).unwrap())
        .collect();
    let fields = &mut template.driver_config.as_mut().unwrap().fields;
    // Rebuild the expected sources for this run's tenant.
    if let Some(prost_types::value::Kind::ListValue(list)) =
        fields.get_mut("mounts").and_then(|m| m.kind.as_mut())
    {
        for (value, name) in list.values.iter_mut().zip(&names) {
            if let Some(prost_types::value::Kind::StructValue(v)) = value.kind.as_mut() {
                v.fields.insert(
                    "source".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue(name.clone())),
                    },
                );
            }
        }
    }
    // Remove every test volume even if an assertion panics.
    struct Volumes(Vec<String>);
    impl Drop for Volumes {
        fn drop(&mut self) {
            for name in &self.0 {
                let _ = std::process::Command::new("docker")
                    .args(["volume", "rm", "-f", name])
                    .output();
            }
        }
    }
    let mut cleanup = Volumes(names.clone());
    let approved = NativeCreate::decode(&s.encode_to_vec(), &r, &p).unwrap();
    // Upstream admission refuses volumes that do not exist yet.
    assert!(native.validate(&approved).await.is_err());
    native.ensure_volumes(&r).await.unwrap();
    native.ensure_volumes(&r).await.unwrap(); // idempotent
    native.validate(&approved).await.unwrap();

    // A same-named volume squatted without this workspace's labels is never
    // adopted, relabeled or admitted.
    let mut squat = r.clone();
    squat.execution.workload = "squatted".into();
    let squatted =
        trusted_shim::openshell::attachments::volume_name(&squat, &squat.mounts[0]).unwrap();
    cleanup.0.extend(
        squat
            .mounts
            .iter()
            .map(|m| trusted_shim::openshell::attachments::volume_name(&squat, m).unwrap()),
    );
    assert!(std::process::Command::new("docker")
        .args(["volume", "create", &squatted])
        .output()
        .unwrap()
        .status
        .success());
    assert!(matches!(
        native.ensure_volumes(&squat).await,
        Err(trusted_shim::Error::Untrusted)
    ));
}
