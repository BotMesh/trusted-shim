# Native OpenShell

Detailed reference. See the [README](../README.md) for an overview.

## Native OpenShell transport

The pinned stock gateway's create protocol is covered by an opt-in integration
test. It starts an isolated gateway, authenticates with mTLS, creates a workspace,
and captures the gateway-prepared private compute request. The shim accepts its
pending configuration status and policy-derived process selectors, binds the
workspace to Fleet's tenant, and rejects substituted tenants or claimed runtime
readiness. The platform namespace is empty on create and remains driver-owned.
The test extension refuses provisioning after capture; this does not establish
native sandbox isolation, application readiness or completed Fleet migration.

```sh
OPENSHELL_GATEWAY_BINARY=/absolute/path/to/pinned/openshell-gateway \
  cargo test --locked --all-features --test openshell \
  stock_gateway_mints_private_launch -- --ignored
```

OpenShell is an unconditional dependency, including in `--no-default-features` builds;
there is no OpenShell build or runtime enable switch. The adapter uses the unmodified upstream compute-driver
protobufs at commit `ce58cf8e9b953281352d98a637e41616295b1318`.
`openshell::NativeDriver` connects to a private same-UID Unix socket, negotiates
the upstream extension contract and checks the operator's resource admission
policy and CPU/memory limit capabilities. `NativeCreate` binds the native policy
hash, namespace/workspace, image, command, environment and hard limits to the
approved launch inputs. Fleet/Ray own resource requests; the native Docker
driver receives only hard limits because it rejects resource request fields. Unmapped identity, namespace and platform options fail closed.

GPUs and durable storage are `LaunchRequest.gpus` / `LaunchRequest.mounts`
(omitted when empty, so existing launch commitments are unchanged). Fleet binds
`gpus` to the device ids Ray granted the allocation and `mounts` to the admitted
app manifest. The shim translates them into the upstream Docker driver's own
`driver_config`: one `cdi_devices` entry `nvidia.com/gpu=<id>` per granted id
(plus `gpu.count` equal to that number, never a driver-chosen default), and one
`type: volume` mount per entry. Volume names are derived as
`fleet-<commitment(namespace, workload, name)>`, stable across generations but
unnameable by another workload. `NativeCreate` requires the native sandbox to
carry exactly that translation and nothing else; host binds, tmpfs, image mounts
and foreign devices are rejected.

Attachments require the node's driver to run with `allow_driver_config=true` in
its admission policy; the acknowledged policy is checked before any volume is
touched. Only then does the daemon advertise `openshell-attachments-v1`. Before dispatch the shim idempotently creates each missing volume as a
plain `local` volume carrying the policy's `required_labels` (with
`${workspace}` substituted) and `trusted-shim.openshell/volume=v1`. An existing
volume is used only if it is a plain local volume with that label that upstream
resource admission already accepts; otherwise the launch is rejected as
untrusted. Runtime deletion never removes these volumes.
Inspect, stop and delete require the exact sandbox ID and name; deletion is
confirmed by a subsequent lookup. Mutations are never automatically retried.

`openshell_lifecycle::ManagedNativeDriver` adds durable allocation ownership,
native sandbox ID/name claims and generation tombstones. The gateway first
prepares the native sandbox and a Rail `runtime.create` evaluation whose
resource and parameters come from `NativeCreate::authorization_resource` and
`authorization_parameters`. These bind the complete launch input, native policy
and exact private protobuf bytes. After remote proof verification, the adapter
consumes the resulting exact-request grant at the central ledger before calling
native create. `ledger_transport::RemoteLedger` reaches the central ledger through
an authenticated gateway client
on a node; its authoritative database must never be copied onto an untrusted node.

SQLite stores ownership, commitments, admitted service targets, the public SSH
host-key fingerprint and lifecycle state, without native
credentials, environment or the grant. A replay after restart only observes the
original sandbox. An unanswered create is never resubmitted, and an absent
snapshot cannot release its reservation while the create may still be in flight.
Stop and delete verify persisted ownership and confirm their outcome; failed
cleanup retains the allocation. Old generations and reused sandbox identities
remain fenced after deletion. A changed physical instance is rejected.

This adapter proves provisioning admission only. It does not claim that platform
`Ready=True` means supervisor/policy readiness, enforce proofs on agent actions,
or provide TEE attestation. Fleet's guarded activation/credential API is available;
Fleet's embedded stock-gateway compute extension now connects remote startup
proofs to private node delivery. Local application health gates outbound service
registration; Fleet joins central policy readiness before publishing services.
`control_observation` strips native configuration, credentials, local
endpoints and condition messages before returning bounded status to Fleet; it
cannot establish application readiness. Native split credentials
must never enter an ordinary Fleet App spec, workload environment or public response.
The adapter accepts HTTP services and TCP services with a declared application
banner check. Management/credential injection and action-proof-required requests
remain unsupported.
Tests use an upstream-protocol
test server. The ignored native admission test also calls the pinned, unmodified
Docker compute-driver binary to check capabilities, real input validation and
operator policy mismatch. Neither test establishes full OpenShell isolation or
an end-to-end provisioning proof.

`openshell_network::bind` supplies the local data-plane transport for the native
Docker profile. It checks the full workload container ID, native sandbox/name,
driver namespace and workspace, selects exactly one owned supervisor, and checks
its immutable image ID and read-only root filesystem. The SSH host key must match
the public fingerprint returned by the authenticated OpenShell control API. It
uses the same `russh` version as the pinned upstream lockfile. SSH channels reach
only the caller-selected workload loopback port through the stock supervisor's
boundary connector. Requests on that service reuse one SSH session. The central
OpenShell gateway carries no application bytes.

The stock supervisor image needs the small Rust `trusted-shim-socket` executable
at `/opt/trusted-shim/socket`. Compose it with
[`docker/openshell/Dockerfile.supervisor`](../docker/openshell/Dockerfile.supervisor),
using a verified upstream image digest as `SUPERVISOR_IMAGE` and a static binary
for the node architecture in the build context. On a Linux GNU build host:

```sh
rustc --edition=2021 -C target-feature=+crt-static -C opt-level=s -C strip=symbols \
  src/bin/trusted-shim-socket.rs -o /absolute/external/build-context/trusted-shim-socket
docker build --build-arg SUPERVISOR_IMAGE=registry/supervisor@sha256:... \
  -f docker/openshell/Dockerfile.supervisor /absolute/external/build-context
```

Configure the resulting immutable image in the existing native driver's
`supervisor_image` setting, and put its exact local `sha256:<64 hex>` image ID in
the existing shim OpenShell configuration's optional `supervisor_image` field.
Omitting this field preserves provisioning-only behavior and the previous daemon
configuration digest. Keep the native SSH socket at its default
`/run/openshell/ssh.sock`. The helper has no listener, accepts no arguments, and
requires a private socket owned by its supervisor UID. Shim attaches it with
local Docker exec; it stays inside the trusted supervisor container, never the
agent workload. It does not change upstream binaries, require a public node port,
or publish a workload port. Binary stdio is flushed without line buffering.

The returned endpoint is host-loopback only, for the existing outgoing router
connector. Drop/cancellation drains active local streams; ownership monitoring
closes the transport when the pinned workload or supervisor disappears or stops.
This is a privileged library interface, **not an app API**. Callers must supply a
fresh owned observation and an admitted service port. The daemon's private
`network` command accepts the allocation’s actual runtime driver with the existing `NetworkConfig`;
it takes no target or SSH identity from that command. `LaunchRequest.services`
must contain unique, allocation-scoped services of the same protocol, with
`endpoint_ref: app`.
Its `driver_options` must be exactly `{"container_port":8090,"health_path":"/health"}`
(with the application's port/path). These fields participate in the launch
commitment. The public SSH fingerprint is derived from the exact proof-bound
native authentication bundle before Consume; private keys are never persisted.

For TCP (including SSH), select `protocol: tcp`, keep `health_path: /`, and add
`health_tcp_banner: "SSH-2.0-"` to these options. Readiness requires the exact
nonempty ASCII prefix (up to 128 bytes) within three seconds; it sends no commands
or credentials. A local listener or native SSH channel ACK alone does not prove
the workload accepted the connection. Silent TCP protocols need another health
adapter and remain unsupported. `openshell-tcp-services-v1` advertises this
capability so Fleet does not place these services on older shims.

Native HTTP services can also use restricted ingress and a logs-only `control`
service. Give an application service `endpoint_ref: ingress:<service>` and a
matching `driver_options.ingress` rule (at most eight) with the same `paths`,
`methods` and optional `single_use` as Docker ingress; `bearer_env` is rejected,
because a native node holds no copy of the application's credential. The shim
instead forwards the caller's own `Authorization` header, and the application
authenticates it. Single-use approvals commit to the allocation's private
`native-http-invocations.sqlite` journal before forwarding, exactly as on
Docker. Declare at most one `control` service (`endpoint_ref: control`,
`protocol: http1`, also beside TCP applications) for `GET /logs?tail=N` with
Docker's bounds, read from the freshly observed owned workload container. Native
control has no exec, restart or metadata routes: administrative exec goes
through the stock gateway, and lifecycle changes stay Fleet allocation
operations. The rules are part of the launch commitment. `openshell-ingress-v1`
advertises this support.

The daemon recovers stored connector records on restart, checks application health
without redirects or proxy environment, and retries health recovery independently
of Ray. Stop/delete permanently fence connections and wait for transport drain
before native cleanup. No host application port is published. A started connector
worker is not proof of route reachability or policy readiness.

With the service adapter configured, `openshell-service-health-v1` advertises
local health reporting. Native `inspect.application_ready` requires a running
connector worker and a successful local probe within six seconds. It does not
wait for registration grants. The value resets on health failure, worker exit,
cancellation and daemon restart, avoiding a route-grant/readiness dependency cycle.

Fleet publication additionally requires its authenticated gateway
configuration/policy observer. The stock supervisor health socket indicates
session acceptance **before** asynchronous configuration application, so it cannot
replace this gate. Router grants, revocation and control-snapshot freshness still apply;
local connectivity during a control outage does not authorize indefinite access.

Fleet's opt-in native Docker acceptance composes this helper with the stock
supervisor and exercises real HTTP/SSE/WebSocket through the local Data Router,
including wrong tenant/image/host-key rejection, active-stream revocation,
health denial/recovery, durable daemon restart, cleanup drain, gateway mTLS
readiness, cache expiry and control-gateway outage.
Its proof service and route-grant issuer
are explicit test fixtures; it is neither a fresh proof nor a cross-machine NAT
acceptance test.

The pinned router transport also sends standard WebSocket Ping/Pong controls,
with a 15-second interval and 15-second reply deadline. Idle outbound connections
stay active through NAT/proxies; silent network loss closes streams within about
30 seconds plus scheduling delay. Recovery reconnects without replaying work or
creating another runtime. Router's `tools/test_nat.py` and `tools/test_remote.py`
exercise this transport using isolated NAT namespaces and an authorized remote
SSH host, respectively. They use fixture grants and loopback applications;
cross-machine Fleet/OpenShell control and actual workload migration remain
separate acceptance gates.

Canonical namespace IDs map to native workspace names within the stock gateway's
19-byte limit; the full Fleet identity remains proof-bound. The embedding control
plane must reject collisions. Explicit nonempty commands avoid the gateway's
implicit interactive TTY mode, which this profile does not support.

`openshell_gateway::GatewayLaunch` translates an admitted Fleet launch and native
policy into the stock gateway's public create request. It binds the workspace,
command, environment, CPU/memory limits and an allocation-derived routable name.
The compute extension can use the same binding for validation before credential
minting, then bind the credential-bearing Create bytes to Rail's authorization
resource and commitments. `ProvisionRequest::validate_native` repeats these
checks against the exact evaluation request before private delivery and again
inside shim. It does not verify a proof or consume a grant; the existing central
ledger remains responsible for those checks. This translation has no scheduler,
queue, durable state or config file. Fleet remains the lifecycle owner.

The opt-in `stock_gateway_mints_private_launch_for_shim_with_workspace_isolation`
test runs the pinned, unmodified gateway with mTLS. It rejects a changed workload
before native Create and checks the gateway-minted credentials through the same
binding. Its capture driver deliberately refuses provisioning; this acceptance
does not assert sandbox execution or readiness.

The standard runtime includes native OpenShell provisioning inside
the persistent daemon. Its optional `--options` argument contains only operator
settings: `{"openshell":{"socket":"/run/openshell/compute.sock",
"admission_policy":"<upstream acknowledgement>","ledger_endpoint":"https://fleet.example",
"ledger_ca_file":null}}`. Fleet fills these from its existing `apps.yaml`.
The socket must be private and owned by the same UID. HTTPS uses system roots or
the explicitly configured, non-writable CA file; plain HTTP is restricted to numeric
loopback. The access layer always advertises `openshell-access-v1`; without user rules it
delegates to the driver unchanged. A daemon with a native endpoint additionally advertises `openshell-provisioning-v1`, `openshell-allocation-v1` and a digest of its effective operator settings.
It can start during a gateway outage without claiming the native driver is healthy.

The private daemon command `{"operation":"provision","payload":...}` accepts a
`provisioning::ProvisionRequest`, constructed with the exact gateway protobuf,
canonical launch, Rail request, proof-backed grant and execution-only ledger token.
The token and native credentials travel over the same-UID Unix socket, never argv,
status or durable node state. The payload cannot supply a ledger endpoint or driver
socket. Native validation precedes central Consume and the one permitted Create.
Daemon request bodies are bounded; losing the caller does not cancel accepted work.
An ambiguous Consume is retained as authorizing and never retried automatically.

Before private credentials arrive, `{"operation":"allocate","driver":"docker",
"execution":...}` durably reserves ownership without calling the compute driver or
ledger. The `reserved` phase has no sandbox ID, compute or application readiness.
Repeated allocation returns the current phase; it never revives a cancelled lease.
Stopping/deleting an unprovisioned reservation works offline and leaves a tombstone,
so late grants cannot create it. A newer generation requires confirmed deletion.
Fleet retains Ray resources during this state and uses a separate, private outbound
HTTPS delivery for the provisioning envelope.

Use the actual runtime driver with the existing `inspect`, `stop` and `delete` daemon
commands to manage that allocation. Inspection returns `phase`, `present` and
`platform_ready` and, with the service adapter enabled, `application_ready`. Management uses persisted ownership
without a ledger credential or a live gateway, including after daemon restart.
The library likewise takes the ledger only in `ManagedNativeDriver::launch`;
opening ownership state and cleanup never require an authority client. Tests cover
real daemon sockets, central HTTP/2 Consume, revocation, reply loss, restart and
gateway outage with protocol/proof doubles, without claiming native isolation.

Proof-required admission waits for remote verification before dispatch. Applying
that mode to every serial tool call adds the proof network's queue, proving and
round-trip latency to every step. The implemented preflight path evaluates before execution and queues the
ZK receipt in the background. Native permissions enforce at execution; the later
proof establishes the recorded policy evaluation. Such a proof alone establishes
neither completeness of the execution log nor the external side effect. It must
not be accepted as the existing pre-execution `ExecutionGrant`.

Keep one authoritative existing runtime config per application and retain dormant
ACK support. Fleet's opt-in runtime adapter delegates container hard limits to shim
([zkm-fleet #95](https://github.com/ProjectZKM/zkm-fleet/issues/95)). Film and ClawUp
have opt-in adapters for the independent data transport. This increment builds on framework
PR #1 and pins companion repository commits for reproducibility.
