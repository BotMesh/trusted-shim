# Native OpenShell

Native OpenShell lets shim create a workload as a sandbox of the stock,
unmodified OpenShell compute driver. Fleet and the stock OpenShell gateway
prepare and authorize each launch. Shim checks
the result, consumes the grant at the central ledger and calls the native driver
once. This page covers configuration, the provisioning flow, the native driver
and its lifecycle, GPUs and volumes, services and their data-plane transport,
what this support does and does not claim, and the tests.
See the [README](../README.md) for an overview.

## Overview

The pieces and who does what:

- **Fleet** schedules the workload, owns resource requests (with Ray) and owns
  the allocation lifecycle.
- **The stock gateway** is the pinned, unmodified OpenShell gateway. It turns a
  launch into a native create request and mints the native credentials.
- **The native driver** is the upstream OpenShell Docker compute driver. Shim
  reaches it through a private Unix socket.
- **The central ledger** holds the authorization grants. Shim consumes a grant
  there before it creates anything.
- **The supervisor** is the stock OpenShell supervisor container that a native
  sandbox owns. Shim uses it to reach the workload's services.
- **Shim** validates every request, keeps durable ownership state on the node and
  runs the outbound data-plane connections.

OpenShell is an unconditional dependency, including in `--no-default-features`
builds. There is no OpenShell build or runtime enable switch. The adapter uses
the unmodified upstream compute-driver protobufs at commit
`ce58cf8e9b953281352d98a637e41616295b1318`.

The access layer always advertises `openshell-access-v1`. Without user rules it
delegates to the driver unchanged.

## Configuration

The standard runtime includes native OpenShell provisioning inside the persistent
daemon. Its optional `--options` argument contains only operator settings:

```text
{"openshell":{"socket":"/run/openshell/compute.sock",
"admission_policy":"<upstream acknowledgement>","ledger_endpoint":"https://fleet.example",
"ledger_ca_file":null}}
```

Fleet fills these from its existing `apps.yaml`.

- `socket`: the native driver's socket. It must be private and owned by the same
  UID.
- `ledger_endpoint`: the central ledger. HTTPS uses system roots or the explicitly
  configured, non-writable CA file (`ledger_ca_file`). Plain HTTP is restricted to
  numeric loopback.
- `supervisor_image` (optional): the supervisor image ID that enables native
  services. See [The supervisor helper](#the-supervisor-helper).

A daemon with a native endpoint advertises `openshell-provisioning-v1`,
`openshell-allocation-v1` and a digest of its effective operator settings. It can
start during a gateway outage without claiming the native driver is healthy.

Advertised features:

| Feature | When the daemon advertises it |
|---|---|
| `openshell-access-v1` | Always |
| `openshell-provisioning-v1`, `openshell-allocation-v1` | A native endpoint is configured |
| `openshell-attachments-v1` | The driver's admission policy has `allow_driver_config=true` (see [GPUs and volumes](#gpus-and-volumes)) |
| `openshell-service-health-v1` | The service adapter is configured (see [Health and readiness](#health-and-readiness)) |
| `openshell-tcp-services-v1` | TCP services are supported, so Fleet does not place them on older shims |
| `openshell-ingress-v1` | Restricted ingress and the logs-only `control` service are supported |

## Provisioning flow

A native launch goes through these steps:

1. Fleet reserves the allocation with `allocate`.
2. The stock gateway translates the launch and prepares the native sandbox.
3. Rail evaluates `runtime.create` for that exact request, and the remote proof
   is verified.
4. The provisioning envelope reaches shim through the private `provision`
   daemon command.
5. Shim validates it, consumes the grant at the central ledger and calls native
   create once.

### Allocate

Before private credentials arrive, Fleet sends
`{"operation":"allocate","driver":"docker","execution":...}`. This durably
reserves ownership without calling the compute driver or ledger.

- The `reserved` phase has no sandbox ID, compute or application readiness.
- Repeated allocation returns the current phase. It never revives a cancelled
  lease.
- Stopping or deleting an unprovisioned reservation works offline and leaves a
  tombstone, so late grants cannot create it.
- A newer generation requires confirmed deletion.

Fleet retains Ray resources during this state. It uses a separate, private
outbound HTTPS delivery for the provisioning envelope.

### Gateway launch translation

`openshell_gateway::GatewayLaunch` translates an admitted Fleet launch and native
policy into the stock gateway's public create request. It binds the workspace,
command, environment, CPU/memory limits and an allocation-derived routable name.

The compute extension can use the same binding for validation before it mints
credentials. It then binds the credential-bearing Create bytes to Rail's
authorization resource and commitments. `ProvisionRequest::validate_native`
repeats these checks against the exact evaluation request, once before private
delivery and again inside shim.

This translation does not verify a proof or consume a grant. The existing central
ledger remains responsible for those checks. The translation has no scheduler,
queue, durable state or config file. Fleet remains the lifecycle owner.

When shim reads the gateway-prepared private compute request:

- It accepts the request's pending configuration status and policy-derived
  process selectors.
- It binds the workspace to Fleet's tenant.
- It rejects substituted tenants or claimed runtime readiness.
- The platform namespace is empty on create and remains driver-owned.

Workspace names:

- Canonical namespace IDs map to native workspace names within the stock
  gateway's 19-byte limit. The full Fleet identity remains proof-bound.
- The embedding control plane must reject collisions.

Use explicit, nonempty commands. They avoid the gateway's implicit interactive
TTY mode, which this profile does not support.

### Authorization

The gateway first prepares the native sandbox and a Rail `runtime.create`
evaluation. The evaluation's resource and parameters come from
`NativeCreate::authorization_resource` and `authorization_parameters`. These bind
the complete launch input, the native policy and the exact private protobuf bytes.

After remote proof verification, shim consumes the resulting exact-request
grant at the central ledger before it calls native create.

`ledger_transport::RemoteLedger` reaches the central ledger through an
authenticated gateway client on a node. The ledger's authoritative database must
never be copied onto an untrusted node.

### Provision

The private daemon command `{"operation":"provision","payload":...}` accepts a
`provisioning::ProvisionRequest`. It is built from the exact gateway protobuf,
the canonical launch, the Rail request, the proof-backed grant and an
execution-only ledger token.

- The token and native credentials travel over the same-UID Unix socket. They
  never appear in argv, status or durable node state.
- The payload cannot supply a ledger endpoint or driver socket.
- Native validation runs before the central Consume and the one permitted Create.
- Daemon request bodies are bounded. Losing the caller does not cancel accepted
  work.
- Shim treats an ambiguous Consume as authorizing. It keeps it and never retries
  it automatically.

Native split credentials must never enter an ordinary Fleet App spec, workload
environment or public response.

## The native driver

`openshell::NativeDriver` connects to the driver's private same-UID Unix socket.
It negotiates the upstream extension contract. It checks the operator's resource
admission policy and the driver's CPU/memory limit capabilities.

`NativeCreate` binds these fields to the approved launch inputs:

- the native policy hash
- the namespace/workspace
- the image, command and environment
- the hard limits

Fleet and Ray own resource requests. The native Docker driver receives only hard
limits, because it rejects resource request fields. Unmapped identity, namespace
and platform options fail closed.

Inspect, stop and delete require the exact sandbox ID and name. Shim confirms a
deletion with a later lookup. Mutations are never automatically retried.

### Lifecycle and ownership

`openshell_lifecycle::ManagedNativeDriver` adds three things on top of the
native driver:

- durable allocation ownership
- claims on the native sandbox ID and name
- generation tombstones

Its state lives in SQLite. It stores ownership, commitments, admitted service
targets, the public SSH host-key fingerprint and lifecycle state. It does not
store native credentials, the environment or the grant.

Guarantees:

- A replay after restart only observes the original sandbox.
- An unanswered create is never resubmitted.
- An absent snapshot cannot release its reservation while the create may still be
  in flight.
- Stop and delete verify persisted ownership and confirm their outcome.
- Failed cleanup retains the allocation.
- Old generations and reused sandbox identities remain fenced after deletion.
- A changed physical instance is rejected.

### Managing an allocation

Use the allocation's actual runtime driver with the existing `inspect`, `stop`
and `delete` daemon commands.

- `inspect` returns `phase`, `present` and `platform_ready`. With the service
  adapter enabled it also returns `application_ready`.
- Management uses persisted ownership. It needs no ledger credential and no live
  gateway, including after a daemon restart.

The library likewise takes the ledger only in `ManagedNativeDriver::launch`.
Opening ownership state and cleanup never require an authority client.

## GPUs and volumes

GPUs and durable storage are `LaunchRequest.gpus` and `LaunchRequest.mounts`.
Both are omitted when empty, so existing launch commitments are unchanged.

- Fleet binds `gpus` to the device ids Ray granted the allocation.
- Fleet binds `mounts` to the admitted app manifest.

Shim translates them into the upstream Docker driver's own `driver_config`:

- One `cdi_devices` entry `nvidia.com/gpu=<id>` per granted id, plus `gpu.count`
  equal to that number. It is never a driver-chosen default.
- One `type: volume` mount per entry. Volume names are derived as
  `fleet-<commitment(namespace, workload, name)>`. They are stable across
  generations but unnameable by another workload.

`NativeCreate` requires the native sandbox to carry exactly that translation and
nothing else. It rejects host binds, tmpfs, image mounts and foreign devices.

### Requirements and volume handling

Attachments require the node's driver to run with `allow_driver_config=true` in
its admission policy. Shim checks the acknowledged policy before it touches any
volume. Only then does the daemon advertise `openshell-attachments-v1`.

Before dispatch, shim idempotently creates each missing volume. Each one is a
plain `local` volume that carries:

- the policy's `required_labels`, with `${workspace}` substituted
- `trusted-shim.openshell/volume=v1`

Shim uses an existing volume only if it is a plain local volume with that label
that upstream resource admission already accepts. Otherwise it rejects the launch
as untrusted. Runtime deletion never removes these volumes.

## Services and the data-plane transport

Native services go out through shim's existing outgoing router connector. Shim
reaches the workload through the stock supervisor over SSH. The central
OpenShell gateway carries no application bytes. No host application port is
published.

### The supervisor helper

The stock supervisor image needs the small Rust `trusted-shim-socket` executable
at `/opt/trusted-shim/socket`. Compose it with
[`docker/openshell/Dockerfile.supervisor`](../docker/openshell/Dockerfile.supervisor).
Use a verified upstream image digest as `SUPERVISOR_IMAGE` and put a static binary
for the node architecture in the build context. On a Linux GNU build host:

```sh
rustc --edition=2021 -C target-feature=+crt-static -C opt-level=s -C strip=symbols \
  src/bin/trusted-shim-socket.rs -o /absolute/external/build-context/trusted-shim-socket
docker build --build-arg SUPERVISOR_IMAGE=registry/supervisor@sha256:... \
  -f docker/openshell/Dockerfile.supervisor /absolute/external/build-context
```

Then configure two settings:

- Put the resulting immutable image in the existing native driver's
  `supervisor_image` setting.
- Put its exact local `sha256:<64 hex>` image ID in the optional
  `supervisor_image` field of the existing shim OpenShell configuration.

Omitting this field preserves provisioning-only behavior and the previous daemon
configuration digest. Keep the native SSH socket at its default
`/run/openshell/ssh.sock`.

How the helper behaves:

- It has no listener and accepts no arguments.
- It requires a private socket owned by its supervisor UID.
- Shim attaches it with local Docker exec. It stays inside the trusted supervisor
  container, never the agent workload.
- It does not change upstream binaries, require a public node port or publish a
  workload port.
- It flushes binary stdio without line buffering.

### The SSH transport

`openshell_network::bind` supplies the local data-plane transport for the native
Docker profile. It checks:

- the full workload container ID
- the native sandbox and name
- the driver namespace and workspace
- the supervisor: it selects exactly one owned supervisor and checks its
  immutable image ID and read-only root filesystem

The SSH host key must match the public fingerprint returned by the authenticated
OpenShell control API. The transport uses the same `russh` version as the pinned
upstream lockfile.

SSH channels reach only the caller-selected workload loopback port, through the
stock supervisor's boundary connector. Requests on that service reuse one SSH
session.

The returned endpoint is host-loopback only. It exists for the existing outgoing
router connector.

- Drop or cancellation drains active local streams.
- Ownership monitoring closes the transport when the pinned workload or
  supervisor disappears or stops.

This is a privileged library interface, **not an app API**. Callers must supply a
fresh owned observation and an admitted service port.

The daemon's private `network` command accepts the allocation's actual runtime
driver with the existing `NetworkConfig`. It takes no target or SSH identity from
that command.

The public SSH fingerprint is derived from the exact proof-bound native
authentication bundle before Consume. Private keys are never persisted.

### Declaring services

`LaunchRequest.services` must contain unique, allocation-scoped services of the
same protocol, with `endpoint_ref: app`. The request's `driver_options` must be
exactly this, with the application's own port and path:

```json
{"container_port":8090,"health_path":"/health"}
```

These fields participate in the launch commitment.

The adapter accepts HTTP services and TCP services with a declared application
banner check. Management/credential injection and action-proof-required requests
remain unsupported.

### TCP services

For TCP (including SSH):

- Select `protocol: tcp`.
- Keep `health_path: /`.
- Add `health_tcp_banner: "SSH-2.0-"` to these options.

Readiness requires the exact nonempty ASCII prefix (up to 128 bytes) within three
seconds. The check sends no commands or credentials.

A local listener or a native SSH channel ACK alone does not prove the workload
accepted the connection. Silent TCP protocols need another health adapter and
remain unsupported. `openshell-tcp-services-v1` advertises this capability so
Fleet does not place these services on older shims.

### Ingress and control

Native HTTP services can also use restricted ingress and a logs-only `control`
service. The rules are part of the launch commitment. `openshell-ingress-v1`
advertises this support.

Ingress:

- Give an application service `endpoint_ref: ingress:<service>`.
- Add a matching `driver_options.ingress` rule (at most eight) with the same
  `paths`, `methods` and optional `single_use` as Docker ingress.
- `bearer_env` is rejected, because a native node holds no copy of the
  application's credential. Shim instead forwards the caller's own
  `Authorization` header, and the application authenticates it.
- Single-use approvals commit to the allocation's private
  `native-http-invocations.sqlite` journal before forwarding, exactly as on
  Docker.

Control:

- Declare at most one `control` service: `endpoint_ref: control`,
  `protocol: http1`. It is also allowed beside TCP applications.
- It serves `GET /logs?tail=N` with Docker's bounds. Shim reads the logs from the
  freshly observed owned workload container.
- Native control has no exec, restart or metadata routes. Administrative exec
  goes through the stock gateway. Lifecycle changes stay Fleet allocation
  operations.

### Health and readiness

With the service adapter configured, `openshell-service-health-v1` advertises
local health reporting.

Native `inspect.application_ready` requires a running connector worker and a
successful local probe within six seconds. It does not wait for registration
grants. The value resets on health failure, worker exit, cancellation and daemon
restart. This avoids a route-grant/readiness dependency cycle.

Local application health gates outbound service registration. Fleet joins central
policy readiness before publishing services. Fleet publication additionally
requires its authenticated gateway configuration/policy observer. The stock
supervisor health socket cannot replace this gate: it indicates session
acceptance **before** asynchronous configuration application.

`control_observation` strips native configuration, credentials, local endpoints
and condition messages before it returns bounded status to Fleet. It cannot
establish application readiness.

Router grants, revocation and control-snapshot freshness still apply. Local
connectivity during a control outage does not authorize indefinite access.

### Recovery and connection keepalive

On restart, the daemon recovers stored connector records.

- It checks application health without redirects or proxy environment.
- It retries health recovery independently of Ray.
- Stop and delete permanently fence connections and wait for transport drain
  before native cleanup.
- A started connector worker is not proof of route reachability or policy
  readiness.

The pinned router transport also sends standard WebSocket Ping/Pong controls,
with a 15-second interval and a 15-second reply deadline.

- Idle outbound connections stay active through NAT and proxies.
- Silent network loss closes streams within about 30 seconds plus scheduling
  delay.
- Recovery reconnects without replaying work or creating another runtime.

## What this does and does not claim

This adapter proves provisioning admission only. It does not claim that:

- platform `Ready=True` means supervisor/policy readiness
- it enforces proofs on agent actions
- it provides TEE attestation

Fleet's guarded activation/credential API is available. Fleet's embedded
stock-gateway compute extension now connects remote startup proofs to private
node delivery.

### Proofs for actions

Proof-required admission waits for remote verification before dispatch. Applying
that mode to every serial tool call adds the proof network's queue, proving and
round-trip latency to every step.

The implemented preflight path evaluates before execution and queues the ZK
receipt in the background. Native permissions enforce at execution. The later
proof establishes the recorded policy evaluation.

Such a proof alone establishes neither the completeness of the execution log nor
the external side effect. It must not be accepted as the existing pre-execution
`ExecutionGrant`.

## Tests

### Stock gateway create protocol

The pinned stock gateway's create protocol is covered by an opt-in integration
test. It starts an isolated gateway, authenticates with mTLS, creates a workspace
and captures the gateway-prepared private compute request. The test extension
refuses provisioning after capture. This does not establish native sandbox
isolation, application readiness or completed Fleet migration.

```sh
OPENSHELL_GATEWAY_BINARY=/absolute/path/to/pinned/openshell-gateway \
  cargo test --locked --all-features --test openshell \
  stock_gateway_mints_private_launch -- --ignored
```

The opt-in `stock_gateway_mints_private_launch_for_shim_with_workspace_isolation`
test runs the pinned, unmodified gateway with mTLS. It rejects a changed workload
before native Create. It checks the gateway-minted credentials through the same
binding. Its capture driver deliberately refuses provisioning. This acceptance
does not assert sandbox execution or readiness.

### Native driver and daemon

Tests use an upstream-protocol test server. The ignored native admission test
also calls the pinned, unmodified Docker compute-driver binary. It checks
capabilities, real input validation and operator policy mismatch. Neither test
establishes full OpenShell isolation or an end-to-end provisioning proof.

Other tests cover real daemon sockets, central HTTP/2 Consume, revocation, reply
loss, restart and gateway outage. They use protocol and proof doubles and do not
claim native isolation.

### Fleet native Docker acceptance

Fleet's opt-in native Docker acceptance composes this helper with the stock
supervisor. It exercises real HTTP/SSE/WebSocket through the local Data Router,
including:

- wrong tenant/image/host-key rejection
- active-stream revocation
- health denial and recovery
- durable daemon restart
- cleanup drain
- gateway mTLS readiness
- cache expiry
- control-gateway outage

Its proof service and route-grant issuer are explicit test fixtures. It is
neither a fresh proof nor a cross-machine NAT acceptance test.

### Router transport

Router's `tools/test_nat.py` exercises the transport using isolated NAT
namespaces. `tools/test_remote.py` exercises it using an authorized remote SSH
host. They use fixture grants and loopback applications. Cross-machine
Fleet/OpenShell control and actual workload migration remain separate acceptance
gates.

## Related repositories

Keep one authoritative existing runtime config per application and retain dormant
ACK support. Fleet's opt-in runtime adapter delegates container hard limits to
shim ([zkm-fleet #95](https://github.com/ProjectZKM/zkm-fleet/issues/95)). Film
and ClawUp have opt-in adapters for the independent data transport. This
increment builds on framework PR #1 and pins companion repository commits for
reproducibility.
