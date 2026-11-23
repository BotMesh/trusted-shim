# Node runtime, Docker lifecycle and service connections

This page is the detailed reference for the shim node service. It covers how
Fleet runs the service and talks to it, and how the Docker driver starts, limits
and recovers containers. It then covers how a workload's services connect out
through the data relay, and how administrators and clients reach them. See the
[README](../README.md) for an overview.

## Who owns what

```text
Fleet scheduling and allocation
  -> fleet-node / per-machine Ray
    -> shim OpenShell access layer -> RuntimeDriver -> Docker / TEE runtime
    -> router Connector   -> independent data relay

central policy gateway -> approved policy/program + authorization ledger
startup: shim -> rail -> remote proof -> verification -> grant -> Create
action:  preflight evaluation -> durable receipt job + grant -> dispatch
         receipt job -> remote proof -> verification (background)
```

Shim provides the machine-local runtime and trust interfaces below zkm-fleet.
It admits actions through native preflight evaluation. Startup that requires a
proof follows a separate path. Policy evaluation uses trusted-rail's pinned
Regorus engine, and the same engine runs inside trusted-rail's Ziren guest. The
remote proof network generates proofs. Shim checks them with Ziren's upstream
verifier.

- **Fleet** owns placement, retries and confirmed release of resources.
- **Shim** owns one machine's authorized executions.
- **The independent router** carries service payloads.
- **Fleet's control plane** owns infrastructure policy and service grants.
- **Application backends** keep their own authorization for users, sessions and
  API keys.
- **OpenShell** provides native isolation. Shim calls it through its upstream
  interfaces and does not fork it. Fleet wires its durable provisioning adapter
  to central preparation of the native gateway and to application readiness.
  Fleet's default Compose stack includes the gateway.

### The OpenShell access layer

The OpenShell access layer is enabled for every driver.

- With no user rules, it adds no restrictions. The driver's isolation, limits
  and permissions stay authoritative.
- When rules are configured, the control plane binds their canonical digest in
  `access_policy_sha256`. Shim then requires the matching native OpenShell
  enforcement before it creates the runtime.
- A missing service, an invalid policy or a failed receipt never removes a
  configured restriction.
- `access_policy_sha256` is a control-plane policy reference. It is not an
  enable switch and not a new config file.
- Tenant identity and application authentication are separate from this layer.
- Changing or removing user rules requires a new admitted generation. (A
  generation is one numbered execution of an allocation.)

New launches select the `docker`, `tee` or `tee-simulation` driver. The
`openshell` driver name is kept only for compatibility with existing envelopes
and journals. Recovery uses the execution path that was persisted for the
allocation.

## The node service

### Starting it

Fleet can install this binary alongside its node agent. Fleet starts it as a
separate service, in its own cgroup:

```sh
trusted-shim-runtime --serve --state-dir /var/lib/zkm-fleet/shim --node-id machine-name
```

The shim service must not be a child in fleet-node's service cgroup. It must
not have a `PartOf`/`BindsTo` dependency on fleet-node either.

### The control socket

The service exposes only `STATE/control.sock` (mode 0600). It checks the UID of
each connecting process. A client sends one bounded JSON request and then closes
its write half:

```json
{"protocol":1,"node_id":"machine-name","command":{"operation":"capabilities"}}
```

Each response contains `protocol` and either `result` or `error`.

- Launch, inspect, stop, delete and network commands use the same execution
  contracts as the stdio adapter.
- A client that disconnects does not cancel an accepted operation.
- Network commands are idempotent. Each one returns after it starts a connector
  that the daemon owns.
- The daemon persists network configuration privately and recovers it when the
  daemon restarts. Recovery never starts an application container that is
  stopped or missing.
- An explicit stop or delete still fences and drains networking before it
  confirms cleanup.

### Restarts and upgrades

- When the node restarts, it reconnects to the running shim service.
- When shim itself restarts, it closes its transports.
- Upgrading the node must not restart shim, Ray, Docker or upstream runtime
  services.
- The node installer pins the shim executable by content hash. It leaves old
  versions available for active allocations.
- This protocol does not implement automatic shim replacement or live migration
  between shim versions.

## Docker driver

### One-shot mode

Build the binary with:

```sh
cargo build --locked --bin trusted-shim-runtime
```

Fleet selects the binary and a private, persistent state directory in its
existing node configuration.

- Without `--serve`, the binary reads one JSON control request on stdin and
  returns bounded metadata on stdout.
- It has no network listener.
- `--capabilities` reports protocol 1 and the Docker driver.
- It calls Docker directly through `/usr/bin/docker`, against the local Unix
  socket. Install the binary only for the trusted machine adapter.

### What the Docker path accepts

This lifecycle path is opt-in. It accepts only explicit requests that need no
TEE and no proof. It rejects the following instead of silently dropping them:

- policy-proof requirements
- attestation requirements
- unsupported driver options
- unsupported router service mappings

Plain Docker is not a policy boundary for an agent shell. Connect proof-required
admission and upstream OpenShell before you advertise those guarantees. The
proven PolicyEngine is unchanged.

### Limits and container settings

- CPU millicores and memory bytes become Docker hard limits. The driver checks
  them before start and again on inspect.
- The driver requires the Docker daemon to support the requested cgroup limits.
  The Docker acceptance test also reads the CPU and memory limits from the live
  cgroup.
- Memory plus swap is limited to the same total as memory.
- GPU ids come from the allocator.
- Published service ports bind to host loopback only.
- Images must already be present. This driver does not pull images.
- Bind mounts are administrator settings.
- Shim passes the environment in a mode-0600 temporary env file, never in argv.
  It rejects multiline env values.
- Local host administrators and Docker owners remain trusted.

### State, recovery and cleanup

Each allocation has:

- an exclusive file lock,
- a journal that is written atomically and fsynced,
- Docker ownership labels that bind the complete request and execution.

Recovery follows these rules:

- Recovery reuses the same container.
- Shim rejects changed requests, stale leases and stale generations.
- Tombstones keep stopped and deleted generations fenced.
- Shim does not automatically rerun a started container that has gone missing,
  or a start whose outcome is unclear. Confirm cleanup, then allocate a new
  generation explicitly.
- Before it acknowledges a release, cleanup checks ownership and the actual
  daemon state.

Operator instructions:

- Keep both Fleet's allocation journal and shim's state across restarts and
  upgrades. Never delete them to retry an operation.
- A crashed process can leave a private temporary env file behind. Protect the
  state directory with the same access and retention controls as runtime
  credentials.

### Resume

The persistent daemon also accepts `resume`, and advertises it as
`runtime-resume-v1`. The one-shot binary has no `resume`.

- `resume` starts a Running allocation's own exited container again, in place.
  The container keeps its state.
- Shim checks the committed limits again before it restarts the container.
- A container that is still running is left alone.
- Shim never recreates a missing container.
- Shim refuses to resume a stopped or deleted allocation, so a stop or delete
  stays final.

### Docker acceptance test

Run the real Docker acceptance test separately. It creates and removes only test
containers:

```sh
docker pull alpine:3.21
cargo test --locked --test docker -- --ignored
```

It covers:

- concurrent idempotent launch
- hard limits
- process recovery
- request substitution
- stale cleanup
- tombstones
- refusal to recreate a lost execution

## Outbound service connections

This section covers how a workload's services connect out to the independent
data relay.

### Declaring services

Declare services in the existing `LaunchRequest.services`. The Docker adapter
accepts a service when:

- it is an approved `endpoint_ref: app` mapping,
- its namespace and workload match the launch,
- its service name is unique,
- its protocol is HTTP/1, WebSocket or TCP.

Persist the resolved loopback port with the allocation.

- `container_port` can differ from the host port.
- An explicit `entrypoint` supports existing agent images.
- Shim validates these options before Docker runs. They do not enable arbitrary
  Docker flags.

### Automatic host ports

Set `driver_options.port: 0` together with `container_port` to have shim pick a
free host loopback port and reserve it durably.

- Docker receives a fixed mapping, so a restart keeps the same endpoint.
- Runtime status reports the assigned port.
- Shim releases a reservation only after the network has drained and the
  container's removal is confirmed.
- If an external listener already holds the port, the launch fails. Shim never
  silently picks a different target.
- Preserve the private state directory across upgrades.
- A crash before the allocation record is persisted can leave an orphan port
  reservation. The reservation errs on the safe side and stays in place until
  an operator reconciles it.

### The network command

The node supervisor runs a second, long-lived stdio command:

```json
{"operation":"network","execution":...,"config":...}
```

`NetworkConfig` is node-owned data taken from Fleet's existing apps.yaml. It is
not a second runtime catalog. Its fields are:

- `gateway_url`
- `relay_url`
- `token_file`
- `public_key_file`
- `issuer`

### Registration grants

A registration grant is the signed token that lets a connector register one
service with the relay.

The central gateway's authenticated `POST /v1/runtime/registration` accepts
`{"execution":...,"service":...}`. It checks the live allocation and the
approved policy, then returns `{"token":"..."}`.

Fleet embeds the registration gateway and delivers scoped credentials to shim.
Operators must configure the approved issuer and trust roots. A local test
issuer does not substitute for production authorization.

Before it dials the fixed relay, shim verifies the Ed25519 registration grant:

- the exact execution and service,
- the issuer,
- the audience,
- the expiry.

Transport rules:

- Gateway HTTP and relay WS must use TLS. The only exception is tests on a
  numeric loopback address.
- Redirects are disabled.
- Responses are bounded.
- Shim reads node credentials only from an explicitly named private file.
- No token value goes into process arguments or runtime environment variables.

### Lease renewal

If the relay supports `POST /v1/connect/{route}/renew`, the connector refreshes
its registration grant without replacing the transport.

- User Access grants keep their original expiry, policy binding and revocation
  checks.
- If the gateway is unavailable, the connector can carry on only until the last
  accepted registration grant expires.
- Updated embedded gateways issue 30-second registration leases, after a live
  Fleet readiness check. The connector renews at about half of the remaining
  lifetime.
- So when Fleet withdraws a service, it can stay reachable until its current
  lease expires. Fleet's five-second native readiness cache adds to that
  window.
- The relay drains streams on expiry by itself, even if the connector cannot
  contact control.
- Leases that older gateways already issued keep their original expiry until
  they age out.
- Renewal does not turn Docker admission into a policy or TEE proof.

### Stop, delete and connection loss

The connector holds a network lock for each execution.

- Stop and delete durably fence new connectors. They then wait for every stream
  to close before they stop or remove the runtime, or allow the port to be
  reused.
- If the drain fails, cleanup stays unconfirmed.
- Losing the connection never restarts the container.
- The connector refreshes expiring credentials through the central gateway.
- A reconnect never replays application requests.
- Applications must tolerate failed in-flight streams when a connection or a
  grant expires.

### Validation and rollout

Validation covers:

- a real Docker HTTP/SSE service across the independent relay,
- private registration,
- distinct host and container ports,
- draining active streams,
- fencing of port reuse.

The CLI advertises `data-plane-v1`. Upgrade Fleet's node adapter before you
enable services. Policy-proof and TEE requirements stay independent. They fail
closed when the selected runtime path cannot satisfy them.

## Runtime administration

An administrator can declare the reserved `control` service (endpoint
`control`). Through the independent data relay, it exposes:

- metadata for the exact allocation,
- bounded runtime logs,
- command execution,
- in-place restart.

Access rules:

- The central connection gateway requires a Fleet administrator credential for
  this service.
- The node checks the signed `X-Trusted-Route` grant again, including its exact
  execution and service.
- Ordinary application grants cannot access administration.
- The Docker daemon is never exposed remotely.

Docker administration does not claim action-policy proof. Proof-required launch
requests still fail closed.

### Exec

- A request carries argv, an optional user, base64 stdin and a deadline of at
  most 600 seconds.
- Shim enforces the deadline with the image's `timeout` utility.
- Input and output are bounded at 64 MiB.
- The reply contains base64 stdout and stderr, plus an exit code.
- Callers must not automatically retry a timed-out command.

### Logs

`GET /logs?tail=N` reads 1–5000 lines directly from the owned container.

- It returns base64 stdout and stderr, at most the last 128 KiB of each.
- The whole read is bounded to 15 seconds or the remaining grant lifetime.
- It requires the same exact-execution control grant.
- It does not depend on legacy Fleet node log files.

## Application ingress

### Restricted HTTP ingress

To expose an application endpoint to clients, declare
`endpoint_ref: ingress:<service>`. Add a matching `driver_options.ingress` entry
with:

- exact `paths`,
- allowed `methods`,
- an optional `bearer_env`.

The node reads that bearer credential from the owned container and injects it
into the local HTTP request. The client never receives it.

- Ingress supports HTTP/SSE.
- It rejects paths and methods that the rule does not declare.
- Services that need native WebSocket or TCP should use the direct app endpoint.
- Ingress is configured in the existing application manifest, not in a second
  runtime catalog.

### Single-use ingress

Set `single_use: true` on an existing ingress rule to require a signed
`http_request` binding.

For each request, shim:

1. verifies the method, the exact path, and the SHA-256 of the request body (at
   most 16 MiB),
2. commits the invocation ID to a private SQLite ledger,
3. only then sends the request to the workload.

Outcomes:

- Concurrent replays return 409. So do replays after a reconnect or restart.
- A mismatched request returns 403 and does not consume the approval.
- A lost upstream response still consumes the approval. Reconcile the
  application outcome before you authorize a new ID.
- HTTP response bodies are still streamed, including SSE.
- Shim prunes expired ledger entries.

Compatibility and operation:

- Preserve the shim state directory on upgrades.
- Old ingress rules keep their earlier behavior and wire representation.
- Nodes report `single-use-ingress-v1`. Fleet must require this capability
  before it places a single-use rule.
- Admin `control` routes do not accept body-bound application grants.

These invocation capabilities enforce application admission and replay
protection. They are separate from the remote PolicyEngine proof that trusted
actions require.

### Fleet-managed access identity

Shim accepts an optional signed `access` claim in a grant. The claim contains
opaque principal and session IDs, plus the approved access-policy version and
digest.

- The relay and Fleet own freshness and per-stream revocation.
- Shim still validates the signature, the exact execution and service, and any
  single-use request and body binding before it forwards a request.
- This transport policy reference is not a PolicyEngine evaluation proof.
- Consuming a tool action does not generate a second proof.
- In managed mode, administrator `control` grants also require an enabled Fleet
  `control` service policy.

The Docker management acceptance test covers scoped claims, rejection of a
changed body, and concurrent replay.

Rollout:

- Upgrade shim before you enable `TRUSTED_GATEWAY_ROUTER_ID` in the application
  backend. Older parsers reject the additive claim.
- Legacy grants omit the claim.
- Existing runtimes are not migrated.

### Rotating the signing key

The existing `public_key_file` in Fleet node network settings accepts a bounded
Ed25519 PEM bundle. Shim reloads it for each new ingress authorization.

To rotate the central signer:

1. Stage the old and new public keys on every shim, relay and gateway.
2. Switch the central signer.
3. Remove the old key only after you have replaced node enrollment credentials
   and old route grants have expired.

Replace the file atomically, with mode 0644 or stricter. Runtime containers,
ports and existing streams survive the update. Stream expiry and Fleet
revocation stay in force.
