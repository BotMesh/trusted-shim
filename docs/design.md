# Design

The architecture of trusted-shim and the reasons behind it. See the
[README](../README.md) for an overview and how to run it.

## Node runtime

### A service of its own

Shim runs as its own systemd service, outside fleet-node's cgroup, so upgrading
or restarting the node never stops shim or its workloads. A node restart just
reconnects to the running shim.

Fleet talks to shim through one private Unix socket that accepts only shim's own
UID. Each request is one bounded JSON message, and an accepted request runs to
completion even if the caller goes away. A lost connection never leaves an
operation half done.

### Never run anything twice

Fleet owns placement and retries. Shim owns what actually happens on the machine:

- Each allocation has its own lock, an fsynced journal and Docker labels that
  bind the container to the exact request and execution.
- After a restart, shim finds the same container again. A changed request, a
  stale lease or an old generation is rejected, and deleted generations stay
  fenced by tombstones.
- A missing container, or a start whose outcome is unknown, is never rerun
  automatically. Fleet must confirm cleanup and allocate a new generation.

The design prefers an operator reconciling an unclear case over a duplicate
execution, so shim's state directory must survive restarts and upgrades.

### Docker driver

Requested CPU and memory become hard limits, checked at start and on every
inspect. An optional CPU weight (`limits.cpu_shares`, Docker's `--cpu-shares`)
divides CPU under contention in proportion to weight, so a low-weight workload
gets a small share next to others and otherwise uses what they leave idle. It is
checked the same way. For a TEE runtime the limits and the weight are in the
admitted request digest. The native OpenShell path refuses a weight, since
OpenShell's create request has no field for it. Images must already be present, environment goes through a private
file rather than the command line, and ports bind host loopback only. Plain
Docker is not a policy boundary for an agent's shell, so requests that need a
policy proof or attestation are refused on this path rather than downgraded.

### Stopping

A stop, delete or restart gives the process its grace period between SIGTERM and
SIGKILL, up to an hour, so a job can checkpoint. The allocation is fenced first,
so nothing starts it again, and the grace period runs without the allocation's
lock, so `inspect` reports `stopping` meanwhile and nothing queues behind it. The
container is stopped by its id, which never names a later generation's
container. Delete removes a container that outlasts its grace period.

### Networks

A container is on Docker's default bridge network unless its launch chooses
another. `none` leaves it loopback only, with no egress, port or services, for a
job that needs no network. `host` puts it in the host's own network namespace,
where it listens on its port itself and can reach every service on the host,
loopback included, so only a trusted workload should get it. A TEE runtime
refuses `host`: in the confidential VM it would reach the attestation agent,
which serves evidence on loopback. A chosen network is part of the committed
launch, and inspect refuses a container whose network differs.

### Resume after a crash

A crashed container keeps its writable layer. Fleet can therefore ask shim to
`resume` a Running allocation whose container exited, and shim starts the same
container again with its state intact. Shim never recreates a missing container
and never resumes a stopped or deleted allocation, so a stop or delete stays
final.

### Outbound service connections

Workloads publish no host ports. Shim connects each service *out* to an
independent data relay, which works through NAT and keeps nodes unreachable from
outside:

1. Shim gets a signed registration grant from the central gateway for one exact
   execution and service. The gateway checks the live allocation and its policy.
2. Shim verifies the grant and dials the fixed relay over TLS.
3. Grants are short leases that shim keeps renewing, so a service Fleet
   withdraws stops being reachable soon after, even if the node can't be
   contacted.

Stop and delete close every stream before the container is removed or its port
reused, and a reconnect never replays a request. On top of this:

- **Administration** (logs, exec, restart) is a reserved `control` service that
  needs an administrator grant. The Docker daemon is never exposed.
- **Restricted ingress** exposes only declared paths and methods. Shim can
  inject the application's credential on the node, so clients never see it.
- **Single-use ingress** records an invocation in a private ledger *before*
  forwarding it, so a replay is refused.

## TEE startup and resume

### Trust model

Shim and its local Docker run *inside* an already measured confidential VM. Shim
does not create that VM or turn host Docker into an enclave. The VM's measured
init-data confines shim, its endpoint key and its local runtime, so they are part
of what gets attested.

### Admission

Before creating a TEE runtime, shim runs one admission:

1. It builds a **binding** for this launch: the measured profile, init-data,
   endpoint key, execution identity, request digest, a fresh nonce and an expiry.
2. It asks the local attestation agent for evidence over that binding, which
   ties the evidence to this exact launch.
3. The remote proof network runs an approved Ziren guest that verifies the
   evidence. For Intel TDX it uses Automata's pinned DCAP verifier.
4. Shim verifies the receipt against the approved program and the commitment it
   expects, and launches only while the binding is fresh (at most five minutes).

A Trustee appraisal token is not a proof and never authorizes a launch. The
guest commits to its whole input, and shim computes the commitment it expects
itself, so a prover cannot swap in a weaker profile, an old clock or another
launch. An admission job is recorded before it is submitted, and a submission
with an unknown outcome is only polled afterwards, never resent.

### Resume

A crashed TEE runtime gets a new, fresh admission for each restart, for exactly
the request its launch was admitted with. A restarted confidential runtime must
be verified again, not assumed to be the same. One admission starts the
container once, and a failed or expired admission leaves it stopped.

The `tee-simulation` driver runs the same path with sample evidence for tests. It
never satisfies a hardware allocation.

## Policy admission

### Architecture

- **trusted-rail** evaluates policy with a pinned Regorus engine. The same
  engine runs natively and inside its Ziren guest, so both reach the same
  decision.
- **The central policy gateway**, in Fleet, holds the authoritative ledger:
  approved policies, context, budgets and grants. It never runs on an untrusted
  execution node.
- **Nodes** only reserve and consume grants, with scoped, short-lived
  credentials.
- **The remote proof network** proves evaluations, and every receipt is checked
  with Ziren's upstream verifier. Shim never starts a local prover.

### Two modes

Proving takes time, so startup and actions are admitted differently:

- **Strict admission, for startup.** Nothing starts until a proof of an Allow
  decision has been verified.
- **Preflight, for actions.** Proving every serial tool call would add the proof
  network's latency to each step. So the gateway decides at once, and the proof
  (receipt) is generated in the background from the inputs recorded at the
  time. Verifying a receipt never issues authorization.

Preflight is a central administration API, never a mode an agent can choose.

### Grants

A grant is a single-use authorization for one exact request and execution. It
is consumed at the ledger before the action is dispatched, and it is not refunded
if the action fails. Policy changes, revocation and Fleet's scheduler state all
invalidate it early. If the reply to a consume is lost, the grant stays spent
and nothing is dispatched again: a reconciliation is preferred to a duplicate
side effect.

## Native OpenShell

Plain Docker cannot constrain what an agent does in its shell. OpenShell can,
so shim uses it through its upstream interfaces, unmodified. Its access layer
applies to every driver: with no user rules it adds nothing; with rules, shim
requires native enforcement before it creates the runtime.

A native launch is authorized centrally and executed locally:

1. Fleet reserves the allocation on the node before any credentials exist.
2. Fleet and the stock OpenShell gateway prepare the sandbox, and a
   `runtime.create` evaluation bound to the complete launch input is proven.
3. Fleet delivers the result over the private socket. Shim checks it, consumes
   the grant at the central ledger, then creates the sandbox exactly once.

Credentials never reach arguments, status or node state. Shim records sandbox
ownership locally without them, so stop, delete and inspect still work during a
gateway outage, and a create that got no answer is never resent.

Native services also publish no host ports. Shim reaches the workload over SSH
through the stock supervisor, pinned to the host key from the proof-bound launch,
and services then go out through the same relay connector as Docker ones.
