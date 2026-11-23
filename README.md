# trusted-shim

The machine-local runtime under [zkm-fleet](https://github.com/ProjectZKM/zkm-fleet).
Fleet schedules workloads across machines. On each machine, shim runs them,
connects their services out to the data relay, and enforces what may start:
attestation and a verified remote proof for confidential workloads, and policy
admission for actions.

```text
Fleet scheduling and allocation
  -> fleet-node / per-machine Ray
    -> shim: OpenShell access layer -> RuntimeDriver -> Docker / TEE runtime
    -> shim: router connector -> independent data relay

central policy gateway -> approved policy/program + authorization ledger
startup: shim -> rail -> remote proof -> verification -> grant -> create
action:  preflight evaluation -> durable receipt job + grant -> dispatch
         receipt job -> remote proof -> verification (background)
```

- **Fleet** owns placement, retries and confirmed release of resources.
- **Shim** owns one machine's authorized executions, their state and their
  outbound connections.
- **[trusted-rail](https://github.com/attestx/trusted-rail)** evaluates policy
  with a pinned Regorus engine; the same engine runs inside its Ziren guest.
- **The remote proof network** generates proofs; shim checks them with Ziren's
  upstream verifier. Shim never starts a local prover.

## Running it

The image workflow publishes `ghcr.io/attestx/trusted-shim:sha-<full-commit>`
(and version tags for `v*`) with two executables:

- `trusted-shim-runtime`, the node service.
- `trusted-shim-socket`, a small static helper for the native OpenShell
  supervisor image.

Fleet's node installer starts the service in its own systemd unit:

```sh
trusted-shim-runtime --serve --state-dir /var/lib/zkm-fleet/shim --node-id machine-name
```

Keep it out of fleet-node's cgroup, with no `PartOf`/`BindsTo` on it, so upgrading
the node never stops shim or its workloads. Keep the state directory across
restarts and upgrades: it holds each allocation's journal and fences.

The service listens only on `STATE/control.sock` (mode 0600, same UID). Each
connection sends one bounded JSON request and closes its write half:

```json
{"protocol":1,"node_id":"machine-name","command":{"operation":"capabilities"}}
```

The reply has `protocol` and either `result` or `error`. Operations are
`capabilities`, `launch`, `inspect`, `stop`, `resume`, `delete`, `network`,
`allocate` and `provision`. A request runs to completion even if the caller
disconnects.

Other modes: `--probe-machine` reports the TEE devices it sees (not a successful
attestation), and `--state-dir DIR --node-id ID` without `--serve` runs a single
request from stdin.

## Drivers

A launch selects one driver:

| Driver | Runs | Before it starts |
|---|---|---|
| `docker` | A Docker container on the host, with hard CPU/memory limits when requested | Nothing beyond the request checks |
| `tee` | Docker inside an already measured TDX/SNP confidential VM | Fresh evidence and a verified remote proof, at launch and at every restart |
| `tee-simulation` | The same path, with sample evidence and no hardware | The same, for tests. Never satisfies a hardware allocation |

The OpenShell access layer applies to every driver. With no user rules it adds
nothing; with rules, shim requires native OpenShell enforcement before creating
the runtime. `openshell` as a driver name is kept only for existing journals.

A Running allocation whose container exits stays down until Fleet asks shim to
`resume` it. Shim then starts the same container again with its state intact; a
TEE runtime gets a fresh admission first. A stopped or deleted allocation is
never resumed, and a missing container is never recreated.

## Capabilities

`capabilities` reports the drivers this machine offers and these features. Fleet
uses only what a node advertises.

| Feature | Meaning |
|---|---|
| `runtime-daemon-v1` | The persistent `--serve` service |
| `data-plane-v1` | Outbound service connections through the data relay |
| `chisel-network-v1` | Connections can use an upstream Chisel client (`tunnel_binary`) |
| `runtime-management-v1` | The administrator `control` service: metadata, logs, exec, restart |
| `single-use-ingress-v1` | Ingress rules with `single_use: true` |
| `runtime-resume-v1` | `resume` for Docker runtimes |
| `runtime-exit-status-v1` | `exit`: how an exited container's process ended, including an OOM kill |
| `runtime-run-to-completion-v1` | `driver_options.run_to_completion`: a run that ends with its process, such as a batch job |
| `openshell-access-v1` | The OpenShell access layer |
| `tee-startup-v1` | This node has a TEE driver |
| `runtime-resume-tee-v1` | `resume` for TEE runtimes, behind a fresh admission |
| `openshell-provisioning-v1`, `openshell-allocation-v1` | A native OpenShell endpoint is configured |
| `openshell-attachments-v1` | Native GPUs and durable volumes |
| `openshell-local-services-v1`, `openshell-service-health-v1`, `openshell-tcp-services-v1`, `openshell-ingress-v1` | Native services, their health, TCP services and restricted ingress |

## Documentation

- [Design](docs/design.md): the architecture and the reasons behind it, for the
  node runtime, TEE admission, policy admission and native OpenShell.
- [Attestation guest](attestation/README.md) and
  [contract acceptance](contracts/README.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check_engine_features.py
```

Tests that need real Docker are ignored by default:

```sh
docker pull alpine:3.21
cargo test --locked --test docker -- --ignored
cargo test --locked --test daemon -- --ignored
cargo test --locked --all-features --test tee simulated_ -- --ignored
```

Proof networks, receipts and ledgers in tests are orchestration doubles, not ZK
proofs, and no test starts a prover. Other ignored tests need extra
services: stock Trustee (`TRUSTEE_TEST_ENDPOINT`, run in CI) and a pinned
OpenShell gateway binary (`OPENSHELL_GATEWAY_BINARY`).
