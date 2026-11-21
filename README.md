# trusted-shim

Machine-local runtime and trust interfaces below zkm-fleet. This framework PR
contains contracts only. Docker/OpenShell drivers, policy wiring, proof-network
clients and live isolation tests follow framework review.

## Ownership

```text
Fleet scheduling and allocation
  -> fleet-node / per-machine Ray
    -> shim RuntimeDriver -> Docker / OpenShell / TEE runtime
    -> router Connector   -> independent data relay

central policy gateway -> approved policy + cumulative authorization ledger
shim -> rail RuleEngine -> proof network -> ReceiptVerifier -> ledger -> action
shim -> attestation verifier -> proof network -> ReceiptVerifier
```

Fleet owns placement, admission, retries and confirmed resource release. Shim
owns one machine's authorized executions; it has no cluster scheduler. The data
router carries HTTP/SSE/WebSocket and other service payloads. ClawUp backend and
OpenShell gateway remain control-plane services.

## Interfaces

- `RuntimeDriver`: idempotent launch, inspect, stop and confirmed deletion bound
  to full `ExecutionIdentity`. Unsupported explicit resource limits fail closed.
- `Connector` (from router): publish only approved runtime-local endpoints and
  withdraw the exact binding, including active streams. Placement may differ by
  runtime isolation domain; a host connector is not assumed to reach every TEE.
- `RuleEngine` and `AuthorizationLedger` (from rail): deterministic decision,
  central atomic budget reservation and single-use authorization.
- `ActionExecutor`: consumes exact-action authorization at the enforcement
  boundary. A connection credential is not permission to execute arbitrary tools.
- `AttestationVerifier`: checks platform evidence and binds it to an execution,
  fresh challenge, endpoint key and policy. `SkippedNonTee` is a separate outcome.
- `ProofNetwork` and `ReceiptVerifier`: remote proving and actual cryptographic
  verification for two separate proof domains, policy evaluation and attestation.

`ProofRequirement` is explicit for each domain. Requiring an attestation proof
while skipping attestation is invalid. Concrete admission code must reject this
combination and unsupported runtime capabilities; struct construction alone is
not validation. Proof-required execution cannot fall back to unproved execution.

## Existing code to reuse

Use Docker's API through an existing Rust client, OpenShell's public SDK/compute
driver/extensions, Trustee's evidence verifiers, and the existing proof-network
protocol. Do not fork OpenShell or start a local prover. Keep native OpenShell
policy enforcement; rail owns rule evaluation, not a replacement sandbox.

The backend's embedded OpenShell gateway integration still needs a feasibility
test for this architecture. In particular, its service exposure and interactive
exec paths must not be presumed to satisfy a control-plane-only boundary. Prove
that the supported upstream interfaces can preserve isolation with a separate
data connector before selecting an adapter. Attestation only establishes what its
measurement and evidence cover; policy decisions do not prove external effects.

## Cross-repository rollout after review

| Repository | Follow-up |
|---|---|
| trusted-data-router | Concrete proxy/tunnel adapter, grants, durable fences, streams |
| trusted-rail | Pinned upstream evaluator, deterministic profile and proof codec |
| zkm-fleet | App allocation/generation binding; local shim adapter; hard limits ([#95](https://github.com/ProjectZKM/zkm-fleet/issues/95)) |
| ClawUp | Existing runtime catalog/adapters; split chat data plane; central policy and access issuance |
| Film | Qwen service URL first, then ComfyUI affinity, worker and artifact adapters |
| agent-runtime-images | Compatible service/readiness contracts and image revisions |

Keep one authoritative existing runtime config per application. Preserve dormant
ACK support. Use normal Docker to validate the shared data plane first; integrate
native enforcement, then real policy and TEE proofs via the proof network.
Fleet cleanup and data durability remain authoritative during all transitions.

## Checks and limits

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

This verifies interface compilation, not runtime behavior. No node, container,
gateway, tunnel, prover or TEE is started by this framework. Framework dependencies
are pinned to the companion PR commits; update pins after their approved merges.
Concrete implementation waits for the user's framework review.
