# TEE startup and resume

This page explains how shim decides whether a confidential workload may start
on a TEE (trusted execution environment) node, and how it restarts one after a
crash. It covers the admission check, the Intel TDX path through Automata DCAP,
the legacy SNP/sample path through Trustee, node configuration and the tests.
See the [README](../README.md) for an overview.

## Terms

- **Admission**: the check shim runs before it creates or restarts a TEE
  runtime. It collects fresh evidence, gets a proof and verifies it. This is the
  shared RA (remote attestation) gate.
- **AA** (attestation agent): the local service that returns hardware evidence
  at its `/aa/evidence` endpoint.
- **AS** (attestation service): the stock Trustee service that appraises
  evidence. Only the legacy path uses it, and only as a precheck.
- **DCAP**: Intel's Data Center Attestation Primitives, used to verify a TDX
  quote (the signed hardware evidence).
- **Collateral**: the Intel-signed data needed to verify a quote, such as
  certificate chains, CRLs and TCB information.
- **TCB floor**: the minimum TCB evaluation number that the operator approves.
- **Init-data**: the measured data that confines shim and its local runtime
  endpoints. The node configuration names its approved digest.
- **Guest**: the approved Ziren program that verifies the evidence. The proof
  network runs it and returns a **receipt**, the proof of its output.
- **Witness**: the input that shim gives the guest.

## How a TEE launch is admitted

### Intel TDX through Automata DCAP

The Intel TDX path follows
[Automata DCAP](https://github.com/automata-network/automata-dcap-attestation):

1. The Ziren guest verifies the original quote and collateral with pinned
   upstream Rust code.
2. The guest then checks the measured profile, init-data, launch binding and
   TCB floor.
3. Shim submits the witness to the proof network.
4. Shim checks the receipt against the approved program and key, and against
   the exact input commitment.

This path does not require an AS. See
[attestation implementation and tests](../attestation/README.md).

### Legacy SNP and sample profiles through Trustee

The legacy SNP/sample adapter can use a stock Trustee AS. Shim talks to it
through bindings generated from the AS's pinned official gRPC schema.

- The AS is only a precheck. It is never a proof and never authorizes a launch.
- An AS token cannot replace raw-evidence verification in the approved guest.
- Legacy profiles keep `{binding,evidence_sha256}` as public values. They need
  their own approved guest.
- No SNP hardware guest is shipped yet.

The upstream KBS SDK handles secret delivery, not this AS RPC.

## What the proof binds

The launch `binding` covers:

- mode and platform
- the complete measured profile
- init-data
- the endpoint key
- the execution identity
- the launch-request digest
- a nonce and an expiry

The DCAP witness is `{binding,evidence}` plus three more inputs: the original
collateral, the verification time and the minimum TCB number.

The guest commits the SHA256 of the canonical witness, and only after every
check succeeds. Shim, as the consumer, knows which commitment to expect. This
stops a prover from substituting a weaker profile, an old clock input or
another launch.

Two clock checks protect the expiry:

- The guest checks that the collateral stays valid through the expiry.
- Shim checks its own clock again before it creates the runtime.

## Admission jobs and the deadline

- Shim records each job before it submits it.
- If a submission is ambiguous, a retry only polls for its result.
- A crash before submission may need operator reconciliation.
- The gate has a five-minute deadline.
- An expired admission can observe an existing workload. It cannot create one.
- State is fenced to its trust profile. Changing labels does not migrate
  allocations, and it does not permit removing their cleanup driver.

## Configuration

### Where it comes from

Fleet takes `shim_machine_labels` and `shim_tee` from the existing `apps.yaml`
and passes them to the daemon as `machine` options. There is no second
configuration file.

`runtime.driver` selects `auto`, `docker`, `tee` or `tee-simulation`.

- `--probe-machine` reports the SNP/TDX/SGX character devices it can see. This
  never means attestation succeeded.
- `auto` uses a configured TEE adapter. If shim detects devices but there is no
  approved TEE configuration, the operator must decide explicitly. Shim does not
  silently claim hardware trust.
- An SGX-capable host cannot run ordinary Docker as an enclave.

### Hardware and simulation modes

| Mode | Platform | Requires | Advertises |
|---|---|---|---|
| `tee.mode=hardware` | `snp` or `tdx` | The matching guest device and immutable workload image digests | `tee` |
| `tee.mode=simulation` | `sample` | No hardware | `tee-simulation` |

- Sample evidence never satisfies a hardware allocation.
- OpenShell is a shared access capability, not a driver advertisement.
- Production binaries include `ziren` for real Groth16 receipt verification.
  The daemon has no simulation option that skips the proof.

### Attestation and proof settings

Configure:

- the AA `/aa/evidence` endpoint, on a numeric loopback address
- the approved measurement, init-data and key digests
- the pinned RA ELF, program and verifying-key identity

For TDX, set `tee.dcap` to an absolute collateral artifact path and a positive
minimum TCB evaluation number. Omit the Trustee settings.

Legacy profiles keep the stock Trustee v0.19 API and the approved attestation
policy IDs.

Credentials:

- Proof credentials are explicit private files.
- An optional signer file supports Fleet's token-bound proof signatures.
- Nothing discovers workspace credentials.
- Configuration and credential files must stay available locally.

Shim's channels to the proof service and to Trustee reconnect on their own. An
outage of either service does not stop the daemon from restarting, inspecting
or cleaning up.

### Trustee TLS

For HTTPS, `tee.trustee_tls` requires absolute `ca_file`, `cert_file` and
`key_file` paths.

- Shim verifies the endpoint hostname against the configured CA and presents
  the node certificate.
- The private key must be owned by the daemon UID, must have no group or other
  permissions, and must not be a symlink.
- TLS settings on an HTTP endpoint are rejected. Shim does not silently ignore
  them.
- A renewed certificate takes effect when the daemon restarts. Existing
  runtimes stay independent of the daemon process.

Fleet exposes only appraisal, through its existing HTTPS ingress, and only to
certificates with a node URI SAN. AS administration stays private.

### Native OpenShell

Native OpenShell can use the same node TEE profile. Both create paths pass
through the shared RA gate. OpenShell still runs its own native provisioning and
policy enforcement. It does not launch through DockerDriver.

## Resuming a crashed TEE runtime

When the daemon advertises `runtime-resume-tee-v1`, shim can resume a crashed
`tee` or `tee-simulation` runtime in place, as it does a Docker one. The runtime
starts only behind a fresh admission: new evidence and a proof, for exactly the
request digest its launch was admitted with.

- **Each restart is a numbered start.** It has its own admission record and
  nonce. The binding format is unchanged. Shim keeps only the current restart's
  record, beside the launch's.
- **One admission starts the container once.** Shim marks the start as used
  before Docker starts the container. A retried or interrupted restart continues
  its unused, unexpired start without submitting another proof. A failed,
  rejected or expired admission leaves the container stopped.
- **While a restart is being admitted,** `inspect` reports `starting`, and a
  concurrent `resume` returns that status. The admission continues if the caller
  stops waiting. A stop or delete during the admission stays final.
- **Restarts and launches share the node's single admission slot.** Each gets
  the five-minute deadline once it holds the slot.
- **The restart needs the launch's TEE configuration.** After any change to the
  TEE configuration, a crashed runtime stays down until it is cleaned up and
  launched as a new generation.

## Tests

The simulation tests use actual upstream Trustee sample verification and local
Docker. The proof network and receipts are doubles that test orchestration.
They are explicitly not ZK proofs.

```sh
TRUSTEE_TEST_ENDPOINT=http://127.0.0.1:50004 \
  cargo test --locked --all-features --test tee -- --include-ignored
```

- Run stock `grpc-as` only on loopback for this test. The checked upstream
  image is
  `ghcr.io/confidential-containers/staged-images/coco-as-grpc@sha256:f65a0a74972781d5a3a9595f6e1308b86343f940738a0b6a23c270a7e8bd065a`.
- The test AA endpoint emits the upstream sample evidence format. It is a
  fixture, not a hardware attester.
- No local prover is started.
