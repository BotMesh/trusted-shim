# TEE startup and resume

Detailed reference. See the [README](../README.md) for an overview.

## Node-selected TEE startup

The Intel TDX path follows [Automata DCAP](https://github.com/automata-network/automata-dcap-attestation):
the Ziren guest verifies original quote/collateral with pinned upstream Rust code,
then checks the measured profile, init-data, launch binding and TCB floor. Shim
submits the witness to the proof network and checks the receipt against the approved
program/key and exact input commitment. AS is not required for this path.
See [attestation implementation and tests](../attestation/README.md).

The legacy SNP/sample adapter can use stock Trustee AS through generated bindings
from its pinned official gRPC schema. AS is only a precheck, never a proof or
launch authorization. Its token cannot replace raw-evidence verification in the
approved guest. The upstream KBS SDK handles secret delivery, not this AS RPC.

Fleet passes `shim_machine_labels` and `shim_tee` from the existing `apps.yaml`
as daemon `machine` options; no second configuration file is introduced.
`runtime.driver` selects `auto`, `docker`, `tee` or `tee-simulation`.
`--probe-machine` reports visible SNP/TDX/SGX character devices, never successful
attestation. Auto uses a configured TEE adapter; detected devices without an
approved TEE configuration require an explicit operator decision rather than
silently claiming hardware trust. SGX host capability cannot run ordinary Docker
as an enclave. Native OpenShell can use the same node TEE profile: both create
paths pass through the shared RA gate. OpenShell still executes its own native
provisioning and policy enforcement; it does not launch through DockerDriver.

`tee.mode=hardware` accepts `snp`/`tdx`, requires the matching guest device and
immutable workload image digests. `tee.mode=simulation` requires `sample`, needs
no hardware and advertises `tee-simulation`. OpenShell is a shared access capability,
not a driver advertisement. Sample evidence never satisfies
a hardware allocation. Production binaries include `ziren` for real Groth16
receipt verification; there is no no-proof simulation option in the daemon.

Configure the AA `/aa/evidence` endpoint on numeric loopback, approved
measurement/init-data/key digests and pinned RA ELF/program/verifying-key identity.
For TDX, set `tee.dcap` to an absolute collateral artifact path and a positive
minimum TCB evaluation number; omit the Trustee settings. Legacy profiles retain
the stock Trustee v0.19 API and approved attestation policy IDs.
Proof credentials are explicit private files; an optional signer file supports
Fleet's token-bound proof signatures. Nothing discovers workspace credentials.
The proof service and Trustee use reconnecting channels so their outage does not
prevent daemon restart, inspection or cleanup. Configuration/credential files
must remain available locally. For HTTPS, `tee.trustee_tls` requires absolute
`ca_file`, `cert_file` and `key_file` paths. Shim verifies the endpoint hostname
against the configured CA and presents the node certificate. The private key must
be owned by the daemon UID, have no group/other permissions and not be a symlink.
TLS settings cannot be silently ignored on HTTP. Certificate renewal takes effect
on daemon restart; existing runtimes remain independent of the daemon process.
Fleet exposes only appraisal to certificates with a node URI SAN through its
existing HTTPS ingress; AS administration remains private.

The DCAP witness adds the original collateral, verification time and minimum TCB
number to `{binding,evidence}`. The guest commits the canonical witness SHA256
only after all checks succeed. The consumer's expected commitment prevents a
prover from substituting a weaker profile, an old clock input or another launch.
`binding` covers mode, platform, complete measured profile, init-data, endpoint key,
execution identity, launch-request digest, nonce and expiry. The guest checks that
collateral remains valid through that expiry; shim checks its clock again before
creation. Legacy profiles keep `{binding,evidence_sha256}` public values and require
their own approved guest. No SNP hardware guest is shipped yet.

Jobs are recorded before submission; ambiguous submission is only polled on
retry. The gate has a five-minute deadline. A crash before submission may need
operator reconciliation. An expired admission can observe an existing workload
but cannot create it. State is fenced to its trust profile; changing labels does
not migrate allocations or permit removing their cleanup driver.

When the daemon advertises `runtime-resume-tee-v1`, a crashed `tee` or
`tee-simulation` runtime can be resumed in place as a Docker one is. It starts only
behind a fresh admission: new evidence and a proof, for exactly the request digest
its launch was admitted with.
- **Each restart is a numbered start** with its own admission record and nonce; the
  binding format is unchanged. Only the current restart's record is kept, beside the
  launch's.
- **One admission starts the container once.** The start is marked used before
  Docker starts the container. A retried or interrupted restart continues its unused,
  unexpired start without submitting another proof. A failed, rejected or expired
  admission leaves the container stopped.
- **While a restart is admitted,** `inspect` reports `starting`, and a concurrent
  `resume` returns that status. The admission continues if the caller stops waiting,
  and a stop or delete during it stays final.
- **Restarts and launches share** the node's single admission slot, and each has the
  five-minute deadline once it holds the slot.
- **The launch's TEE configuration is required.** After any change to the TEE
  configuration, a crashed runtime stays down until it is cleaned up and launched as
  a new generation.

Simulation checks use actual upstream Trustee sample verification and local Docker;
proof-network/receipt doubles test orchestration and are explicitly not ZK proofs:

```sh
TRUSTEE_TEST_ENDPOINT=http://127.0.0.1:50004 \
  cargo test --locked --all-features --test tee -- --include-ignored
```

Run stock `grpc-as` only on loopback for that test. The checked upstream image is
`ghcr.io/confidential-containers/staged-images/coco-as-grpc@sha256:f65a0a74972781d5a3a9595f6e1308b86343f940738a0b6a23c270a7e8bd065a`.
The test AA endpoint emits the upstream sample evidence format; it is a fixture,
not a hardware attester. No local prover is started.
