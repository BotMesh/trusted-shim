# Offline DCAP verification

The Intel TDX launch guest reuses Automata's `dcap-rs` at
[`5962363a`](https://github.com/automata-network/automata-dcap-attestation/tree/5962363a6cce70fa6da70bb412e0a9ababe97d95/rust-crates/libraries/dcap-rs).
It uses `verify_dcap_quote_v2`, with the upstream production policy and Intel root
key. No `minimal` mode, AS verdict, caller-selected root, network call or local
prover is involved. SNP is a separate adapter and is not supported by this guest.

`types/` contains only the shared witness/commitment encoding. The runtime does
not link the verifier's crypto dependency tree: Automata pins `base64ct=1.6.0`,
while OpenShell's SSH client requires a newer version. The separate verifier/guest
workspaces preserve both upstream implementations without a fork. Native tests
and the MIPS guest use the same verifier source. `x509-verify=0.4.6` matches
Automata's lockfile; later compatible-numbered releases changed X.509 types.

## Checks and trust boundary

Automata authenticates the original quote, Intel certificate chains and CRLs,
signed TCB/QE information, QE report and attestation-key binding, TDX module and
production attributes. The launch guest additionally requires:

- Hardware TDX and the `trusted-shim.remote-attestation.dcap.v2` domain.
- Up-to-date TCB, no advisories, and an operator-approved minimum TCB evaluation
  number checked against both the signed TCB information and QE identity.
- An approved complete measured profile. `measurement()` hashes its domain,
  MRSEAM, MRSIGNERSEAM, SEAM/TD attributes, XFAM, MRTD, MROWNER, MROWNERCONFIG and
  all four RTMRs, in that order. Fields have their fixed hardware lengths.
- MRCONFIGID equal to the configured init-data SHA256 plus 16 zero bytes.
- REPORTDATA equal to SHA256(canonical launch binding) plus 32 zero bytes.
- Verification time before the launch deadline, at most 300 seconds apart, and
  every authenticated certificate/CRL/TCB/QE document valid through that deadline.

The public output commits the canonical **entire witness**, including evidence,
collateral, launch binding, time and policy floor. Shim constructs the expected
commitment itself and checks the receipt against its approved ELF/key mapping.
Computing that expected commitment is not verification; runtime creation still
requires a valid ZKP. The prover cannot choose the time, policy or program.
The consumer checks its own clock and replay state; the guest has no trusted clock.

The operator must refresh collateral and raise the TCB floor as Intel publishes
security updates. Valid signatures do not prove that a snapshot is the latest.
This implementation pins all RTMRs, so it does not derive trusted claims from an
unverified event log. An updated measured image requires a reviewed profile.
The measured boot environment must enforce init-data, protect the endpoint key
and confine shim's create endpoints. Merely hashing a desired key into REPORTDATA
does not demonstrate possession or confinement. TEE VM provisioning and external
control-plane verification of the launch receipt remain separate integration work.

## Node configuration

Use Fleet's existing `apps.yaml`, under `shim_tee` (daemon: `machine.tee`):

```yaml
mode: hardware
platform: tdx
dcap:
  collateral_file: /var/lib/zkm-fleet/attestation/tdx-collateral.abi
  min_tcb_evaluation_data_number: 20 # example only; approve the current floor
```

Retain the existing evidence endpoint, measurement/init-data/key digests and
proof-network/ELF/key settings. Omit `trustee_endpoint`, `trustee_policy_ids` and
`trustee_tls` for AS-free operation. An explicitly configured AS is an additional
precheck; its failure cannot downgrade the proof requirement.

`collateral_file` is a fetched public artifact, **not another configuration file**.
Its bytes use Automata's `Collateral::sol_abi_encode()` format, compatible with
its PCCS collection tooling. Fetch outside the guest and replace the file
atomically. Shim snapshots these bytes in the pending job; a restart or refresh
cannot rebind an already submitted proof. Automatic PCCS refresh is not included.

## Validation

```sh
cargo test --locked --manifest-path attestation/Cargo.toml
cargo clippy --locked --manifest-path attestation/Cargo.toml --all-targets -- -D warnings
export CARGO_TARGET_DIR=/path/outside/repository/build
bash scripts/build_attestation_guest.sh --features quote-check
cargo run --locked --manifest-path attestation/Cargo.toml --example export-vectors -- /path/to/vectors
cargo run --locked --manifest-path guest-check/Cargo.toml -- \
  "$CARGO_TARGET_DIR/mipsel-zkm-zkvm-elf/release/dcap-quote-check" \
  /path/to/vectors/tdx4.input /path/to/vectors/tdx4.output
```

The `quote-check` feature builds an execution-only compatibility harness, with
Automata's original ABI input and journal. **Never approve that ELF as the launch
guest.** The launch ELF is `trusted-shim-dcap-guest`. Run it with
`unbound-launch.input reject`; a historical signed quote must fail the fresh
launch-binding check. Also check `tdx5` for journal parity and the quote harness
with `migration.input reject` and `bad-signature.input reject`.

These checks execute MIPS instructions without generating proofs. They do not
claim a successful hardware launch or proof-network acceptance. A live TDX quote
bound to an approved measured shim environment, a network-generated receipt and
consumer verification are still required before migration. GOAT registration is
TODO and must require a user-signed authorization.
