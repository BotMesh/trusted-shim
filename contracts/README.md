# Policy proof verification on EVM

This acceptance path verifies an existing Proof Network receipt with Ziren's
unmodified v2.0.0 Solidity verifier. It never starts a prover. Both the native
verifier and the contract bind the approved guest key, exact committed public
bytes and pinned recursion verification-key root. The receipt's public-input
strings are not treated as authoritative.

`PolicyProofRecord` pins the program key and verifier at deployment. Its `record`
transaction verifies the proof and emits the SHA-256 of the public values. It
does **not** authorize an action or parse a decision from JSON. Historical allow,
deny and approval-required computations may all have valid proofs. Current policy
ownership, validity, revocation, budgets and single-use dispatch still belong to
the central authorization ledger. Repeated recording is allowed. Public values
are public transaction calldata; witnesses and application keys are never sent.

## Reproduce against a real remote receipt

Use the guest ELF and key from the operator-approved build manifest, the canonical
policy/request witness and the Groth16 receipt produced remotely. Generated files
must remain outside a git checkout. The exporter executes the same native policy
engine and verifies cryptography before writing calldata with private permissions:

```sh
export CARGO_TARGET_DIR=/absolute/external/build
cargo run --locked --features ziren --example export-policy-proof -- \
  /absolute/external/guest.elf 0xAPPROVED_PROGRAM_VKEY \
  /absolute/external/witness.json /absolute/external/receipt.json \
  /absolute/external/evm-fixture.json

python3 scripts/verify_policy_evm.py \
  --circuits /absolute/existing/zkm/circuits/groth16/v2.0.0 \
  --ziren-source /absolute/existing/Ziren \
  --fixture /absolute/external/evm-fixture.json \
  --work-dir /absolute/external/new-evm-acceptance
```

Requirements: Python 3.10+, Rust, Foundry (`forge`, `anvil`), Solc 0.8.20, the
existing upstream source commit `c9988a098d92bc55a85ca9307c470d1f97be3337`, and
the already downloaded v2.0.0 circuit files. The script copies only two small
Solidity sources and checks their SHA-256 and the verification-key hash against
the pinned release. It reads the interface at that exact upstream git commit.
No SDK initialization, artifact generation or proving-key loading occurs.

Foundry tests reject substituted program keys, public values, proof bytes,
circuit selectors, truncated packets and noncanonical trailing bytes. The script
then starts an isolated loopback Anvil chain, deploys the upstream verifier and
record contract, and sends a **non-view transaction** that records the verified
proof. All three successful receipts and the emitted record are required.
It saves transaction hashes and gas usage in `result.json`, then stops its own
Anvil process. Compiler output, vendored source, broadcasts and diagnostics remain
under the external work directory.

The recorded acceptance used Fleet proof job
`p-47e08ab1f10d378b87cf5917979d976ec3fcf06b0e2f47277ef87a2ffc27695e`
and the actual trusted-rail guest. The proof-record transaction consumed 253,153
gas on local Anvil. This is EVM execution acceptance, not a public-testnet
deployment or evidence that TEE attestation proving is implemented.

Upstream contract/artifact contract: https://docs.zkm.io/dev/verifier.html
