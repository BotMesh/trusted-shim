# Policy admission and remote proofs

This page covers how a workload is admitted to start or run an action, and how
the remote proof network proves those policy decisions. Runtime actions use
**preflight**: the central gateway decides at once, and the proof follows in the
background. Startup uses **strict admission**: nothing starts until a verified
proof exists. The page also covers node access to the central ledger, GOAT
registration consent, the remote proof protocol and its acceptance test.
See the [README](../README.md) for an overview.

## Terms

- **Guest**: a program that runs in the Ziren zkVM on the remote proof network.
  The policy guest comes from trusted-rail.
- **Witness**: the exact input to one policy evaluation, which the guest
  evaluates.
- **Receipt**: the ZK proof the remote proof network returns for one evaluation.
- **Grant**: a single-use authorization that the central ledger issues. It must
  be consumed before an action is dispatched.
- **Preflight**: evaluating policy before execution, returning the verdict at
  once, and generating the receipt later.

## Preflight admission for actions

### How a preflight decision is made

`SqliteLedger::preflight` reads the centrally activated policy and the
authenticated context. It then commits all of the following in one transaction:

- the exact witness;
- the decision;
- for Allow, a shared-budget reservation and a single-use grant.

Deny and ApprovalRequired decisions also queue receipts. They get no grant and
no budget charge. If the transaction fails, preflight returns no authorization.

The existing `AuthorizedExecutor` and the authenticated ledger Consume enforce
the exact request. Calling a tool for that action does not generate a second
proof.

### Receipts

Fleet embeds `PreflightWorker`, which uses the existing remote `ProofNetwork`
adapter. A receipt is in one of these states:

| State | Meaning |
|---|---|
| `queued` | Recorded, not yet claimed by the worker |
| `proving` | Claimed by the worker for the remote proof network |
| `verified` | The receipt passed verification |
| `failed` | Proving failed terminally |

A native Allow is never labelled a verified receipt.

The worker proves the persisted original policy and request. This holds even if,
while proving, the policy changes, the grant expires or the instance is revoked.

- Receipt verification never issues or renews authorization.
- Current policy, lease and revocation still gate consumption immediately before
  dispatch.
- The guest proves evaluation of the recorded snapshot. It does not prove the
  SQLite budget write or the execution of the external action.

### Restarts, failures and limits

- Queued tasks survive restart.
- The worker durably claims a submission before it contacts the network.
- After an ambiguous response, the worker polls with the same job ID. It does not
  submit a second time automatically. A crash before the RPC may therefore need
  operator reconciliation.
- A terminal proof failure blocks new preflight actions for that instance. The
  block lasts until an operator reconciles it with a valid original receipt.
- At 128 outstanding receipts (including failures), new admissions fail closed.
- An invalid receipt is never accepted.
- A later proof failure cannot undo an action that has already run.

Receipt retention and monitoring need operator deployment planning. These are
bounded initial limits, not a latency or throughput claim.

### Who may use preflight

Preflight is a trusted central administration API. An untrusted agent never
selects it as a mode.

- It rejects `runtime.*` operations.
- It cannot convert an existing strict request into a native authorization.
- The gRPC `Reserve` method still requires a valid proof. It does not accept
  missing evidence as preflight.

Preflight claims no chain synchronization and no hardware attestation.

## Strict admission for startup

### Policy admission

`PolicyAdmission` uses the actual Regorus evaluator. It computes the canonical
witness and the expected public decision, and it admits only `allow`.

The caller must persist the job ID and the authoritative policy and request
before submission. After an ambiguous RPC outcome, the caller queries that ID
before retrying. After a restart, the caller reconstructs the job from the same
persisted inputs. There is no automatic resubmission.

Pending, failed, expired or invalid proofs never authorize execution. Before
`AuthorizationLedger::reserve` is called, the receipt must verify against the
approved guest key and the exact expected public values.

The central ledger then independently verifies the evidence, the current policy,
context and lease, and the budgets. It then atomically issues and consumes a
single-use grant.

### TEE startup gate

TEE startup has a synchronous gate. Before shim launches the container, it:

1. collects CoCo Attestation Agent evidence;
2. prechecks that evidence through stock Trustee;
3. submits the original evidence to the remote RA program;
4. verifies the receipt.

The current hardware backend is meant for shim and local Docker **inside** an
already measured SNP/TDX confidential VM. It does not create that VM, and it does
not turn host Docker into an enclave. The measured init-data must confine shim,
its endpoint key and the local runtime. Shim does not use Trustee's token as a
proof or as launch authorization.

### The central ledger

`ledger::SqliteLedger` is the durable ledger implementation for the central
policy gateway. An untrusted execution node must not host it.

To set it up:

- Open it in a private durable directory with the approved program and a real
  `ReceiptVerifier`.
- The operator sets a cumulative shared budget.
- The operator activates an exact allocation with its approved policy,
  authoritative context and state root.
- Stage the request and cost before remote submission. After a restart, `request`
  recovers the identical witness.

What the ledger guarantees:

- It re-verifies every receipt.
- It atomically reserves budget across allocations.
- It consumes an HMAC-authenticated grant once, before dispatch.
- Reservations are idempotent. Execution failures do not refund them.
- Policy or context changes invalidate pending grants.
- Revocation is durable, even when it arrives before activation.

Preserve the database, including its signing secret, across restarts. This is a
single-host SQLite authority. Multi-host gateway replicas need a shared
transactional ledger implementation.

Expose the library's operator APIs only through authenticated control
administration. Fleet embeds them in its existing gateway with:

- administrator-only routes;
- an approved guest manifest;
- a private ledger under its data directory.

Ordinary namespace tokens cannot set policy or budgets, and cannot stage
authoritative inputs.

## Node-to-ledger access

### The ledger service

`ledger_transport::LedgerService` embeds a bounded gRPC service in the existing
Fleet-controlled policy gateway. It uses the same authoritative `SqliteLedger`.

- It exposes only `Reserve` and `Consume`.
- It does not start a gateway process.
- It does not export policy, context, budget, activation or request-staging APIs.

The host must serve it behind TLS. When multiple Rustls crypto provider features
are linked, the host must select its provider before it constructs the listener.
The transport does not override the host's crypto configuration.

`RemoteLedger::connect` requires HTTPS, except for numeric loopback HTTP.
Operator-supplied channels support a private CA or mTLS. Clients:

- enforce 30-second call deadlines;
- bound message sizes;
- enforce exact execution binding;
- make no application retries;
- never discover credentials or select an agent's URL.

### Access credentials

The central operator calls `SqliteLedger::issue_access` for one exact execution.
An execution is identified by namespace, workload, allocation, lease, generation
and node. The operator chooses the scope:

| Scope | Allows |
|---|---|
| Admission | Reserve |
| Execution | Consume |
| Both | Reserve and Consume |

- Credentials contain 256 random bits.
- They expire within one hour.
- Only their hashes enter the central database.
- An embedding scheduler must also cap validity at any fixed allocation lease
  deadline.
- The scheduler must deliver secrets through its authenticated private
  provisioning channel. It must never put them in ordinary App JSON or node
  reports.
- Rotation issues a replacement credential and revokes the old one. It does not
  reset grants or budgets.
- `revoke_access` withdraws one credential. `revoke` fences the allocation.

### Checks and failure behavior

The ledger checks credential validity and scope before proof verification, and
again in the reservation transaction. Consumption checks authorization and marks
the grant spent in the same transaction, so revocation cannot race between these
steps.

Gateway restarts preserve credentials, revoked state, budgets and consumed
grants.

None of these authorize dispatch:

- unknown credentials;
- wrong scopes;
- stale authority;
- transport failures.

A response can be lost after consumption. The grant then stays spent. Shim keeps
its local Authorizing state and does not create a native sandbox on retry. This
favors reconciliation over duplicate external effects.

### Fleet's scheduler fence

`LedgerService::with_authority` lets Fleet keep its live scheduler state fence in
place through reservation and consumption on the blocking ledger worker. Fleet
checks:

- the exact reported execution;
- the current deployment;
- a fresh node session;
- an active namespace;
- a held quota allocation.

Suspension, release, stale heartbeats and replacement therefore reject old
credentials, even if their TTL has not elapsed.

The service is mounted in Fleet's gateway. Fleet provisions private credentials
and activates the exact execution before native Create. Credentials are delivered
only through the private node channel.

### Tests

Tests run the service over real loopback gRPC and TLS. They cover:

- concurrent consumption;
- all six execution identity fields;
- credential rotation and expiry;
- revocation during proof verification;
- gateway reopen;
- OpenShell dispatch after an ambiguous reply.

These tests use proof and native-driver doubles for orchestration. They do not
claim a new remote proof or a native sandbox isolation acceptance.

### Running an authorized action

`AuthorizedExecutor` binds a grant to the full request and execution identity.
It consumes the grant through the ledger before it invokes `ActionHandler`. It
rejects substitution, expiry and replay. Execution failure does not refund the
grant.

The handler must sit behind the runtime's native enforcement boundary. Wrapping
a Rust function cannot constrain arbitrary shell access in plain Docker. An
authorization proof establishes a policy decision, not an external side effect.

## GOAT registration (future)

### Current status

GOAT registration execution is deliberately deferred.

- The owner-consent interface below does not register an agent. It does not add
  a registration requirement to today's Docker path.
- Ordinary non-TEE registration will require owner authorization and agent-key
  possession, with an explicit `unattested` identity. It must never synthesize a
  successful RA result.
- Concrete multi-TEE RA guests and the GOAT agent registry integration remain
  TODO.
- Policy editing currently goes through the application/control plane. The
  planned GOAT authority must authenticate the owner, chain/contract, policy
  version, digest, finality and revocation before it activates its local policy
  snapshot.

### The owner-consent interface

`registration::PreparedRegistration` prepares a versioned EIP-712 wallet request.
It verifies an owner's EOA signature with Alloy/k256.

- The control plane supplies the approved chain, the future
  authorization-adapter address and the identity registry. These must not come
  from the signature submission.
- The authenticated product owner must independently match the recovered signer.
- This is a library interface. It has no chain RPC, wallet custody, transaction
  submission or readiness mutation.

### Inputs to prepare before signing

Prepare these immutable inputs before you ask the user to sign:

- **Identity**: owner wallet, product agent ID, agent public-key address and the
  exact execution commitment. Preparing an agent key is not the same as enabling
  its actions. The future adapter must still verify key possession and any TEE
  binding.
- **Content commitments**: SHA-256 commitments of the canonical runtime
  configuration and policy, plus the agent manifest URI and content hash. The
  caller must verify these hashes against the approved content. Signatures alone
  do not authenticate hashes the caller supplies.
- **Trust requirement**: `unattested`, or `tee_required` with the approved
  attestation profile hash. This records the requested trust level, not a
  successful result.
- **Freshness**: a fresh random 32-byte nonce and a bounded validity window (at
  most 24 hours).

Changing any bound input requires a new user signature. This includes the
allocation after a scheduling retry.

### Signing and verification

- `signing_request()` returns the `eth_signTypedData_v4` payload. Integers are
  decimal strings, to preserve precision in JavaScript wallets.
- `digest()` returns its EIP-712 digest.
- Submit `{intent_digest, signature}` through the authenticated private control
  path. Signatures are authorization material. Do not log them or include them in
  workload metadata.
- Verification requires a canonical 65-byte low-S signature with v=27/28, a
  current validity window and the current authenticated owner.
- Contract wallets (ERC-1271) remain unsupported.

### What a verified signature means

`VerifiedOwnerSignature` is deliberately not deserializable and is **only
consent**. It is not a grant, a proof of key possession, an RA result or an
on-chain registration.

Verification is pure and repeatable. It does not consume the nonce. No deployed
authorizer address is supplied. Do not expose this interface as a live
registration button until its consumer is implemented and approved.

### Remaining registration work (TODO)

- an owner-preserving contract adapter;
- atomic durable nonce consumption and idempotency;
- signature revocation and current policy checks;
- agent-key possession;
- RA receipt binding for TEE profiles;
- transaction reconciliation and confirmation handling.

Stock ERC-8004 `register(string)` mints to the transaction sender. It does not
accept this owner signature. A backend must not relay that call and then claim
the resulting identity belongs to the signing user. See the
[ERC-8004 specification](https://eips.ethereum.org/EIPS/eip-8004) and the
[pinned upstream identity registry](https://github.com/erc-8004/erc-8004-contracts/blob/b9e466c250744a7e06b13dff9d3c2844ed64f825/contracts/IdentityRegistryUpgradeable.sol).

### Registration tests

Tests decode the exported wallet JSON independently through Alloy's dynamic
EIP-712 encoder. They compare it with the static Solidity-struct digest and
verify a real test-key signature. They reject:

- every bound-field substitution;
- cross-chain and cross-registry reuse;
- wrong owners;
- expired or early consent;
- high-S and malformed signatures.

These tests make no network calls and create no on-chain identities.

## Remote proof protocol

### Connecting to the network

`ZirenNetwork` uses the upstream StageService protobuf and ZKM stdin framing. It
uploads the approved ELF, preserves caller job IDs and requests Groth16 output.

- Credentials and channels are explicit. There is no SDK initialization and no
  credential-file discovery.
- HTTPS uses system roots.
- Numeric loopback HTTP is supported for Fleet's loopback-only proof-app
  endpoint.
- A deployment can inject a channel with its own private CA or mTLS
  configuration.
- Never accept a channel that an agent selects.

Older Fleet deployments require a token-bound EIP-191 signer as well as bearer
authentication. `with_fleet_signer` supplies it explicitly. It uses the same
message encoding and crypto libraries as Fleet. Token-only networks need no
signer.

`ZirenNetwork` does not use worker-supplied download URLs or output streams for
verification.

### Verifying proofs

With the `ziren` feature, `ZirenGroth16Verifier` accepts the upstream SDK Groth16
JSON variant. It uses `zkm-verifier` from the pinned Ziren revision. It verifies:

- the cryptography;
- the expected public bytes;
- the approved program key, including the upstream recursion-key allowlist.

Other proof formats fail closed. The gateway must approve the ELF/key mapping. A
worker cannot select a verification manifest.

### Program identity

- `ProgramRef.program_sha256` hashes the ELF.
- `verifying_key_sha256` hashes the decoded 32-byte program key
  (`vk.bytes32()`), not the global Groth16 circuit key.

trusted-rail's guest checker produces both values through upstream static
machine setup. The guest, checker, verifier and Fleet prover image revisions must
agree.

### Evaluator profile upgrades

Rail's v2 evaluator profile includes checked collection-index conversions, so
native and MIPS decisions match.

- Roll out the native evaluator, guest ELF, approved program key and explicitly
  approved policy revisions together.
- Old profiles fail closed. Existing stored policies and receipts are not
  silently rewritten.
- Run `scripts/check_engine_features.py` in every consumer build. It audits the
  exact evaluator source and Cargo features.
- A previous remote proof does not validate the new ELF. Repeat network
  acceptance before enabling it.

## Remote acceptance test

### Prepare the proof app

1. Build trusted-rail's guest and run its native/MIPS differential checker. Keep
   build outputs, synthetic witnesses and the generated program manifest outside
   project directories.
2. Register that ELF as a dedicated Fleet proof app, with the matching prover
   image and a shared proof storage root.
3. Start its prover through Fleet.
4. Point a `fleet-proof-app` endpoint at that app's namespace, ELF and storage.
   The Fleet control-plane URL is not the app's StageService endpoint.

### Run the example

Supply credentials through the environment, from an explicitly selected secret
source. Never pass token values on the command line or keep them in tracked
files.

```sh
# TRUSTED_PROOF_ENDPOINT: the app's authenticated StageService endpoint
# TRUSTED_PROOF_TOKEN: namespace token
# TRUSTED_PROOF_SIGNER: optional hex SDK key required by older Fleet deployments
export CARGO_TARGET_DIR=/absolute/path/outside-projects/build
cargo run --locked --features ziren --example remote-policy-proof -- \
  /absolute/path/policy-guest.elf 0xPROGRAM_KEY_FROM_MANIFEST \
  /absolute/path/read.witness.json UNIQUE_PERSISTED_JOB_ID \
  /absolute/path/outside-projects/receipt.json
```

The example:

- submits to the remote network;
- polls for up to 30 minutes;
- verifies the receipt;
- rejects substituted public values;
- optionally saves the verified receipt.

It never starts a prover or dispatches an action. Synthetic historical inputs
test proof correctness. Live admission separately requires current validity.

Remote proving operators can see the witness.

After testing, stop the dedicated app through Fleet and confirm that its
resources are released.

## Checks and remaining adapters

### What is in place

- The current migration baseline is **DockerDriver + the shared OpenShell access
  layer**. Default access remains subject to driver restrictions. User-configured
  rules require OpenShell enforcement.
- `DockerDriver` and the confidential-VM `TeeDriver` implement the machine-local
  `RuntimeDriver`. The data-plane adapter owns outbound connectors.
- The CoCo evidence adapter and the optional Trustee gRPC adapter are concrete.
- The TDX guest reuses Automata DCAP verification.
- Fleet embeds the central ledger. It implements private provisioning, native
  launch preparation and gateway readiness.
- Non-TEE attestation remains `SkippedNonTee`. Requiring an attestation proof for
  that outcome is invalid.
- No permissive fallback or local prover is included.

TEE simulation and fixture-based guest tests do not qualify a node for
hardware-attested production workloads.

### Deferred acceptance work

- [ ] Real TDX: validate a fresh, launch-bound quote and collateral on a measured
  confidential VM, including OpenShell enforcement and runtime creation.
- [ ] Startup proof: publish/approve the DCAP guest. Obtain and verify its
  launch-bound receipt through the remote proof network before creating a runtime.
  Execution-only guest tests and existing policy receipts do not satisfy this gate.
  Do not start a local prover.
- [ ] AMD SNP: implement full raw-evidence verification in its approved guest and
  complete hardware plus proof-network startup acceptance. An AS result alone
  cannot authorize launch.

Other follow-ups:

- collateral refresh;
- SNP guests;
- SGX/Nitro isolation backends;
- live hardware and proof-network acceptance;
- integrating application action hooks, so preflight enforcement cannot be
  bypassed.

### Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
python3 scripts/check_engine_features.py
```

Tests cover:

- protocol framing and authentication;
- admission failure paths;
- request substitution;
- concurrent grant consumption;
- rejection by the real crypto verifier.

Test ledgers and proof networks are orchestration doubles. They are not
production implementations or evidence of successful remote proving. The feature
audit must also run in downstream binaries, to prevent widening Regorus's
deterministic profile.
