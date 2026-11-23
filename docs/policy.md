# Policy admission and remote proofs

Detailed reference. See the [README](../README.md) for an overview.

## Policy admission

Runtime actions use **preflight**: evaluate before execution, return the verdict,
and generate the ZK receipt in the background. `SqliteLedger::preflight` reads the
centrally activated policy and authenticated context, then commits the exact
witness, decision and (for Allow) shared-budget reservation and single-use grant
in one transaction. Deny and ApprovalRequired also queue receipts, without grants
or budget charges. A failed transaction cannot return authorization. The existing
`AuthorizedExecutor` and authenticated ledger Consume enforce the exact request;
calling a tool for that action does not generate a second proof.

Fleet embeds `PreflightWorker` using the existing remote `ProofNetwork` adapter.
Receipt states are `queued`, `proving`, `verified` and `failed`; native Allow is
never labelled a verified receipt. The worker uses the persisted original policy
and request, even if the policy changes, the grant expires or the instance is
revoked while proving. Receipt verification never issues or renews authorization.
Current policy, lease and revocation still gate consumption immediately before
dispatch. The guest proves evaluation of the recorded snapshot, not the SQLite
budget write or the external action's execution.

Queued tasks survive restart. Submission is durably claimed before contacting
the network; an ambiguous response is polled using the same job ID, without an
automatic second submission. A crash before the RPC may therefore need operator
reconciliation. Terminal proof failures block new preflight actions for that
instance until reconciled with a valid original receipt. At 128 outstanding
receipts (including failures), new admissions fail closed. An invalid receipt is
never accepted; an already executed action cannot be undone by a later proof
failure. Receipt retention and monitoring need operator deployment planning.
These are bounded initial limits, not a latency or throughput claim.

Preflight is a trusted central administration API, never a mode an untrusted
agent selects. It rejects `runtime.*` operations and cannot convert an existing
strict request into a native authorization. The gRPC `Reserve` method continues
to require a valid proof; it does not accept missing evidence as preflight.

TEE startup has a synchronous gate: collect CoCo Attestation Agent evidence,
precheck it through stock Trustee, submit the original evidence to the remote
RA program and verify its receipt before launching the container. The current
hardware backend is intended for shim and local Docker **inside** an already
measured SNP/TDX confidential VM; it does not create that VM or turn host Docker
into an enclave. The measured init-data must confine shim, its endpoint key and
local runtime. Trustee's token is not used as a proof or as launch authorization.
GOAT registration execution is deliberately deferred. The owner-consent interface
below does not register an agent or add a registration requirement to today's
Docker path. Ordinary non-TEE registration will require owner authorization and
agent-key possession, with an explicit `unattested` identity; it must never
synthesize a successful RA result. Concrete multi-TEE RA guests and the GOAT agent
registry integration remain TODO. Policy editing currently uses the application/control plane; the
planned GOAT authority must authenticate owner, chain/contract, policy version,
digest, finality and revocation before activating its local policy snapshot.
No chain synchronization or hardware attestation is claimed by preflight.

### Future GOAT registration: user consent interface

`registration::PreparedRegistration` prepares a versioned EIP-712 wallet request
and verifies an owner's EOA signature with Alloy/k256. The control plane supplies
the approved chain, future authorization-adapter address and identity registry;
these must not come from the signature submission. The authenticated product
owner must independently match the recovered signer. This is a library interface,
with no chain RPC, wallet custody, transaction submission or readiness mutation.

Prepare the following immutable inputs before asking the user to sign:

- Owner wallet, product agent ID, agent public-key address and exact execution
  commitment. Preparing an agent key is distinct from enabling its actions; key
  possession and any TEE binding still require verification by the future adapter.
- Canonical runtime configuration and policy SHA-256 commitments, plus the agent
  manifest URI and content hash. The caller must verify those hashes against the
  approved content. Signatures alone do not authenticate caller-supplied hashes.
- Trust requirement: `unattested`, or `tee_required` with the approved attestation
  profile hash. This records the requested trust level, not a successful result.
- A fresh random 32-byte nonce and a bounded validity window (at most 24 hours).
  Changing any bound input, including allocation after a scheduling retry,
  requires a new user signature.

`signing_request()` is the `eth_signTypedData_v4` payload, with decimal-string
integers to preserve precision in JavaScript wallets. `digest()` is its EIP-712
digest. Submit `{intent_digest, signature}` through the authenticated private
control path; signatures are authorization material and must not be logged or
included in workload metadata. Verification requires canonical 65-byte low-S
signatures with v=27/28, current validity and the current authenticated owner.
Contract wallets (ERC-1271) remain unsupported.

`VerifiedOwnerSignature` is deliberately not deserializable and is **only consent**.
It is not a grant, proof of key possession, RA result or on-chain registration.
Verification is pure and repeatable; it does not consume the nonce. No deployed
authorizer address is supplied, and this interface must not be exposed as a live
registration button until its consumer is implemented and approved.

Registration execution remains TODO: an owner-preserving contract adapter,
atomic durable nonce consumption/idempotency, signature revocation and current
policy checks, agent-key possession, RA receipt binding for TEE profiles,
transaction reconciliation and confirmation handling. Stock ERC-8004
`register(string)` mints to the transaction sender; it does not accept this owner
signature. A backend must not relay that call and claim the resulting identity
belongs to the signing user. See the [ERC-8004 specification](https://eips.ethereum.org/EIPS/eip-8004)
and [pinned upstream identity registry](https://github.com/erc-8004/erc-8004-contracts/blob/b9e466c250744a7e06b13dff9d3c2844ed64f825/contracts/IdentityRegistryUpgradeable.sol).

Tests independently decode the exported wallet JSON through Alloy's dynamic
EIP-712 encoder, compare it with the static Solidity-struct digest and verify a
real test-key signature. They reject every bound-field substitution, cross-chain
and cross-registry reuse, wrong owners, expired/early consent, high-S and malformed
signatures. These tests make no network calls and create no on-chain identities.

### Strict admission for startup

`PolicyAdmission` uses the actual Regorus evaluator, computes the canonical
witness and expected public decision, and only admits `allow`. The caller must
persist the job ID and authoritative policy/request before submission. After an
ambiguous RPC outcome, query that ID before retrying. Reconstruct a job from the
same persisted inputs after restart; there is no automatic resubmission.

Pending, failed, expired or invalid proofs never authorize execution. The receipt
must verify against the approved guest key and exact expected public values before
calling `AuthorizationLedger::reserve`. The central ledger must independently
verify evidence, current policy/context/lease and budgets, then atomically issue
and consume a single-use grant. `ledger::SqliteLedger` provides this durable
implementation for the central policy gateway. It must not be hosted by an
untrusted execution node.

Open it in a private durable directory with the approved program and a real
`ReceiptVerifier`. The operator sets a cumulative shared budget and activates an
exact allocation with its approved policy, authoritative context and state root.
Stage the request and cost before remote submission; after restart, `request`
recovers the identical witness. The ledger re-verifies every receipt, atomically
reserves budget across allocations, and consumes an HMAC-authenticated grant
once before dispatch. Reservations are idempotent; execution failures do not
refund them. Policy/context changes invalidate pending grants. Revocation is
durable even when it arrives before activation. Preserve the database, including
its signing secret, across restarts. This is a single-host SQLite authority;
multi-host gateway replicas require a shared transactional ledger implementation.
The library's operator APIs must be exposed only through authenticated control
administration. Fleet embeds them in its existing gateway with administrator-only
routes, an approved guest manifest, and a private ledger under its data directory.
Ordinary namespace tokens cannot set policy, budgets or stage authoritative inputs.

### Authenticated node-to-ledger access

`ledger_transport::LedgerService` embeds a bounded gRPC service in the existing
Fleet-controlled policy gateway. It exposes only `Reserve` and `Consume`, using
the same authoritative `SqliteLedger`; it does not start a gateway process or
export policy, context, budget, activation or request-staging APIs. The host must
serve it behind TLS and select its Rustls crypto provider before constructing
the listener when multiple provider features are linked. The transport does not
override the host's crypto configuration. `RemoteLedger::connect` requires HTTPS, except numeric
loopback HTTP; operator-supplied channels support private CA/mTLS. Clients enforce
30-second call deadlines, bounded messages, exact execution binding and no
application retries. They never discover credentials or select an agent's URL.

The central operator calls `SqliteLedger::issue_access` for one exact execution
(namespace, workload, allocation, lease, generation and node), choosing Admission,
Execution or both. Admission credentials can reserve; Execution credentials can
consume. Credentials contain 256 random bits, expire within one hour, and only
their hashes enter the central database. An embedding scheduler must also cap
validity at any fixed allocation lease deadline and deliver secrets through its authenticated private
provisioning channel, never ordinary App JSON or node reports. Rotation issues
a replacement credential and revokes the old one without resetting grants or
budgets. `revoke_access` withdraws one credential; `revoke` fences the allocation.

Credential validity and scope are checked before proof verification and again in
the reservation transaction. Consumption checks authorization and marks the
grant spent in the same transaction, so revocation cannot race between these
steps. Gateway restarts preserve credentials, revoked state, budgets and consumed
grants. Unknown credentials, wrong scopes, stale authority or transport failures
never authorize dispatch. A lost response after consumption leaves the grant
spent: the shim retains its local Authorizing state and does not create a native
sandbox on retry. This favors reconciliation over duplicate external effects.

Tests run the service over real loopback gRPC and TLS, including concurrent
consumption, all six execution identity fields, credential rotation/expiry,
revocation during proof verification, gateway reopen, and OpenShell dispatch
after an ambiguous reply. These use proof/native-driver doubles for orchestration;
they do not claim a new remote proof or a native sandbox isolation acceptance.
`LedgerService::with_authority` lets Fleet retain its live scheduler state fence
through reservation and consumption on the blocking ledger worker. Fleet checks
the exact reported execution, current deployment, fresh node session, active
namespace and held quota allocation. Suspension, release, stale heartbeats and
replacement therefore reject old credentials even if their TTL has not elapsed.
The service is mounted in Fleet's gateway; Fleet provisions private credentials and activates the exact execution before
native Create. Credentials are delivered only through the private node channel.

`AuthorizedExecutor` binds a grant to the full request and execution identity,
consumes it through the ledger before invoking `ActionHandler`, and rejects
substitution, expiry and replay. Execution failure does not refund the grant.
The handler must be held behind the runtime's native enforcement boundary;
wrapping a Rust function cannot constrain arbitrary shell access in plain Docker.
An authorization proof establishes a policy decision, not an external side effect.

## Remote proof protocol

`ZirenNetwork` uses the upstream StageService protobuf and ZKM stdin framing.
It uploads the approved ELF, preserves caller job IDs and requests Groth16 output.
Credentials and channels are explicit; no SDK initialization or credential-file
discovery occurs. HTTPS uses system roots. Numeric loopback HTTP is supported for
Fleet's loopback-only proof-app endpoint; a deployment can inject a channel with
its own private CA or mTLS configuration. Never accept an agent-selected channel.

Older Fleet deployments require a token-bound EIP-191 signer as well as bearer
authentication. `with_fleet_signer` supplies it explicitly using the same message
encoding and crypto libraries as Fleet. Token-only networks need no signer.
Worker-supplied download URLs and output streams are not used for verification.

With the `ziren` feature, `ZirenGroth16Verifier` accepts the upstream SDK Groth16
JSON variant and uses `zkm-verifier` from the pinned Ziren revision. It verifies
cryptography, expected public bytes and the approved program key, including the
upstream recursion-key allowlist. Other proof formats fail closed. The gateway
must approve the ELF/key mapping; a worker cannot select a verification manifest.

`ProgramRef.program_sha256` hashes the ELF. `verifying_key_sha256` hashes the
decoded 32-byte program key (`vk.bytes32()`), not the global Groth16 circuit key.
trusted-rail's guest checker produces both values through upstream static machine
setup. Guest, checker, verifier and Fleet prover image revisions must agree.

Rail's v2 evaluator profile includes checked collection-index conversions for
matching native/MIPS decisions. Roll out the native evaluator, guest ELF, approved
program key and explicitly approved policy revisions together. Old profiles fail
closed; existing stored policies and receipts are not silently rewritten. Run
`scripts/check_engine_features.py` in every consumer build to audit the exact
evaluator source and Cargo features. A previous remote proof does not validate
the new ELF; repeat network acceptance before enabling it.

## Remote acceptance test

First build trusted-rail's guest and run its native/MIPS differential checker.
Keep build outputs, synthetic witnesses and the generated program manifest outside
project directories. Register that ELF as a dedicated Fleet proof app with the
matching prover image and a shared proof storage root; start its prover through
Fleet. Point a `fleet-proof-app` endpoint at that app's namespace, ELF and storage.
The Fleet control-plane URL is not the app's StageService endpoint.

Supply credentials through the environment from an explicitly selected secret
source, never command-line token values or tracked files:

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

The example submits to the remote network, polls up to 30 minutes, verifies the
receipt, rejects substituted public values and optionally saves the verified
receipt. It never starts a prover or dispatches an action. Synthetic historical
inputs test proof correctness; live admission separately requires current validity.
Remote proving operators can see the witness. Stop the dedicated app through
Fleet after testing and confirm its resources are released.

## Checks and remaining adapters

The current migration baseline is **DockerDriver + the shared OpenShell access
layer**. Default access remains subject to driver restrictions; user-configured
rules require OpenShell enforcement. TEE simulation and fixture-based guest tests
do not qualify a node for hardware-attested production workloads.

Deferred acceptance work:

- [ ] Real TDX: validate a fresh, launch-bound quote and collateral on a measured
  confidential VM, including OpenShell enforcement and runtime creation.
- [ ] Startup proof: publish/approve the DCAP guest and obtain and verify its
  launch-bound receipt through the remote proof network before creating a runtime.
  Execution-only guest tests and existing policy receipts do not satisfy this gate;
  do not start a local prover.
- [ ] AMD SNP: implement full raw-evidence verification in its approved guest and
  complete hardware plus proof-network startup acceptance. An AS result alone
  cannot authorize launch.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
python3 scripts/check_engine_features.py
```

Tests cover protocol framing/authentication, admission failure paths, request
substitution, concurrent grant consumption and rejection by the real crypto
verifier. Test ledgers and proof networks are orchestration doubles, not production
implementations or evidence of successful remote proving. The feature audit must
also run in downstream binaries to prevent widening Regorus's deterministic profile.

`DockerDriver` and the confidential-VM `TeeDriver` implement machine-local
`RuntimeDriver`; the data-plane adapter owns outbound connectors. CoCo evidence
and optional Trustee gRPC adapters are concrete. The TDX guest reuses Automata
DCAP verification; collateral refresh, SNP guests, SGX/Nitro isolation backends
and live hardware/proof-network acceptance remain follow-ups. Fleet embeds the central ledger and implements private
provisioning, native launch preparation and gateway readiness. Application action
hooks still need integration to make preflight enforcement non-bypassable.
Non-TEE attestation remains `SkippedNonTee`;
requiring an attestation proof for that outcome is invalid. No permissive fallback
or local prover is included.
