//! User consent for a future GOAT registration adapter. No transaction sender,
//! registry deployment, nonce consumption or runtime-readiness transition lives
//! here. A verified signature is not registration, attestation or authorization
//! to execute an agent action.
use crate::{contracts::Validity, Error, Result};
use alloy_primitives::{Address, Bytes, Signature, B256};
use alloy_sol_types::{eip712_domain, sol, Eip712Domain, SolStruct};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

sol! {
    struct RegisterAgent {
        address owner;
        address identityRegistry;
        string agentId;
        address agentKey;
        bytes32 executionHash;
        bytes32 runtimeConfigHash;
        bytes32 policyHash;
        string agentURI;
        bytes32 manifestHash;
        uint8 trustMode;
        bytes32 attestationProfileHash;
        bytes32 nonce;
        uint64 notBefore;
        uint64 deadline;
    }
}

/// Selected by the control plane, never taken from the submitted signature.
/// `authorizer` is the future registration authorization adapter, not a claim
/// that stock ERC-8004 register(string) accepts an EIP-712 owner signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationDomain {
    pub chain_id: u64,
    pub authorizer: Address,
    pub identity_registry: Address,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistrationTrust {
    Unattested {},
    TeeRequired { profile_sha256: B256 },
}

/// Freeze these values before presenting the wallet signing screen. A change
/// of key, execution, configuration, policy or trust mode needs new consent.
/// `agent_id` is ClawUp's opaque logical ID, not an ERC-8004 token ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationIntent {
    pub owner: Address,
    pub agent_id: String,
    pub agent_key: Address,
    pub execution_sha256: B256,
    pub runtime_config_sha256: B256,
    pub policy_sha256: B256,
    pub agent_uri: String,
    pub manifest_sha256: B256,
    pub trust: RegistrationTrust,
    pub nonce: B256,
    pub validity: Validity,
}

/// Wallet-compatible eth_signTypedData_v4 input. Integer values are decimal
/// strings so JavaScript clients cannot silently round uint64/uint256 fields.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationSigningRequest {
    pub domain: Value,
    pub types: Value,
    pub primary_type: String,
    pub message: Value,
}

/// Signature bytes are sensitive authorization material: no Debug impl.
/// Store/deliver only over the authenticated private control path.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerSignature {
    pub intent_digest: B256,
    pub signature: Bytes,
}

/// An in-process verification result, deliberately not deserializable. The
/// future adapter must still atomically claim the nonce, validate current owner
/// and policy, verify required RA evidence, and reconcile the chain transaction.
pub struct VerifiedOwnerSignature {
    owner: Address,
    intent_digest: B256,
    nonce: B256,
    deadline: u64,
}
impl VerifiedOwnerSignature {
    pub fn owner(&self) -> Address {
        self.owner
    }
    pub fn intent_digest(&self) -> B256 {
        self.intent_digest
    }
    pub fn nonce(&self) -> B256 {
        self.nonce
    }
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
}

pub struct PreparedRegistration {
    domain: RegistrationDomain,
    intent: RegistrationIntent,
}

impl PreparedRegistration {
    /// Pure preparation: no keys, chain RPC, runtime launch or proving.
    pub fn new(domain: RegistrationDomain, intent: RegistrationIntent) -> Result<Self> {
        let text =
            |s: &str, max| !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control);
        if domain.chain_id == 0
            || domain.authorizer.is_zero()
            || domain.identity_registry.is_zero()
            || domain.authorizer == domain.identity_registry
            || intent.owner.is_zero()
            || intent.agent_key.is_zero()
            || !text(&intent.agent_id, 256)
            || !text(&intent.agent_uri, 4096)
            || [
                intent.execution_sha256,
                intent.runtime_config_sha256,
                intent.policy_sha256,
                intent.manifest_sha256,
                intent.nonce,
            ]
            .iter()
            .any(B256::is_zero)
            || intent.validity.not_before >= intent.validity.expires_at
            || intent.validity.expires_at - intent.validity.not_before > 86400
            || matches!(intent.trust, RegistrationTrust::TeeRequired { profile_sha256 } if profile_sha256.is_zero())
        {
            return Err(Error::InvalidContract);
        }
        Ok(Self { domain, intent })
    }

    fn eip712_domain(&self) -> Eip712Domain {
        eip712_domain! {
            name: "TrustedShimAgentRegistration",
            version: "1",
            chain_id: self.domain.chain_id,
            verifying_contract: self.domain.authorizer,
        }
    }

    fn message(&self) -> RegisterAgent {
        let i = &self.intent;
        let (trust, profile) = match i.trust {
            RegistrationTrust::Unattested {} => (0, B256::ZERO),
            RegistrationTrust::TeeRequired { profile_sha256 } => (1, profile_sha256),
        };
        RegisterAgent {
            owner: i.owner,
            identityRegistry: self.domain.identity_registry,
            agentId: i.agent_id.clone(),
            agentKey: i.agent_key,
            executionHash: i.execution_sha256,
            runtimeConfigHash: i.runtime_config_sha256,
            policyHash: i.policy_sha256,
            agentURI: i.agent_uri.clone(),
            manifestHash: i.manifest_sha256,
            trustMode: trust,
            attestationProfileHash: profile,
            nonce: i.nonce,
            notBefore: i.validity.not_before,
            deadline: i.validity.expires_at,
        }
    }

    pub fn digest(&self) -> B256 {
        self.message().eip712_signing_hash(&self.eip712_domain())
    }

    pub fn signing_request(&self) -> RegistrationSigningRequest {
        let m = self.message();
        RegistrationSigningRequest {
            domain: json!({"name":"TrustedShimAgentRegistration","version":"1",
                "chainId":self.domain.chain_id.to_string(),"verifyingContract":self.domain.authorizer}),
            primary_type: "RegisterAgent".into(),
            types: json!({
                "EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},
                    {"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
                "RegisterAgent":[{"name":"owner","type":"address"},{"name":"identityRegistry","type":"address"},
                    {"name":"agentId","type":"string"},{"name":"agentKey","type":"address"},
                    {"name":"executionHash","type":"bytes32"},{"name":"runtimeConfigHash","type":"bytes32"},
                    {"name":"policyHash","type":"bytes32"},{"name":"agentURI","type":"string"},
                    {"name":"manifestHash","type":"bytes32"},{"name":"trustMode","type":"uint8"},
                    {"name":"attestationProfileHash","type":"bytes32"},{"name":"nonce","type":"bytes32"},
                    {"name":"notBefore","type":"uint64"},{"name":"deadline","type":"uint64"}]
            }),
            message: json!({"owner":m.owner,"identityRegistry":m.identityRegistry,"agentId":m.agentId,
                "agentKey":m.agentKey,"executionHash":m.executionHash,"runtimeConfigHash":m.runtimeConfigHash,
                "policyHash":m.policyHash,"agentURI":m.agentURI,"manifestHash":m.manifestHash,
                "trustMode":m.trustMode.to_string(),"attestationProfileHash":m.attestationProfileHash,
                "nonce":m.nonce,"notBefore":m.notBefore.to_string(),"deadline":m.deadline.to_string()}),
        }
    }

    /// EOA signatures only. The caller supplies the currently authenticated
    /// product owner's wallet independently of the signed input. ERC-1271
    /// contract-wallet validation remains TODO; never treat it as an EOA success.
    /// This method does not consume a nonce or return an execution grant.
    pub fn verify_owner_signature(
        &self,
        signed: &OwnerSignature,
        authenticated_owner: Address,
        now: u64,
    ) -> Result<VerifiedOwnerSignature> {
        let digest = self.digest();
        if authenticated_owner != self.intent.owner
            || now < self.intent.validity.not_before
            || now >= self.intent.validity.expires_at
            || signed.intent_digest != digest
            || signed.signature.len() != 65
            || !matches!(signed.signature[64], 27 | 28)
        {
            return Err(Error::Untrusted);
        }
        let signature = Signature::from_raw(&signed.signature).map_err(|_| Error::Untrusted)?;
        // Validate scalar ranges before normalization: malformed r/s values
        // must never reach arithmetic intended for a valid secp256k1 signature.
        if signature.to_k256().is_err()
            || signature.normalize_s().is_some()
            || signature
                .recover_address_from_prehash(&digest)
                .map_err(|_| Error::Untrusted)?
                != authenticated_owner
        {
            return Err(Error::Untrusted);
        }
        Ok(VerifiedOwnerSignature {
            owner: authenticated_owner,
            intent_digest: digest,
            nonce: self.intent.nonce,
            deadline: self.intent.validity.expires_at,
        })
    }
}
