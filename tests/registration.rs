use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, Bytes, Signature, B256, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use trusted_shim::{
    contracts::Validity,
    registration::{
        OwnerSignature, PreparedRegistration, RegistrationDomain, RegistrationIntent,
        RegistrationTrust,
    },
};

fn key() -> SigningKey {
    // Public test key; never used on a network.
    SigningKey::from_slice(&[7; 32]).unwrap()
}

fn fixture() -> (RegistrationDomain, RegistrationIntent) {
    (
        RegistrationDomain {
            chain_id: 48816,
            authorizer: Address::repeat_byte(1),
            identity_registry: Address::repeat_byte(2),
        },
        RegistrationIntent {
            owner: Address::from_public_key(key().verifying_key()),
            agent_id: "claw-123".into(),
            agent_key: Address::repeat_byte(3),
            execution_sha256: B256::repeat_byte(4),
            runtime_config_sha256: B256::repeat_byte(5),
            policy_sha256: B256::repeat_byte(6),
            agent_uri: "ipfs://test-manifest".into(),
            manifest_sha256: B256::repeat_byte(7),
            trust: RegistrationTrust::TeeRequired {
                profile_sha256: B256::repeat_byte(8),
            },
            nonce: B256::repeat_byte(9),
            validity: Validity {
                not_before: 1000,
                expires_at: 1600,
            },
        },
    )
}

fn sign(digest: B256) -> OwnerSignature {
    let (signature, recovery) = key().sign_prehash_recoverable(digest.as_slice()).unwrap();
    OwnerSignature {
        intent_digest: digest,
        signature: Signature::from_signature_and_parity(signature, recovery.is_y_odd())
            .as_bytes()
            .into(),
    }
}

#[test]
fn wallet_json_hash_matches_typed_verifier_and_recovers_owner() {
    let (mut domain, mut intent) = fixture();
    // Exercise decimal-string encoding beyond JavaScript's safe integer range.
    domain.chain_id = u64::MAX;
    intent.validity = Validity {
        not_before: u64::MAX - 600,
        expires_at: u64::MAX,
    };
    for trust in [intent.trust.clone(), RegistrationTrust::Unattested {}] {
        intent.trust = trust;
        let prepared = PreparedRegistration::new(domain.clone(), intent.clone()).unwrap();
        let wallet = serde_json::to_value(prepared.signing_request()).unwrap();
        let dynamic: TypedData = serde_json::from_value(wallet.clone()).unwrap();
        let digest = dynamic.eip712_signing_hash().unwrap();
        assert_eq!(digest, prepared.digest());
        assert_eq!(wallet["domain"]["chainId"], u64::MAX.to_string());
        assert_eq!(wallet["message"]["deadline"], u64::MAX.to_string());
        let signed = sign(digest);
        let result = prepared
            .verify_owner_signature(&signed, intent.owner, u64::MAX - 1)
            .unwrap();
        assert_eq!(result.owner(), intent.owner);
        assert_eq!(result.intent_digest(), digest);
        assert_eq!(result.nonce(), intent.nonce);
        assert_eq!(result.deadline(), u64::MAX);
        // It is deliberately a pure verifier; nonce consumption is a future
        // adapter transaction, not an in-memory claim of replay protection.
        assert!(prepared
            .verify_owner_signature(&signed, intent.owner, u64::MAX - 1)
            .is_ok());
    }
}

#[test]
fn signature_cannot_be_reused_after_any_bound_field_changes() {
    let (domain, intent) = fixture();
    let prepared = PreparedRegistration::new(domain.clone(), intent.clone()).unwrap();
    let original = sign(prepared.digest());
    let changes = [
        ("owner", json!(Address::repeat_byte(10))),
        ("agent_id", json!("another-agent")),
        ("agent_key", json!(Address::repeat_byte(11))),
        ("execution_sha256", json!(B256::repeat_byte(12))),
        ("runtime_config_sha256", json!(B256::repeat_byte(13))),
        ("policy_sha256", json!(B256::repeat_byte(14))),
        ("agent_uri", json!("ipfs://other-manifest")),
        ("manifest_sha256", json!(B256::repeat_byte(15))),
        ("trust", json!({"mode": "unattested"})),
        (
            "trust",
            json!({"mode": "tee_required", "profile_sha256": B256::repeat_byte(16)}),
        ),
        ("nonce", json!(B256::repeat_byte(17))),
        ("validity", json!({"not_before": 999, "expires_at": 1600})),
        ("validity", json!({"not_before": 1000, "expires_at": 1601})),
    ];
    for (field, value) in changes {
        let mut altered = serde_json::to_value(&intent).unwrap();
        altered[field] = value;
        let altered: RegistrationIntent = serde_json::from_value(altered).unwrap();
        let owner = altered.owner;
        let other = PreparedRegistration::new(domain.clone(), altered).unwrap();
        assert_ne!(prepared.digest(), other.digest(), "{field}");
        // Updating the claimed digest as well must not bypass recovery.
        let forged = OwnerSignature {
            intent_digest: other.digest(),
            signature: original.signature.clone(),
        };
        assert!(
            other.verify_owner_signature(&forged, owner, 1200).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("chain_id", json!(2345)),
        ("authorizer", json!(Address::repeat_byte(18))),
        ("identity_registry", json!(Address::repeat_byte(19))),
    ] {
        let mut altered = serde_json::to_value(&domain).unwrap();
        altered[field] = value;
        let other =
            PreparedRegistration::new(serde_json::from_value(altered).unwrap(), intent.clone())
                .unwrap();
        let forged = OwnerSignature {
            intent_digest: other.digest(),
            signature: original.signature.clone(),
        };
        assert!(
            other
                .verify_owner_signature(&forged, intent.owner, 1200)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn requires_current_authenticated_owner_and_validity() {
    let (domain, intent) = fixture();
    let prepared = PreparedRegistration::new(domain, intent.clone()).unwrap();
    let signed = sign(prepared.digest());
    for now in [0, 999, 1600, u64::MAX] {
        assert!(prepared
            .verify_owner_signature(&signed, intent.owner, now)
            .is_err());
    }
    for now in [1000, 1599] {
        assert!(prepared
            .verify_owner_signature(&signed, intent.owner, now)
            .is_ok());
    }
    assert!(prepared
        .verify_owner_signature(&signed, Address::repeat_byte(33), 1200)
        .is_err());
    let mut wrong_digest = sign(prepared.digest());
    wrong_digest.intent_digest = B256::ZERO;
    assert!(prepared
        .verify_owner_signature(&wrong_digest, intent.owner, 1200)
        .is_err());
}

#[test]
fn rejects_malleable_malformed_and_non_ethereum_signatures() {
    let (domain, intent) = fixture();
    let prepared = PreparedRegistration::new(domain, intent.clone()).unwrap();
    let signed = sign(prepared.digest());
    let sig = Signature::from_raw(&signed.signature).unwrap();
    let order = U256::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();
    let high_s = Signature::new(sig.r(), order - sig.s(), !sig.v());
    let mut cases: Vec<Bytes> = vec![
        Bytes::new(),
        vec![0; 64].into(),
        vec![0; 66].into(),
        high_s.as_bytes().into(),
    ];
    for v in [0, 1, 26, 29, 35, 255] {
        let mut bytes = signed.signature.to_vec();
        bytes[64] = v;
        cases.push(bytes.into());
    }
    let mut zero = vec![0; 65];
    zero[64] = 27;
    cases.push(zero.into());
    for range in [0..32, 32..64, 0..64] {
        let mut out_of_range = signed.signature.to_vec();
        out_of_range[range].fill(255);
        cases.push(out_of_range.into());
    }
    for signature in cases {
        let malformed = OwnerSignature {
            intent_digest: prepared.digest(),
            signature,
        };
        assert!(prepared
            .verify_owner_signature(&malformed, intent.owner, 1200)
            .is_err());
    }
}

#[test]
fn invalid_or_ambiguous_intents_never_reach_wallet_preparation() {
    let (domain, intent) = fixture();
    for (field, value) in [
        ("owner", json!(Address::ZERO)),
        ("agent_key", json!(Address::ZERO)),
        ("agent_id", json!("")),
        ("agent_id", json!("x".repeat(257))),
        ("agent_id", json!("claw\nother")),
        ("agent_uri", json!("")),
        ("agent_uri", json!("x".repeat(4097))),
        ("execution_sha256", json!(B256::ZERO)),
        ("runtime_config_sha256", json!(B256::ZERO)),
        ("policy_sha256", json!(B256::ZERO)),
        ("manifest_sha256", json!(B256::ZERO)),
        ("nonce", json!(B256::ZERO)),
        (
            "trust",
            json!({"mode": "tee_required", "profile_sha256": B256::ZERO}),
        ),
        ("validity", json!({"not_before": 1600, "expires_at": 1600})),
        ("validity", json!({"not_before": 1600, "expires_at": 1000})),
        ("validity", json!({"not_before": 0, "expires_at": 86401})),
    ] {
        let mut altered = serde_json::to_value(&intent).unwrap();
        altered[field] = value;
        assert!(
            PreparedRegistration::new(domain.clone(), serde_json::from_value(altered).unwrap())
                .is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("chain_id", json!(0)),
        ("authorizer", json!(Address::ZERO)),
        ("identity_registry", json!(Address::ZERO)),
        ("authorizer", json!(domain.identity_registry)),
    ] {
        let mut altered = serde_json::to_value(&domain).unwrap();
        altered[field] = value;
        assert!(
            PreparedRegistration::new(serde_json::from_value(altered).unwrap(), intent.clone())
                .is_err(),
            "{field}"
        );
    }
    let mut unknown = serde_json::to_value(&intent).unwrap();
    unknown["registered"] = Value::Bool(true);
    assert!(serde_json::from_value::<RegistrationIntent>(unknown).is_err());
    let mut unknown = serde_json::to_value(&intent).unwrap();
    unknown["trust"] = json!({"mode": "unattested", "verified": true});
    assert!(serde_json::from_value::<RegistrationIntent>(unknown).is_err());
}
