use base64::{engine::general_purpose::STANDARD, Engine};
use dcap_rs::{
    types::{collateral::Collateral, quote::Quote},
    v2::encode_guest_input_v2,
};
use serde_json::{json, Value};
use trusted_shim_attestation::*;

fn fixture(name: &str) -> Value {
    serde_json::from_str(match name {
        "tdx4" => include_str!("fixtures/ata-tdx-v4.json"),
        "tdx5" => include_str!("fixtures/v5.json"),
        _ => include_str!("fixtures/alibaba-v5.json"),
    })
    .unwrap()
}
fn bytes(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap().trim_start_matches("0x")).unwrap()
}

#[test]
fn automata_signed_vectors_and_journals_match_without_as() {
    for name in ["tdx4", "tdx5"] {
        let f = fixture(name);
        let out = dcap_rs::v2::verify_guest_input_v2(&bytes(&f, "guestInput")).unwrap();
        assert_eq!(out, bytes(&f, "expectedJournal"));
        let q = bytes(&f, "quote");
        let quote = Quote::read(&mut q.as_slice()).unwrap();
        let mut report = *quote.body.as_tdx_report_body().unwrap();
        let original = measurement(&report);
        report.rtm_r3[0] ^= 1;
        assert_ne!(
            original,
            measurement(&report),
            "profile must cover runtime measurements"
        );
    }
    assert!(
        dcap_rs::v2::verify_guest_input_v2(&bytes(&fixture("migration"), "guestInput")).is_err()
    );
}

#[test]
fn guest_rejects_unsigned_stale_and_substituted_evidence() {
    let f = fixture("tdx4");
    let quote_bytes = bytes(&f, "quote");
    let quote = Quote::read(&mut quote_bytes.as_slice()).unwrap();
    let report = quote.body.as_tdx_report_body().unwrap();
    // Decode the frozen upstream ABI to retain the original signed JSON bytes.
    use alloy_sol_types::{sol, SolType};
    type Input = sol!((bytes, bytes, uint64));
    let (collateral, _, time) = Input::abi_decode_params(&bytes(&f, "guestInput")).unwrap();
    let binding: Binding = serde_json::from_value(json!({
        "domain":DCAP_DOMAIN,"mode":"hardware","platform":"tdx",
        "expected_measurement":measurement(report),
        "init_data_sha256":hex::encode(&report.mr_config_id[..32]),
        "endpoint_key_sha256":"22".repeat(32),"request_sha256":"33".repeat(32),
        "nonce":"44".repeat(32),"expires_at":time+300,
        "execution":{"namespace":"test","workload":"dcap","allocation_id":"a","lease_id":"l","generation":1,"node_id":"test-node"}
    })).unwrap();
    let witness = DcapWitness {
        binding,
        evidence: serde_json::to_vec(&json!({"quote":STANDARD.encode(&quote_bytes)})).unwrap(),
        collateral: collateral.to_vec(),
        verification_time: time,
        min_tcb_evaluation_data_number: 20,
    };
    // Real valid historical quote, but no fresh shim launch binding. It MUST fail.
    assert!(evaluate_dcap(&canonical(&witness).unwrap())
        .unwrap_err()
        .to_string()
        .contains("launch binding"));
    let base = serde_json::to_value(&witness).unwrap();
    let mut obsolete = base.clone();
    obsolete["min_tcb_evaluation_data_number"] = json!(21);
    assert!(evaluate_dcap(&canonical(&obsolete).unwrap())
        .unwrap_err()
        .to_string()
        .contains("obsolete TCB"));
    for (key, value) in [
        ("mode", json!("simulation")),
        ("platform", json!("snp")),
        ("expected_measurement", json!("00".repeat(32))),
        ("init_data_sha256", json!("11".repeat(32))),
        ("expires_at", json!(time)),
    ] {
        let mut changed = base.clone();
        changed["binding"][key] = value;
        assert!(
            evaluate_dcap(&canonical(&changed).unwrap()).is_err(),
            "{key}"
        );
    }
    let collateral = Collateral::sol_abi_decode(&collateral).unwrap();
    for index in [0, 48, 636] {
        let mut bad = quote_bytes.clone();
        bad[index] ^= 1;
        let input = encode_guest_input_v2(&collateral, &bad, time).unwrap();
        assert!(
            dcap_rs::v2::verify_guest_input_v2(&input).is_err(),
            "quote byte {index}"
        );
    }
    for time in [1, u64::MAX, time + 366 * 86400] {
        let input = encode_guest_input_v2(&collateral, &quote_bytes, time).unwrap();
        assert!(dcap_rs::v2::verify_guest_input_v2(&input).is_err());
    }
    type CollateralInput = sol!((bytes, bytes, bytes[2], string, string));
    let encoded = collateral.sol_abi_encode().unwrap();
    let original = CollateralInput::abi_decode_params(&encoded).unwrap();
    for field in 0..4 {
        let mut changed = original.clone();
        let der = match field {
            0 => &mut changed.0,
            1 => &mut changed.1,
            2 => &mut changed.2[0],
            _ => &mut changed.2[1],
        };
        let mut bytes = der.to_vec();
        *bytes.last_mut().unwrap() ^= 1; // signature bytes; preserve DER framing
        *der = bytes.into();
        let bad = CollateralInput::abi_encode_params(&changed);
        let bad = Collateral::sol_abi_decode(&bad).unwrap();
        let input = encode_guest_input_v2(&bad, &quote_bytes, time).unwrap();
        assert!(
            verify_quote_vector(&input).is_err(),
            "signed collateral field {field}"
        );
    }
    for field in [3, 4] {
        let mut changed = original.clone();
        let json = if field == 3 {
            &mut changed.3
        } else {
            &mut changed.4
        };
        // Changing an authenticated counter must invalidate the signed JSON.
        *json = json.replace(
            "\"tcbEvaluationDataNumber\":20",
            "\"tcbEvaluationDataNumber\":21",
        );
        assert_ne!(CollateralInput::abi_encode_params(&changed), encoded);
        let bad =
            Collateral::sol_abi_decode(&CollateralInput::abi_encode_params(&changed)).unwrap();
        assert!(
            verify_quote_vector(&encode_guest_input_v2(&bad, &quote_bytes, time).unwrap()).is_err()
        );
    }
    let mut changed = serde_json::to_value(&collateral).unwrap();
    // CRLs/signatures must not be replaceable with arbitrary data.
    changed["root_ca_crl"] = json!("00");
    assert!(serde_json::from_value::<Collateral>(changed).is_err());
}

#[test]
fn input_commitment_covers_acceptance_policy_and_launch() {
    let f = fixture("tdx4");
    let mut value = json!({"binding":{
        "domain":DCAP_DOMAIN,"mode":"hardware","platform":"tdx","expected_measurement":"00".repeat(32),
        "init_data_sha256":"11".repeat(32),"endpoint_key_sha256":"22".repeat(32),"request_sha256":"33".repeat(32),
        "nonce":"44".repeat(32),"expires_at":f["verificationTimestamp"].as_u64().unwrap()+300,
        "execution":{"namespace":"test","workload":"dcap","allocation_id":"a","lease_id":"l","generation":1,"node_id":"test-node"}},
        "evidence":[1,2],"collateral":[3,4],"verification_time":f["verificationTimestamp"],"min_tcb_evaluation_data_number":20});
    let original: DcapWitness = serde_json::from_value(value.clone()).unwrap();
    let expected = original.expected_public_values().unwrap();
    for pointer in [
        "/binding/nonce",
        "/binding/request_sha256",
        "/binding/endpoint_key_sha256",
        "/binding/execution/namespace",
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("changed");
        assert_ne!(
            expected,
            serde_json::from_value::<DcapWitness>(changed)
                .unwrap()
                .expected_public_values()
                .unwrap()
        );
    }
    value["min_tcb_evaluation_data_number"] = json!(19);
    assert_ne!(
        expected,
        serde_json::from_value::<DcapWitness>(value)
            .unwrap()
            .expected_public_values()
            .unwrap()
    );
    assert!(evaluate_dcap(&vec![0; MAX_WITNESS_BYTES + 1]).is_err());
}
