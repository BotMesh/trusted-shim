//! Export immutable public fixtures for execution-only guest tests. Never prove.
use base64::{engine::general_purpose::STANDARD, Engine};
use dcap_rs::types::quote::Quote;
use serde_json::{json, Value};
use trusted_shim_attestation::*;

fn main() -> anyhow::Result<()> {
    use alloy_sol_types::{sol, SolType};
    type Input = sol!((bytes, bytes, uint64));
    let out = std::env::args_os()
        .nth(1)
        .expect("usage: export-vectors OUTPUT_DIRECTORY");
    let out = std::path::PathBuf::from(out);
    std::fs::create_dir_all(&out)?;
    for (name, source, valid) in [
        (
            "tdx4",
            include_str!("../tests/fixtures/ata-tdx-v4.json"),
            true,
        ),
        ("tdx5", include_str!("../tests/fixtures/v5.json"), true),
        (
            "migration",
            include_str!("../tests/fixtures/alibaba-v5.json"),
            false,
        ),
    ] {
        let f: Value = serde_json::from_str(source)?;
        let decode = |key: &str| hex::decode(f[key].as_str().unwrap().trim_start_matches("0x"));
        let input = decode("guestInput")?;
        let result = verify_quote_vector(&input);
        if valid {
            let expected = decode("expectedJournal")?;
            assert_eq!(result?, expected);
            std::fs::write(out.join(format!("{name}.output")), expected)?;
        } else {
            assert!(result.is_err());
        }
        std::fs::write(out.join(format!("{name}.input")), &input)?;
        if name == "tdx4" {
            let (collateral, raw_quote, time) = Input::abi_decode_params(&input)?;
            let quote = Quote::read(&mut raw_quote.as_ref())?;
            let report = quote.body.as_tdx_report_body().unwrap();
            let witness: DcapWitness = serde_json::from_value(json!({
                "binding":{
                    "domain":DCAP_DOMAIN,"mode":"hardware","platform":"tdx",
                    "expected_measurement":measurement(report),"init_data_sha256":hex::encode(&report.mr_config_id[..32]),
                    "endpoint_key_sha256":"22".repeat(32),"request_sha256":"33".repeat(32),"nonce":"44".repeat(32),"expires_at":time+300,
                    "execution":{"namespace":"test","workload":"dcap","allocation_id":"a","lease_id":"l","generation":1,"node_id":"test-node"}},
                "evidence":serde_json::to_vec(&json!({"quote":STANDARD.encode(&raw_quote)}))?,
                "collateral":collateral.to_vec(),"verification_time":time,"min_tcb_evaluation_data_number":20
            }))?;
            let launch = canonical(&witness)?;
            assert!(evaluate_dcap(&launch)
                .unwrap_err()
                .to_string()
                .contains("launch binding"));
            std::fs::write(out.join("unbound-launch.input"), launch)?;
            let mut bad = raw_quote.to_vec();
            bad[48] ^= 1;
            let input = Input::abi_encode_params(&(collateral, bad, time));
            assert!(verify_quote_vector(&input).is_err());
            std::fs::write(out.join("bad-signature.input"), input)?;
        }
    }
    Ok(())
}
