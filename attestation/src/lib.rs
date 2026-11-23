//! No service, clock, network or prover. The guest verifies original evidence
//! with pinned Automata DCAP code, then enforces the committed launch profile.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use dcap_rs::{
    types::{collateral::Collateral, quote::Quote, report::Td10ReportBody},
    v2::verify_dcap_quote_v2,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
pub use trusted_attestation_types::*;

/// The complete profile, rather than MRTD alone, identifies the measured boot
/// environment. MRCONFIGID is checked separately against measured init-data.
pub fn measurement(report: &Td10ReportBody) -> String {
    let mut hash = Sha256::new();
    hash.update(b"trusted-shim.tdx-measurement.v1\0");
    for field in [
        report.mr_seam.as_slice(),
        report.mr_signer_seam.as_slice(),
        report.seam_attributes.as_slice(),
        report.td_attributes.as_slice(),
        report.xfam.as_slice(),
        report.mr_td.as_slice(),
        report.mr_owner.as_slice(),
        report.mr_owner_config.as_slice(),
        report.rtm_r0.as_slice(),
        report.rtm_r1.as_slice(),
        report.rtm_r2.as_slice(),
        report.rtm_r3.as_slice(),
    ] {
        hash.update(field);
    }
    hex::encode(hash.finalize())
}

fn hash32(text: &str) -> Result<[u8; 32]> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA256"
    );
    hex::decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid SHA256"))
}

/// CoCo AA's TDX evidence contains the base64 quote and optional event logs.
/// Event logs are not trusted here: the approved profile pins all four RTMRs.
pub fn quote_from_evidence(evidence: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !evidence.is_empty() && evidence.len() <= 128 * 1024,
        "evidence size"
    );
    let value: serde_json::Value = serde_json::from_slice(evidence)?;
    let quote = STANDARD.decode(value["quote"].as_str().context("missing TDX quote")?)?;
    ensure!(!quote.is_empty() && quote.len() <= 64 * 1024, "quote size");
    Ok(quote)
}

/// Authenticate original evidence and the complete launch profile inside the guest.
/// The output is a commitment to all inputs; no successful output is produced for
/// invalid evidence. Hardware trust is rooted in Automata's pinned Intel key.
pub fn evaluate_dcap(input: &[u8]) -> Result<Vec<u8>> {
    ensure!(input.len() <= MAX_WITNESS_BYTES, "witness size");
    let witness: DcapWitness = serde_json::from_slice(input)?;
    ensure!(
        witness.collateral.len() <= MAX_WITNESS_BYTES / 2,
        "collateral size"
    );
    let binding = &witness.binding;
    ensure!(
        binding.domain == DCAP_DOMAIN
            && binding.mode == Mode::Hardware
            && binding.platform == "tdx",
        "wrong attestation domain"
    );
    ensure!(
        witness.min_tcb_evaluation_data_number > 0,
        "missing TCB floor"
    );
    ensure!(
        witness.verification_time < binding.expires_at
            && binding.expires_at - witness.verification_time <= 300,
        "invalid verification window"
    );
    hash32(&binding.request_sha256)?;
    hash32(&binding.endpoint_key_sha256)?;
    hash32(&binding.nonce)?;
    let init_data = hash32(&binding.init_data_sha256)?;
    hash32(&binding.expected_measurement)?;
    let raw_quote = quote_from_evidence(&witness.evidence)?;
    let collateral = Collateral::sol_abi_decode(&witness.collateral)?;
    let at = UNIX_EPOCH
        .checked_add(Duration::from_secs(witness.verification_time))
        .context("timestamp overflow")?;
    // Production entrypoint: checks Intel's pinned root, chain/CRL/signatures,
    // QE/TCB/module status, quote framing, debug and migration attributes.
    let verified = verify_dcap_quote_v2(at, &collateral, &raw_quote)?;
    ensure!(
        verified.tcb_status == 0 && verified.advisory_ids.is_empty(),
        "TCB is not up to date"
    );
    let quote = Quote::read(&mut raw_quote.as_slice())?;
    let report = quote.body.as_tdx_report_body().context("not TDX")?;
    ensure!(
        measurement(report) == binding.expected_measurement,
        "measurement mismatch"
    );
    ensure!(
        report.mr_config_id[..32] == init_data && report.mr_config_id[32..] == [0; 16],
        "init-data mismatch"
    );

    // The proof's time is not a trusted wall clock. Require all authenticated
    // material to remain valid through the launch deadline, which the consumer
    // checks against its own clock. A prover cannot renew an expired challenge.
    let tcb = collateral.tcb_info.get_tcb_info()?;
    let qe = collateral.qe_identity.get_enclave_identity()?;
    let min_tcb = tcb
        .tcb_evaluation_data_number
        .min(qe.tcb_evaluation_data_number);
    ensure!(
        min_tcb >= witness.min_tcb_evaluation_data_number,
        "obsolete TCB collateral"
    );
    let mut valid_until =
        u64::try_from(tcb.next_update.timestamp())?.min(u64::try_from(qe.next_update.timestamp())?);
    let seconds = |t: SystemTime| -> Result<u64> { Ok(t.duration_since(UNIX_EPOCH)?.as_secs()) };
    for crl in [&collateral.root_ca_crl, &collateral.pck_crl] {
        valid_until = valid_until.min(seconds(
            crl.tbs_cert_list
                .next_update
                .context("missing CRL expiry")?
                .to_system_time(),
        )?);
    }
    let pck = quote.signature.get_pck_cert_chain()?;
    for cert in collateral
        .tcb_info_and_qe_identity_issuer_chain
        .iter()
        .chain(pck.pck_cert_chain.iter())
    {
        valid_until = valid_until.min(seconds(
            cert.tbs_certificate.validity.not_after.to_system_time(),
        )?);
    }
    ensure!(
        binding.expires_at < valid_until,
        "collateral expires before launch deadline"
    );
    let report_data = Sha256::digest(canonical(binding)?);
    ensure!(
        report.user_report_data[..32] == report_data[..]
            && report.user_report_data[32..] == [0; 32],
        "launch binding mismatch"
    );
    witness.expected_public_values()
}

/// Compatibility harness for upstream's historical signed quote vectors.
/// This has no shim launch semantics and must not be approved as a launch guest.
pub fn verify_quote_vector(input: &[u8]) -> Result<Vec<u8>> {
    ensure!(input.len() <= MAX_WITNESS_BYTES, "witness size");
    dcap_rs::v2::verify_guest_input_v2(input)
}
