//! A real GCP founding replays only with the endorsement it was archived
//! with
#![cfg(not(feature = "mock"))]

use attestation::{
    AttestationError,
    AttestationExchangeMessage,
    AttestationVerifier,
    EndorsementSnapshot,
    GcpEndorsementError,
    GcpFirmwareEndorsement,
    QuoteCollateralV3,
    measurements::MeasurementPolicy,
};

/// One founder's harvest on a c3-standard-4 guest, 2026-10-01: the
/// evidence, the DCAP collateral it verified against, the instant, and
/// Google's endorsement of its firmware
#[derive(serde::Deserialize)]
struct Founding {
    at: u64,
    evidence: AttestationExchangeMessage,
    dcap_collateral: QuoteCollateralV3,
    gcp_firmware_endorsement: String,
}

fn founding() -> Founding {
    serde_json::from_str(include_str!("../test-assets/gcp-tdx-founding-1790873673.json")).unwrap()
}

fn endorsement(founding: &Founding) -> GcpFirmwareEndorsement {
    GcpFirmwareEndorsement::new(hex::decode(&founding.gcp_firmware_endorsement).unwrap())
}

/// The binding the evidence carries, read back from the quote
fn report_data(evidence: &AttestationExchangeMessage) -> [u8; 64] {
    let quote = &evidence.attestation_evidence.as_ref().unwrap().quote;
    dcap_qvl::quote::Quote::parse(quote).unwrap().report.as_td10().unwrap().report_data
}

fn verifier() -> AttestationVerifier {
    let policy =
        MeasurementPolicy::from_json_bytes(br#"[{"attestation_type": "gcp-tdx"}]"#.to_vec())
            .unwrap();
    AttestationVerifier::builder(policy).build()
}

#[test]
fn a_gcp_archive_replays_with_its_recorded_endorsement() {
    let founding = founding();
    let endorsements = EndorsementSnapshot::dcap(founding.dcap_collateral.clone(), founding.at)
        .with_gcp_firmware(endorsement(&founding));

    let replayed = verifier()
        .verify_attestation_archived(
            founding.evidence.clone(),
            report_data(&founding.evidence),
            &endorsements,
        )
        .unwrap()
        .expect("the founding carries an attestation");

    assert_eq!(replayed.endorsements, endorsements);
}

#[test]
fn a_gcp_archive_without_an_endorsement_is_refused() {
    let founding = founding();
    let endorsements = EndorsementSnapshot::dcap(founding.dcap_collateral.clone(), founding.at);

    let replayed = verifier().verify_attestation_archived(
        founding.evidence.clone(),
        report_data(&founding.evidence),
        &endorsements,
    );

    assert!(
        matches!(
            replayed,
            Err(AttestationError::GcpFirmwareEndorsement(GcpEndorsementError::NotArchived))
        ),
        "{replayed:?}"
    );
}

#[test]
fn a_gcp_archive_with_a_tampered_endorsement_is_refused() {
    let founding = founding();
    let mut tampered = endorsement(&founding).into_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let endorsements = EndorsementSnapshot::dcap(founding.dcap_collateral.clone(), founding.at)
        .with_gcp_firmware(GcpFirmwareEndorsement::new(tampered));

    let replayed = verifier().verify_attestation_archived(
        founding.evidence.clone(),
        report_data(&founding.evidence),
        &endorsements,
    );

    assert!(
        matches!(
            replayed,
            Err(AttestationError::GcpFirmwareEndorsement(GcpEndorsementError::Signature))
        ),
        "{replayed:?}"
    );
}
