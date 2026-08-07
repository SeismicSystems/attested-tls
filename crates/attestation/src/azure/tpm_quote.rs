//! Portable verification of Azure vTPM quotes.
//!
//! A vTPM quote is a signed, marshalled `TPMS_ATTEST` structure together
//! with the PCR values it attests to. Verifying one is pure computation:
//! an RSA signature check over the message, a nonce comparison against
//! the `extraData` field, and a SHA-256 digest comparison against the
//! attested `pcrDigest`. This module owns that verification so it needs
//! no TPM stack; only evidence generation (reading the vTPM on an Azure
//! CVM) goes through `az_tdx_vtpm`.
//!
//! The verification logic is adapted from az-cvm-vtpm's `vtpm::verify`
//! (<https://github.com/kinvolk/azure-cvm-tooling>, Copyright (c)
//! Microsoft Corporation, MIT license), with the `TPMS_ATTEST` field
//! extraction done by the `tpms_attest` parser instead of tss-esapi. It is
//! vendored because az-cvm-vtpm's verifier feature currently requires its
//! TPM device support (tss-esapi links the native tpm2-tss libraries,
//! making such builds Linux-only). If upstream decouples verification
//! from the TPM stack, this module can be retired in favour of depending
//! on az-cvm-vtpm's verifier again.

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sha::Sha256,
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::tpms_attest::{AttestError, TpmsAttest};

/// An error when verifying a vTPM quote
#[derive(Error, Debug)]
pub enum TpmQuoteError {
    #[error("TPMS_ATTEST parse: {0}")]
    Attest(#[from] AttestError),
    #[error("OpenSSL: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("quote is not signed by key")]
    SignatureMismatch,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("PCR digest does not match PCR values")]
    PcrMismatch,
}

/// A vTPM quote: AK signature, marshalled `TPMS_ATTEST` message, and the
/// attested sha256 PCR values.
///
/// The field names and types match `az_tdx_vtpm::vtpm::Quote`, keeping
/// the serde_json wire format of attestation evidence identical.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct TpmQuote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
}

impl TpmQuote {
    /// Retrieve sha256 PCR values from the quote
    pub(super) fn pcrs_sha256(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.pcrs.iter()
    }

    /// Verify the quote's signature, nonce, and PCR digest
    pub(super) fn verify(&self, pub_key: &PKey<Public>, nonce: &[u8]) -> Result<(), TpmQuoteError> {
        self.verify_signature(pub_key)?;

        let attest = TpmsAttest::parse(&self.message)?;
        if attest.extra_data() != nonce {
            return Err(TpmQuoteError::NonceMismatch);
        }

        self.verify_pcrs(&attest)
    }

    /// Verify the quote's signature (SHA-256 RSA) over the message
    fn verify_signature(&self, pub_key: &PKey<Public>) -> Result<(), TpmQuoteError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;
        if !verifier.verify(&self.signature)? {
            return Err(TpmQuoteError::SignatureMismatch);
        }
        Ok(())
    }

    /// Verify that the attested PCR digest matches the digest of the
    /// bundled PCR values
    fn verify_pcrs(&self, attest: &TpmsAttest) -> Result<(), TpmQuoteError> {
        let mut hasher = Sha256::new();
        for pcr in &self.pcrs {
            hasher.update(pcr);
        }
        let digest = hasher.finish();
        if digest[..] != *attest.pcr_digest() {
            return Err(TpmQuoteError::PcrMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] =
        include_bytes!("../../test-assets/azure-tdx-with-ak-intermediates-1780922561.yaml");

    fn fixture_quote_value() -> serde_json::Value {
        let document: serde_json::Value = serde_saphyr::from_slice(FIXTURE).unwrap();
        document["tpm_attestation"]["quote"].clone()
    }

    /// The wire format must be identical to the `az_tdx_vtpm::vtpm::Quote`
    /// serialization captured in the fixture: evidence produced before and
    /// after this type verifies the same.
    #[test]
    fn wire_format_round_trips_against_fixture() {
        let quote_value = fixture_quote_value();
        let quote: TpmQuote = serde_json::from_value(quote_value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&quote).unwrap(), quote_value);
    }

    #[test]
    fn verify_pcrs_accepts_fixture_and_rejects_tampered_pcr() {
        let mut quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();

        let attest = TpmsAttest::parse(&quote.message).unwrap();
        quote.verify_pcrs(&attest).unwrap();

        quote.pcrs[0][0] ^= 0x01;
        let err = quote.verify_pcrs(&attest).unwrap_err();
        assert!(matches!(err, TpmQuoteError::PcrMismatch));
    }

    #[test]
    fn verify_rejects_corrupted_signature() {
        let hcl_report_base64 = {
            let document: serde_json::Value = serde_saphyr::from_slice(FIXTURE).unwrap();
            document["hcl_report_base64"].as_str().unwrap().to_string()
        };
        let mut quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();

        use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
        let hcl_report_bytes = BASE64_URL_SAFE.decode(hcl_report_base64).unwrap();
        let hcl_report = az_cvm_vtpm::hcl::HclReport::new(hcl_report_bytes).unwrap();
        let ak_pub_der = hcl_report.ak_pub().unwrap().key.try_to_der().unwrap();
        let pub_key = PKey::public_key_from_der(&ak_pub_der).unwrap();

        let nonce = quote_nonce(&quote);
        quote.verify(&pub_key, &nonce).unwrap();

        quote.signature.reverse();
        let err = quote.verify(&pub_key, &nonce).unwrap_err();
        assert!(matches!(err, TpmQuoteError::SignatureMismatch));
    }

    fn quote_nonce(quote: &TpmQuote) -> Vec<u8> {
        TpmsAttest::parse(&quote.message).unwrap().extra_data().to_vec()
    }
}
