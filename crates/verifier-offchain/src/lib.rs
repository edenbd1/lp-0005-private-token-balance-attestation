//! Off-chain verifier for LP-0005 attestation credentials.
//!
//! A credential is a Risc0 receipt that journals a [`PublicJournal`]. Verification proceeds
//! in two stages:
//!
//! 1. **ZK verification** — [`verify_receipt`] checks the Risc0 receipt against the
//!    pinned `ATTESTATION_ID` and decodes the journal. This proves the prover knew an
//!    LEZ private account whose balance meets the attested threshold.
//!
//! 2. **Identity check** — [`verify_presenter_signature`] checks that the presenter
//!    controls the private key corresponding to `journal.presenter_pubkey` by validating
//!    an ECDSA-secp256k1 signature over a verifier-supplied challenge bound to the
//!    journal. This prevents passive forwarding of a captured proof.
//!
//! Callers must additionally enforce business rules (correct `context_id`, fresh
//! `merkle_root`, unique `nullifier` if they care about one-shot use, expected
//! `threshold`).

use attestation_core::PublicJournal;
pub use attestation_methods::ATTESTATION_ID;
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("risc0 receipt verification failed: {0}")]
    Receipt(String),
    #[error("could not decode the journal: {0}")]
    Journal(String),
    #[error("invalid presenter pubkey encoding")]
    InvalidPubkey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("presenter signature did not verify under journal.presenter_pubkey")]
    SignatureRejected,
    #[error("application context mismatch")]
    ContextMismatch,
    #[error("threshold smaller than required minimum")]
    ThresholdTooLow,
}

/// Verify a Risc0 receipt and return the public journal it commits to.
pub fn verify_receipt(receipt: &Receipt) -> Result<PublicJournal, VerifyError> {
    receipt
        .verify(ATTESTATION_ID)
        .map_err(|e| VerifyError::Receipt(e.to_string()))?;
    receipt
        .journal
        .decode::<PublicJournal>()
        .map_err(|e| VerifyError::Journal(e.to_string()))
}

/// Compute the canonical challenge digest the presenter signs.
/// The verifier picks `nonce` freshly; the rest of the bytes bind the signature to the journal,
/// so a signature for journal A cannot be reused for journal B.
pub fn presenter_challenge_digest(nonce: &[u8; 32], journal: &PublicJournal) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"/lp-0005/v0.1/PresenterChallenge/");
    h.update(nonce);
    h.update(journal.merkle_root);
    h.update(journal.threshold.to_le_bytes());
    h.update(journal.context_id);
    h.update(journal.presenter_pubkey);
    h.update(journal.nullifier);
    h.finalize().into()
}

/// Check the presenter signature for the given challenge.
pub fn verify_presenter_signature(
    journal: &PublicJournal,
    nonce: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), VerifyError> {
    let vk = VerifyingKey::from_sec1_bytes(&journal.presenter_pubkey)
        .map_err(|_| VerifyError::InvalidPubkey)?;
    let sig = Signature::from_der(signature_der).map_err(|_| VerifyError::InvalidSignature)?;
    let digest = presenter_challenge_digest(nonce, journal);
    vk.verify(&digest, &sig)
        .map_err(|_| VerifyError::SignatureRejected)
}

/// End-to-end: ZK + identity in one call.
pub fn verify_credential(
    receipt: &Receipt,
    presenter_nonce: &[u8; 32],
    presenter_signature_der: &[u8],
    expected_context_id: &[u8; 32],
    minimum_threshold: u128,
) -> Result<PublicJournal, VerifyError> {
    let journal = verify_receipt(receipt)?;
    if &journal.context_id != expected_context_id {
        return Err(VerifyError::ContextMismatch);
    }
    if journal.threshold < minimum_threshold {
        return Err(VerifyError::ThresholdTooLow);
    }
    verify_presenter_signature(&journal, presenter_nonce, presenter_signature_der)?;
    Ok(journal)
}
