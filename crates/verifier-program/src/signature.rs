//! secp256k1 signature verification, vendored so the verifier program does not depend
//! on `attestation-verifier-offchain` (which pulls in risc0-zkvm). Stays minimal.

use attestation_core::PublicJournal;
use sha2::{Digest, Sha256};

use super::GateError;

/// Mirror of `attestation_verifier_offchain::presenter_challenge_digest` — kept in sync
/// because the verifier-program guest will be compiled into a separate ELF and we want
/// to avoid pulling host-only crates in.
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

pub fn verify_presenter(
    journal: &PublicJournal,
    nonce: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), GateError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let vk =
        VerifyingKey::from_sec1_bytes(&journal.presenter_pubkey).map_err(|_| GateError::InvalidPubkey)?;
    let sig = Signature::from_der(signature_der).map_err(|_| GateError::InvalidSignature)?;
    let digest = presenter_challenge_digest(nonce, journal);
    vk.verify(&digest, &sig).map_err(|_| GateError::SignatureRejected)
}
