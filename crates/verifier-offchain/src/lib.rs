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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use k256::ecdsa::{signature::Signer, SigningKey};
    use rand::Rng;

    fn synthetic_journal(presenter_pubkey: [u8; 33]) -> PublicJournal {
        PublicJournal {
            merkle_root: [0xaa; 32],
            threshold: 100,
            context_id: [0xbb; 32],
            presenter_pubkey,
            nullifier: [0xcc; 32],
        }
    }

    fn sign_journal(sk: &SigningKey, nonce: &[u8; 32], journal: &PublicJournal) -> Vec<u8> {
        let digest = presenter_challenge_digest(nonce, journal);
        let sig: Signature = sk.sign(&digest);
        sig.to_der().as_bytes().to_vec()
    }

    fn fresh_nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        rand::thread_rng().fill(&mut n);
        n
    }

    #[test]
    fn challenge_digest_is_deterministic() {
        let pubkey = [0x02u8; 33];
        let j = synthetic_journal(pubkey);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_eq!(d1, d2);
    }

    #[test]
    fn challenge_digest_changes_with_nonce() {
        let j = synthetic_journal([0x02u8; 33]);
        let n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        n2[0] = 1;
        assert_ne!(
            presenter_challenge_digest(&n1, &j),
            presenter_challenge_digest(&n2, &j)
        );
    }

    #[test]
    fn challenge_digest_changes_with_threshold() {
        let mut j = synthetic_journal([0x02u8; 33]);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        j.threshold += 1;
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_ne!(d1, d2);
    }

    #[test]
    fn challenge_digest_changes_with_context_id() {
        let mut j = synthetic_journal([0x02u8; 33]);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        j.context_id[0] ^= 0xff;
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_ne!(d1, d2);
    }

    #[test]
    fn challenge_digest_changes_with_nullifier() {
        let mut j = synthetic_journal([0x02u8; 33]);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        j.nullifier[0] ^= 0xff;
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_ne!(d1, d2);
    }

    #[test]
    fn verify_signature_accepts_valid() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let pk_bytes = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&pk_bytes);
        let j = synthetic_journal(pubkey);
        let nonce = fresh_nonce();
        let sig = sign_journal(&sk, &nonce, &j);
        verify_presenter_signature(&j, &nonce, &sig).unwrap();
    }

    #[test]
    fn verify_signature_rejects_wrong_nonce() {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let pk_bytes = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&pk_bytes);
        let j = synthetic_journal(pubkey);
        let nonce = fresh_nonce();
        let sig = sign_journal(&sk, &nonce, &j);
        let different_nonce = fresh_nonce();
        assert!(matches!(
            verify_presenter_signature(&j, &different_nonce, &sig),
            Err(VerifyError::SignatureRejected)
        ));
    }

    #[test]
    fn verify_signature_rejects_garbage_signature() {
        let pubkey = [0x02u8; 33];
        let j = synthetic_journal(pubkey);
        let nonce = fresh_nonce();
        let garbage = vec![0u8, 1, 2, 3, 4];
        assert!(matches!(
            verify_presenter_signature(&j, &nonce, &garbage),
            Err(VerifyError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_signature_rejects_bad_pubkey() {
        let mut j = synthetic_journal([0u8; 33]); // 33 zero bytes is not a valid compressed point
        j.presenter_pubkey = [0u8; 33];
        let nonce = fresh_nonce();
        let some_sig = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        assert!(matches!(
            verify_presenter_signature(&j, &nonce, &some_sig),
            Err(VerifyError::InvalidPubkey)
        ));
    }

    #[test]
    fn verify_signature_rejects_other_signers_key() {
        let alice = SigningKey::random(&mut rand::thread_rng());
        let bob = SigningKey::random(&mut rand::thread_rng());
        // journal binds to Alice's key, Bob signs
        let alice_pk_bytes = alice
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&alice_pk_bytes);
        let j = synthetic_journal(pubkey);
        let nonce = fresh_nonce();
        let sig_by_bob = sign_journal(&bob, &nonce, &j);
        assert!(matches!(
            verify_presenter_signature(&j, &nonce, &sig_by_bob),
            Err(VerifyError::SignatureRejected)
        ));
    }

    #[test]
    fn challenge_digest_includes_pubkey() {
        let mut j = synthetic_journal([0x02u8; 33]);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        j.presenter_pubkey[10] ^= 0xff;
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_ne!(d1, d2);
    }

    #[test]
    fn challenge_digest_includes_merkle_root() {
        let mut j = synthetic_journal([0x02u8; 33]);
        let nonce = [0u8; 32];
        let d1 = presenter_challenge_digest(&nonce, &j);
        j.merkle_root[0] ^= 0xff;
        let d2 = presenter_challenge_digest(&nonce, &j);
        assert_ne!(d1, d2);
    }

    #[test]
    fn verify_error_messages_are_short_and_single_line() {
        // Each VerifyError Display impl should be a short, single-line
        // diagnostic that doesn't accidentally embed multi-line content
        // (e.g. an entire receipt dump).
        let errs = [
            VerifyError::Receipt("dummy".into()),
            VerifyError::Journal("dummy".into()),
            VerifyError::InvalidPubkey,
            VerifyError::InvalidSignature,
            VerifyError::SignatureRejected,
            VerifyError::ContextMismatch,
            VerifyError::ThresholdTooLow,
        ];
        for e in &errs {
            let s = e.to_string();
            assert!(s.len() < 200, "VerifyError display too verbose: {s}");
            assert!(!s.contains('\n'), "VerifyError display has newline: {s}");
        }
    }
}
