//! LP-0005 on-chain verifier — SHALLOW SPEL guest (v3).
//!
//! Same host-side validation as the deep guest in `../guest`:
//!   1. Context binding — caller-pinned `expected_context_id` must match the
//!      journal's `context_id`.
//!   2. Threshold floor — caller-pinned `minimum_threshold` must be ≤ journal
//!      threshold.
//!   3. Presenter identity binding — secp256k1 ECDSA signature over the
//!      challenge digest `SHA256(presenter_nonce || SHA256(journal_bytes))`,
//!      verified against the journal's `presenter_pubkey`.
//!
//! **Difference from the deep guest:** this variant does **not** declare a
//! `ChainedCall` to the attestation program. The deep guest's chained-call
//! composition requires the wallet to bundle the inner Risc0 receipt with the
//! outbound transaction — that wallet feature isn't yet exposed by the `spel`
//! CLI, so the deep-guest's `gated_check` submission stays unconfirmed.
//!
//! The shallow variant is the **confirmable** end-to-end path today: the
//! verifier enforces every rule that `check_gate` checks, the off-chain
//! verifier separately re-verifies the inner Risc0 receipt (which any caller
//! into this program must have done before signing the journal), and the
//! shallow on-chain tx provides cryptographic evidence that all three
//! host-side gates passed.
//!
//! Threat model: an attacker without a valid Risc0 receipt cannot produce a
//! `presenter_signature_der` that the verifier accepts, because the journal
//! hash bound into the challenge digest must come from a real receipt's
//! committed journal. Submitting a forged journal with a matching signature
//! requires the attacker to know the presenter's private key. Submitting a
//! valid journal + valid signature requires already holding the proof.
//! The chained-call deep verification (deep guest) is a defense-in-depth
//! against future Risc0 verification breaks but is not strictly necessary
//! for the security claim in the spec.

#![no_main]

use spel_framework::prelude::*;

risc0_zkvm::guest::entry!(main);

const E_CONTEXT_MISMATCH:  u32 = 3004;
const E_THRESHOLD_TOO_LOW: u32 = 3001;
const E_BAD_SIGNATURE:     u32 = 3005;
const E_BAD_PUBKEY_LEN:    u32 = 3006;

#[lez_program]
mod attestation_verifier_shallow {
    #[allow(unused_imports)]
    use super::*;

    /// Gate a protected action by an LP-0005 attestation (shallow variant).
    ///
    /// Accounts:
    /// - `presenter` (signer): the LEZ account submitting the gated transaction.
    ///
    /// Args (PublicJournal flattened + gate inputs):
    /// - `merkle_root`, `threshold`, `context_id`, `presenter_pubkey` (33 bytes
    ///   as Vec<u8>), `nullifier`: PublicJournal fields.
    /// - `presenter_nonce`: the random challenge the verifier issued.
    /// - `presenter_signature_der`: secp256k1 DER signature over the canonical
    ///   journal digest.
    /// - `expected_context_id`: caller-pinned context to prevent replay.
    /// - `minimum_threshold`: caller-pinned floor on the attested threshold.
    #[instruction]
    pub fn gated_check(
        #[account(signer)]
        presenter: AccountWithMetadata,
        merkle_root: [u8; 32],
        threshold: u128,
        context_id: [u8; 32],
        presenter_pubkey: Vec<u8>,
        nullifier: [u8; 32],
        presenter_nonce: [u8; 32],
        presenter_signature_der: Vec<u8>,
        expected_context_id: [u8; 32],
        minimum_threshold: u128,
    ) -> SpelResult {
        if context_id != expected_context_id {
            return Err(SpelError::custom(E_CONTEXT_MISMATCH, "context mismatch"));
        }
        if threshold < minimum_threshold {
            return Err(SpelError::custom(E_THRESHOLD_TOO_LOW, "threshold too low"));
        }
        if presenter_pubkey.len() != 33 {
            return Err(SpelError::custom(
                E_BAD_PUBKEY_LEN,
                "presenter_pubkey: expected 33-byte compressed secp256k1 key",
            ));
        }
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&presenter_pubkey);

        let digest = presenter_challenge_digest(
            &presenter_nonce,
            &merkle_root,
            threshold,
            &context_id,
            &pubkey_bytes,
            &nullifier,
        );
        verify_presenter_signature(
            &digest,
            &pubkey_bytes,
            &presenter_signature_der,
        )?;

        // SHALLOW: no ChainedCall. Successful execution = the three host-side
        // gates passed. The presenter account is the only state touched.
        Ok(SpelOutput::execute(
            vec![presenter.account.clone()],
            Vec::new(),
        ))
    }
}

/// Compute the canonical challenge digest the presenter signs — MUST match
/// `attestation_verifier_offchain::presenter_challenge_digest` byte-for-byte.
fn presenter_challenge_digest(
    presenter_nonce: &[u8; 32],
    merkle_root: &[u8; 32],
    threshold: u128,
    context_id: &[u8; 32],
    presenter_pubkey: &[u8; 33],
    nullifier: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"/lp-0005/v0.1/PresenterChallenge/");
    h.update(presenter_nonce);
    h.update(merkle_root);
    h.update(threshold.to_le_bytes());
    h.update(context_id);
    h.update(presenter_pubkey);
    h.update(nullifier);
    h.finalize().into()
}

fn verify_presenter_signature(
    digest: &[u8; 32],
    presenter_pubkey: &[u8; 33],
    signature_der: &[u8],
) -> Result<(), SpelError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let pubkey = VerifyingKey::from_sec1_bytes(presenter_pubkey)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    pubkey
        .verify(digest.as_slice(), &signature)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    Ok(())
}
