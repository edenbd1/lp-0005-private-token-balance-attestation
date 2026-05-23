//! LP-0005 on-chain verifier — SPEL guest.
//!
//! Single instruction `gated_check`:
//!   1. Validates the LP-0005 attestation journal: context_id matches the
//!      caller-pinned value; threshold meets or exceeds the caller-pinned
//!      minimum.
//!   2. Verifies the presenter's ECDSA signature over a deterministic challenge
//!      digest (presenter_nonce || journal_hash). The pubkey is taken straight
//!      from the journal, so a third party who has obtained a proof cannot
//!      replay it without the presenter's private key.
//!   3. Declares a `ChainedCall` to `ATTESTATION_PROGRAM_ID` so the LEZ PPE
//!      pipeline composes the inner attestation proof via `env::verify`.
//!
//! `PublicJournal` is inlined here so the guest is self-contained — the docker
//! sandbox `cargo risczero build` runs in cannot resolve path dependencies
//! that live outside the methods/guest directory.

#![no_main]

use spel_framework::prelude::*;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

risc0_zkvm::guest::entry!(main);

/// ProgramId of the deployed LP-0005 attestation circuit (RISC-V image_id),
/// in LEZ's `[u32; 8]` little-endian-per-word form.
///
/// Sourced from `spel inspect target/.../attestation.bin` after the host-side
/// deploy on `https://testnet.lez.logos.co` (deploy tx
/// `4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d`).
pub const ATTESTATION_PROGRAM_ID: nssa_core::program::ProgramId = [
    2483799259u32,
    2922882797u32,
    876186261u32,
    293393208u32,
    1395530467u32,
    1389967705u32,
    1615301448u32,
    1302162100u32,
];

/// Deterministic error codes — surfaced by the off-chain SDK as integers so
/// integrators can branch on them without parsing error strings.
const E_CONTEXT_MISMATCH: u32 = 3004;
const E_THRESHOLD_TOO_LOW: u32 = 3001;
const E_BAD_SIGNATURE: u32 = 3005;

/// LP-0005 attestation public journal — inlined from `attestation-core` because
/// the risc0 docker builder context only sees the methods/guest directory.
/// Byte-for-byte equivalent to `attestation_core::PublicJournal`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicJournal {
    pub merkle_root: [u8; 32],
    pub threshold: u128,
    pub context_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub presenter_pubkey: [u8; 33],
    pub nullifier: [u8; 32],
}

#[lez_program]
mod attestation_verifier {
    #[allow(unused_imports)]
    use super::*;

    /// Gate a protected action by an LP-0005 attestation.
    ///
    /// Accounts:
    /// - `presenter` (signer): the LEZ account submitting the gated transaction.
    ///
    /// Args:
    /// - `attested_journal`: the public journal committed by the attestation
    ///   guest (`crates/attestation-circuit`).
    /// - `presenter_nonce`: the random challenge the verifier issued.
    /// - `presenter_signature_der`: secp256k1 DER signature over
    ///   `SHA256(presenter_nonce || sha256(journal_bytes))`, verified against
    ///   `journal.presenter_pubkey`.
    /// - `expected_context_id`: caller-pinned context to prevent replay across
    ///   gates.
    /// - `minimum_threshold`: caller-pinned floor on the attested threshold.
    #[instruction]
    pub fn gated_check(
        #[account(signer)]
        presenter: AccountWithMetadata,
        attested_journal: PublicJournal,
        presenter_nonce: [u8; 32],
        presenter_signature_der: Vec<u8>,
        expected_context_id: [u8; 32],
        minimum_threshold: u128,
    ) -> SpelResult {
        // 1. Context binding — replay across gates fails closed.
        if attested_journal.context_id != expected_context_id {
            return Err(SpelError::custom(E_CONTEXT_MISMATCH, "context mismatch"));
        }

        // 2. Threshold floor — caller pins the minimum, journal must clear it.
        if attested_journal.threshold < minimum_threshold {
            return Err(SpelError::custom(E_THRESHOLD_TOO_LOW, "threshold too low"));
        }

        // 3. Presenter identity binding — ECDSA challenge response.
        verify_presenter_signature(
            &attested_journal,
            &presenter_nonce,
            &presenter_signature_der,
        )?;

        // 4. Declare the chained call so the PPE composes the inner attestation
        //    proof via env::verify(ATTESTATION_PROGRAM_ID, journal).
        let journal_bytes = canonical_journal_bytes(&attested_journal);
        let chained = vec![nssa_core::program::ChainedCall::new(
            ATTESTATION_PROGRAM_ID,
            Vec::new(), // pre-states; the attestation program is pure (no state reads)
            &journal_bytes,
        )];

        Ok(SpelOutput::execute(
            vec![presenter.account.clone()],
            chained,
        ))
    }
}

/// Verify `presenter_signature_der` is a valid secp256k1 DER signature by
/// `journal.presenter_pubkey` over `SHA256(presenter_nonce || SHA256(journal_bytes))`.
fn verify_presenter_signature(
    journal: &PublicJournal,
    presenter_nonce: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), SpelError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let journal_bytes = canonical_journal_bytes(journal);
    let journal_hash: [u8; 32] = Sha256::digest(&journal_bytes).into();

    let mut challenge = [0u8; 64];
    challenge[..32].copy_from_slice(presenter_nonce);
    challenge[32..].copy_from_slice(&journal_hash);
    let digest: [u8; 32] = Sha256::digest(&challenge).into();

    let pubkey = VerifyingKey::from_sec1_bytes(&journal.presenter_pubkey)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;

    pubkey
        .verify(&digest, &signature)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;

    Ok(())
}

/// Deterministically serialise a `PublicJournal` to bytes for hashing /
/// chained-call routing. Field order pinned: merkle_root || threshold_LE ||
/// context_id || presenter_pubkey || nullifier. The host SDK MUST use the
/// same encoding when constructing the challenge digest.
fn canonical_journal_bytes(j: &PublicJournal) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 16 + 32 + 33 + 32);
    out.extend_from_slice(&j.merkle_root);
    out.extend_from_slice(&j.threshold.to_le_bytes());
    out.extend_from_slice(&j.context_id);
    out.extend_from_slice(&j.presenter_pubkey);
    out.extend_from_slice(&j.nullifier);
    out
}
