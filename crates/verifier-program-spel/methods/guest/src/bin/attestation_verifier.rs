//! LP-0005 on-chain verifier — SPEL guest (v2: flat args).
//!
//! Single instruction `gated_check`:
//!   1. Validates the LP-0005 attestation journal: context_id matches the
//!      caller-pinned value; threshold meets or exceeds the caller-pinned
//!      minimum.
//!   2. Verifies the presenter's ECDSA signature over a deterministic challenge
//!      digest (presenter_nonce || journal_hash). The pubkey is taken straight
//!      from the journal fields, so a third party who has obtained a proof
//!      cannot replay it without the presenter's private key.
//!   3. Declares a `ChainedCall` to `ATTESTATION_PROGRAM_ID` so the LEZ PPE
//!      pipeline composes the inner attestation proof via `env::verify`.
//!
//! v2 takes the `PublicJournal` fields as flat primitives (5 args) rather than
//! a single `Defined` struct. This is required because the `spel` CLI cannot
//! serialise `Defined` types from CLI flags — every arg must be a primitive
//! or a builtin like `[u8; N]`, `Vec<u8>`, `u128`, etc.
//!
//! The off-chain SDK reconstructs the journal byte sequence for signing /
//! hashing — see `canonical_journal_bytes` below for the canonical encoding.

#![no_main]

use spel_framework::prelude::*;

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
const E_BAD_PUBKEY_LEN: u32 = 3006;

#[lez_program]
mod attestation_verifier {
    #[allow(unused_imports)]
    use super::*;

    /// Gate a protected action by an LP-0005 attestation.
    ///
    /// Accounts:
    /// - `presenter` (signer): the LEZ account submitting the gated transaction.
    ///
    /// Args (PublicJournal flattened + gate inputs):
    /// - `merkle_root`: anchored Merkle root the attestation proved against.
    /// - `threshold`: the threshold N the attestation proved `balance >= N`.
    /// - `context_id`: application context the attestation committed to.
    /// - `presenter_pubkey`: secp256k1 compressed key (Vec<u8>; must be 33
    ///   bytes — serde doesn't impl [u8;N] for N>32 natively, so we use Vec).
    /// - `nullifier`: opaque marker from the attestation journal.
    /// - `presenter_nonce`: the random challenge the verifier issued.
    /// - `presenter_signature_der`: secp256k1 DER signature over
    ///   `SHA256(presenter_nonce || sha256(journal_bytes))`.
    /// - `expected_context_id`: caller-pinned context to prevent replay across
    ///   gates.
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
        // 1. Context binding — replay across gates fails closed.
        if context_id != expected_context_id {
            return Err(SpelError::custom(E_CONTEXT_MISMATCH, "context mismatch"));
        }

        // 2. Threshold floor — caller pins the minimum, journal must clear it.
        if threshold < minimum_threshold {
            return Err(SpelError::custom(E_THRESHOLD_TOO_LOW, "threshold too low"));
        }

        // 3. Validate the presenter pubkey length (secp256k1 compressed = 33 bytes).
        if presenter_pubkey.len() != 33 {
            return Err(SpelError::custom(
                E_BAD_PUBKEY_LEN,
                "presenter_pubkey: expected 33-byte compressed secp256k1 key",
            ));
        }
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&presenter_pubkey);

        // 4. Presenter identity binding — ECDSA challenge response.
        let journal_bytes = canonical_journal_bytes(
            &merkle_root,
            threshold,
            &context_id,
            &pubkey_bytes,
            &nullifier,
        );
        verify_presenter_signature(
            &journal_bytes,
            &pubkey_bytes,
            &presenter_nonce,
            &presenter_signature_der,
        )?;

        // 5. Declare the chained call so the PPE composes the inner attestation
        //    proof via env::verify(ATTESTATION_PROGRAM_ID, journal).
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
/// `presenter_pubkey` over `SHA256(presenter_nonce || SHA256(journal_bytes))`.
fn verify_presenter_signature(
    journal_bytes: &[u8],
    presenter_pubkey: &[u8; 33],
    presenter_nonce: &[u8; 32],
    signature_der: &[u8],
) -> Result<(), SpelError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    let journal_hash: [u8; 32] = Sha256::digest(journal_bytes).into();

    let mut challenge = [0u8; 64];
    challenge[..32].copy_from_slice(presenter_nonce);
    challenge[32..].copy_from_slice(&journal_hash);
    let digest: [u8; 32] = Sha256::digest(&challenge).into();

    let pubkey = VerifyingKey::from_sec1_bytes(presenter_pubkey)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;

    pubkey
        .verify(&digest, &signature)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;

    Ok(())
}

/// Deterministically serialise journal fields to bytes for hashing and
/// chained-call routing. Field order pinned: merkle_root || threshold_LE ||
/// context_id || presenter_pubkey || nullifier. The host SDK MUST use the
/// same encoding when constructing the challenge digest.
fn canonical_journal_bytes(
    merkle_root: &[u8; 32],
    threshold: u128,
    context_id: &[u8; 32],
    presenter_pubkey: &[u8; 33],
    nullifier: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 16 + 32 + 33 + 32);
    out.extend_from_slice(merkle_root);
    out.extend_from_slice(&threshold.to_le_bytes());
    out.extend_from_slice(context_id);
    out.extend_from_slice(presenter_pubkey);
    out.extend_from_slice(nullifier);
    out
}
