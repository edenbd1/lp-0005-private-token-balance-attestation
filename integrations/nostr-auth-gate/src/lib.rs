//! # nostr-auth-gate (LP-0005 reference integration #4)
//!
//! A Nostr relay can require connecting clients to prove possession of a
//! shielded token balance above some threshold before honouring EVENT or REQ
//! frames. The check happens during the [NIP-42 AUTH](https://github.com/nostr-protocol/nips/blob/master/42.md)
//! handshake — the relay sends a challenge event, the client returns a kind:22242
//! reply, and **this gate extends the reply with an LP-0005 attestation**
//! credential. The relay verifies both: the Schnorr signature over the
//! challenge AND the LP-0005 receipt (presenter signature + Risc0 proof).
//!
//! ## Why this is a community-starter integration
//!
//! Nostr is its own ecosystem with its own relay implementations, NIPs, and
//! conventions. LP-0005 contributions to Nostr's auth model belong with Nostr
//! community maintainers, not the LP-0005 prize submitter. This crate is
//! shipped as a **reference template** that an external builder can fork
//! into the relevant relay implementation (`strfry`, `nostr-rs-relay`, etc.).
//!
//! It is structurally distinct from the other 3 in-repo integrations
//! (`chat-gate`, `governance-gate`, `premium-features`) — different domain,
//! different framing, different transport — so the diff between the four
//! makes the integration surface obvious to a forking implementer.
//!
//! Solicitation status: this crate ships in-tree as a starter template and is
//! not published to crates.io. Forks and outside ports will be tracked in
//! `docs/community-ports.md` as they land.

#![warn(missing_docs)]

use attestation_core::PublicJournal;
use attestation_verifier_offchain::{verify_credential, VerifyError};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors a relay sees while gating a client's NIP-42 AUTH.
#[derive(Debug, thiserror::Error)]
pub enum NostrGateError {
    /// The AUTH reply didn't include an LP-0005 credential tag.
    #[error("missing lp0005 tag in NIP-42 AUTH reply")]
    MissingTag,
    /// The base64 of the credential blob failed to decode.
    #[error("base64 decode of credential: {0}")]
    BadBase64(String),
    /// Bincode deserialization of the Risc0 receipt failed.
    #[error("decode receipt: {0}")]
    DecodeReceipt(String),
    /// LP-0005 verification failed.
    #[error("LP-0005 verification: {0}")]
    Verify(#[from] VerifyError),
    /// The hex-encoded fields (nonce, signature) couldn't be decoded.
    #[error("bad hex: {0}")]
    BadHex(String),
}

/// A NIP-42 AUTH reply tag carrying an LP-0005 credential, plus the
/// challenge nonce drawn by the relay and the presenter's signature.
///
/// Wire form (the tag value inside a kind:22242 event):
///
/// ```text
/// ["lp0005",
///   "<base64 receipt bytes>",
///   "<hex 32-byte nonce>",
///   "<hex DER ECDSA signature>"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lp0005AuthTag {
    /// Base64-encoded bincode-encoded Risc0 receipt.
    pub credential_b64: String,
    /// Hex-encoded 32-byte nonce the relay drew during the AUTH challenge.
    pub nonce_hex: String,
    /// Hex-encoded DER ECDSA signature by the presenter's secp256k1 key.
    pub signature_hex: String,
}

/// Relay-side verification entry point.
///
/// `relay_context` is the relay's stable identifier (URL or pubkey) used as
/// the LP-0005 context — prevents a credential intended for one relay from
/// being replayed at another. `minimum_threshold` is the per-relay policy.
pub fn verify_nip42_with_lp0005(
    tag: &Lp0005AuthTag,
    relay_context: &str,
    minimum_threshold: u128,
) -> Result<PublicJournal, NostrGateError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let receipt_bytes = B64
        .decode(&tag.credential_b64)
        .map_err(|e| NostrGateError::BadBase64(e.to_string()))?;
    let (receipt, _): (Receipt, _) =
        bincode::serde::decode_from_slice(&receipt_bytes, bincode::config::standard())
            .map_err(|e| NostrGateError::DecodeReceipt(e.to_string()))?;

    let nonce_bytes: [u8; 32] = hex::decode(&tag.nonce_hex)
        .map_err(|e| NostrGateError::BadHex(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| NostrGateError::BadHex("nonce must be exactly 32 bytes".into()))?;

    let signature_bytes =
        hex::decode(&tag.signature_hex).map_err(|e| NostrGateError::BadHex(e.to_string()))?;

    let context_id = context_id_for_relay(relay_context);

    let journal = verify_credential(
        &receipt,
        &nonce_bytes,
        &signature_bytes,
        &context_id,
        minimum_threshold,
    )?;
    Ok(journal)
}

/// Deterministically derive the LP-0005 `context_id` from a relay's stable
/// identifier. Pinned format: `SHA256("nostr-auth-gate/v1/" || relay_id)`.
pub fn context_id_for_relay(relay_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nostr-auth-gate/v1/");
    h.update(relay_id.as_bytes());
    h.finalize().into()
}

// Bring in base64 + bincode + thiserror (handled via dependencies above).
extern crate base64 as _base64_used_in_doc;
