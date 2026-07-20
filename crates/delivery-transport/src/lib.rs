//! Transport abstraction for LP-0005 credentials over Logos Delivery (the messaging
//! layer also referred to as "Logos Messaging" in the prize text).
//!
//! Logos Delivery currently ships only as a Qt/C++ Logos Core module (see
//! `_external/logos-delivery-module`). The Rust binding doesn't exist upstream yet.
//! We define a transport trait so the rest of the SDK can be written and tested today,
//! and we can plug in the real backend later (`liblogosdelivery` FFI or a Qt helper
//! subprocess — see task #16 for the trade-off).

use attestation_core::PublicJournal;
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

/// A credential as it travels on the wire: the Risc0 receipt + presenter metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialEnvelope {
    pub receipt: Receipt,
    /// Verifier-supplied challenge nonce being responded to.
    pub challenge_nonce: [u8; 32],
    /// DER-encoded secp256k1 signature over the challenge digest.
    pub presenter_signature_der: Vec<u8>,
    /// Optional application-defined metadata (e.g. a group id, a tier name).
    pub app_meta: Vec<u8>,
}

impl CredentialEnvelope {
    pub fn journal(&self) -> Result<PublicJournal, TransportError> {
        self.receipt
            .journal
            .decode::<PublicJournal>()
            .map_err(|e| TransportError::Decode(e.to_string()))
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"/lp-0005/v0.1/EnvelopeFingerprint/");
        h.update(self.challenge_nonce);
        h.update(&self.presenter_signature_der);
        h.update(&self.app_meta);
        // bincode-encode the receipt for a stable fingerprint that survives across
        // calls. The exact bytes do not matter — only that they are deterministic.
        let bytes = bincode::serde::encode_to_vec(&self.receipt, bincode::config::standard())
            .expect("receipt is serializable");
        h.update(bytes);
        h.finalize().into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("upstream Logos Delivery error: {0}")]
    Upstream(String),
    #[error("envelope encoding error: {0}")]
    Encode(String),
    #[error("envelope decoding error: {0}")]
    Decode(String),
}

/// Serialise an envelope for the wire. Shared by every transport so a credential
/// sent by one is readable by another.
pub fn encode_envelope(envelope: &CredentialEnvelope) -> Result<Vec<u8>, TransportError> {
    bincode::serde::encode_to_vec(envelope, bincode::config::standard())
        .map_err(|e| TransportError::Encode(e.to_string()))
}

/// Inverse of [`encode_envelope`].
pub fn decode_envelope(bytes: &[u8]) -> Result<CredentialEnvelope, TransportError> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| TransportError::Decode(e.to_string()))
}

/// Trait implemented by every concrete transport (real Logos Delivery, Qt-bridge
/// subprocess, in-memory test bus, file-on-disk dev loop).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Publish a credential to a topic (group id, peer id, app channel — semantics
    /// are transport-defined).
    async fn send(&self, topic: &str, envelope: CredentialEnvelope) -> Result<(), TransportError>;

    /// Receive the next pending credential on a topic. Returns `None` if the topic is
    /// closed; blocks until a message arrives otherwise.
    async fn recv(&self, topic: &str) -> Result<Option<CredentialEnvelope>, TransportError>;
}

/// In-process bus. For unit tests only: it performs no network I/O, so it must
/// not be presented as Logos Messaging transmission. Use [`waku_rest`] for that.
pub mod inmem;

/// Real Logos Messaging transport, over the Waku network Logos Delivery runs on.
pub mod waku_rest;

#[cfg(feature = "qt-bridge")]
pub mod qt_bridge;
