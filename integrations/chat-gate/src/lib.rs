//! Reference integration #2 — off-chain token-gated chat group admission.
//!
//! A chat group operator maintains a member set. To join, a candidate sends a
//! `MembershipRequest` over Logos Messaging with: their attestation receipt
//! (proves `balance >= min_stake` in the relevant token), a fresh nonce, and a
//! signature over that nonce bound to the journal. The group operator runs
//! this kernel; on success, it adds the candidate's `presenter_pubkey` to the
//! roster and replies "admitted". Nullifiers are tracked per-group so a single
//! attestation can join exactly once.
//!
//! Pure Rust — no Logos Messaging at this layer. The transport bridge lives in
//! `crates/sdk` (and ultimately in a Logos Delivery binding, task #16).

use attestation_core::PublicJournal;
use attestation_verifier_offchain::{verify_credential, VerifyError};
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("attestation verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("nullifier already used in this group")]
    NullifierReused,
    #[error("attestation does not bind to this group's context")]
    WrongGroup,
}

/// Derive the per-group `context_id` from a stable group identifier.
pub fn group_context_id(group_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"/lp-0005/integ/chat-gate-v1/");
    h.update(group_id.as_bytes());
    h.finalize().into()
}

#[derive(Default, Debug, Clone)]
pub struct GroupRoster {
    pub group_id: String,
    pub members: std::collections::BTreeSet<[u8; 33]>,
    pub used_nullifiers: std::collections::BTreeSet<[u8; 32]>,
    pub minimum_stake: u128,
}

impl GroupRoster {
    pub fn new(group_id: impl Into<String>, minimum_stake: u128) -> Self {
        Self {
            group_id: group_id.into(),
            members: Default::default(),
            used_nullifiers: Default::default(),
            minimum_stake,
        }
    }

    /// Apply an admission request and return the verified journal on success.
    pub fn admit(
        &mut self,
        receipt: &Receipt,
        presenter_nonce: &[u8; 32],
        presenter_signature_der: &[u8],
    ) -> Result<PublicJournal, AdmissionError> {
        let expected_ctx = group_context_id(&self.group_id);
        let journal = verify_credential(
            receipt,
            presenter_nonce,
            presenter_signature_der,
            &expected_ctx,
            self.minimum_stake,
        )?;

        if !self.used_nullifiers.insert(journal.nullifier) {
            return Err(AdmissionError::NullifierReused);
        }
        self.members.insert(journal.presenter_pubkey);
        Ok(journal)
    }
}
