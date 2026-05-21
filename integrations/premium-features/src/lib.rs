//! Reference integration #3 — privacy-preserving feature tiering.
//!
//! A SaaS-style service exposes feature tiers (free / pro / enterprise). A user
//! attests their token balance via LP-0005 against the threshold corresponding to
//! the tier they want; the service grants access without ever learning the user's
//! exact balance. The nullifier doubles as a per-user-per-tier identifier so the
//! service can enforce "one active session per attestation" without seeing the
//! user's account id.
//!
//! Designed so an outside party can port this against their own product with
//! minimal LP-0005 knowledge. The interesting surface is `Tier::context_id()` and
//! `FeatureService::activate` — a third party only needs to pick tiers + thresholds.

use attestation_core::PublicJournal;
use attestation_verifier_offchain::{verify_credential, VerifyError};
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("attestation verification failed: {0}")]
    Verify(#[from] VerifyError),
    #[error("nullifier already activated for this tier")]
    NullifierReused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    Free,
    Pro,
    Enterprise,
}

impl Tier {
    pub fn minimum_balance(&self) -> u128 {
        match self {
            Tier::Free => 0,
            Tier::Pro => 10_000,
            Tier::Enterprise => 1_000_000,
        }
    }

    pub fn context_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"/lp-0005/integ/premium-features-v1/tier/");
        h.update(match self {
            Tier::Free => b"free".as_slice(),
            Tier::Pro => b"pro".as_slice(),
            Tier::Enterprise => b"enterprise".as_slice(),
        });
        h.finalize().into()
    }
}

#[derive(Default, Debug)]
pub struct FeatureService {
    pub active_sessions: std::collections::BTreeMap<[u8; 32], Tier>, // nullifier -> tier
}

impl FeatureService {
    /// Activate a tier for a user who provided a valid attestation.
    pub fn activate(
        &mut self,
        tier: Tier,
        receipt: &Receipt,
        presenter_nonce: &[u8; 32],
        presenter_signature_der: &[u8],
    ) -> Result<PublicJournal, ActivateError> {
        let ctx = tier.context_id();
        let journal = verify_credential(
            receipt,
            presenter_nonce,
            presenter_signature_der,
            &ctx,
            tier.minimum_balance(),
        )?;

        if self.active_sessions.contains_key(&journal.nullifier) {
            return Err(ActivateError::NullifierReused);
        }
        self.active_sessions.insert(journal.nullifier, tier);
        Ok(journal)
    }

    pub fn tier_for(&self, nullifier: &[u8; 32]) -> Option<Tier> {
        self.active_sessions.get(nullifier).copied()
    }
}
