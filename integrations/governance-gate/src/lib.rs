//! Reference integration #1 — on-chain governance gate.
//!
//! A minimal governance protocol where a vote is only counted when accompanied by a
//! valid LP-0005 attestation that the voter holds at least `MIN_VOTING_STAKE` tokens
//! of the governance token. The attestation does NOT reveal the voter's balance or
//! identity.
//!
//! In LEZ deployment this module is wrapped by a `#[lez_program]` macro and the
//! tallying state lives in a PDA; the pure-Rust kernel here mirrors the verification
//! logic so we can unit-test gate semantics without spinning up a sequencer.

use attestation_core::PublicJournal;
use attestation_verifier_program::{check_gate, GateError, GateInputs};

pub const GOVERNANCE_CONTEXT_ID: [u8; 32] = *b"/lp-0005/integ/governance-v1/\0\0\0\0";

#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("gate verification failed: {0:?}")]
    Gate(GateError),
    #[error("nullifier already used in this proposal")]
    NullifierReused,
    #[error("voter pubkey is not on the governance allow list")]
    NotEligible,
}

/// State tracked per proposal. Application picks the storage layout; this struct is
/// the minimum needed to enforce single-use-per-proposal.
#[derive(Default, Clone, Debug)]
pub struct ProposalState {
    pub yes_votes: u64,
    pub no_votes: u64,
    pub used_nullifiers: std::collections::BTreeSet<[u8; 32]>,
}

pub fn cast_vote(
    state: &mut ProposalState,
    attestation: &PublicJournal,
    presenter_nonce: &[u8; 32],
    presenter_signature_der: &[u8],
    minimum_stake: u128,
    vote_yes: bool,
) -> Result<(), VoteError> {
    check_gate(&GateInputs {
        attested: attestation,
        expected_context_id: &GOVERNANCE_CONTEXT_ID,
        minimum_threshold: minimum_stake,
        challenge_nonce: presenter_nonce,
        presenter_signature_der,
    })
    .map_err(VoteError::Gate)?;

    if !state.used_nullifiers.insert(attestation.nullifier) {
        return Err(VoteError::NullifierReused);
    }

    if vote_yes {
        state.yes_votes += 1;
    } else {
        state.no_votes += 1;
    }
    Ok(())
}
