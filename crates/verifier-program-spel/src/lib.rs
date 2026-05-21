//! `#[lez_program]` wrapper around [`attestation_verifier_program::check_gate`].
//!
//! This file does not compile in the lp-0005 workspace — it depends on the
//! Logos `spel_framework` and `nssa_core` crates, which only resolve inside a
//! LEZ workspace checkout (see this crate's README and [ADR-002]).
//!
//! Provided here as a documented skeleton so the intended on-chain shape is
//! reviewable in the submission repository. Refer to `_external/lez-multisig/`
//! for the equivalent full implementation in a working LEZ program.

#![allow(unexpected_cfgs)]
#![cfg(feature = "lez-workspace")]

use attestation_core::PublicJournal;
use attestation_verifier_program::{check_gate, GateInputs};
use spel_framework::prelude::*;

/// Public program-id constant for this verifier (filled in at deploy time).
pub const ATTESTATION_PROGRAM_ID: nssa_core::program::ProgramId = [0u32; 8];

#[lez_program(instruction = "verifier_program::Instruction")]
mod verifier_program {
    use super::*;

    /// Gate a protected action by an LP-0005 attestation.
    /// Accounts:
    /// - presenter: must sign the LEZ transaction.
    /// Args:
    /// - attested_journal: the journal committed by the attestation circuit.
    /// - presenter_nonce: the challenge nonce the verifier drew.
    /// - presenter_signature_der: secp256k1 DER signature over the digest.
    /// - expected_context_id: pinned by the caller program.
    /// - minimum_threshold: pinned by the caller program.
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
        // 1. Apply the gate's local checks (context / threshold / signature).
        check_gate(&GateInputs {
            attested: &attested_journal,
            expected_context_id: &expected_context_id,
            minimum_threshold,
            challenge_nonce: &presenter_nonce,
            presenter_signature_der: &presenter_signature_der,
        })
        .expect("gate check");

        // 2. Declare the chained call to the attestation program so the PPE
        //    outer circuit composes its proof via env::verify and binds the
        //    journal we just gated on.
        let chained = vec![nssa_core::program::ChainedCall::new(
            ATTESTATION_PROGRAM_ID,
            vec![/* attestation program pre-states; sequencer-supplied */],
            &attested_journal,
        )];

        Ok(SpelOutput::execute(vec![presenter.account.clone()], chained))
    }
}
