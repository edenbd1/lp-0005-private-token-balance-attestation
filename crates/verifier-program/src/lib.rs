//! Pure-Rust verification kernel for the LEZ on-chain verifier program.
//!
//! Decoupled from SPEL/nssa so it (a) compiles on the host for unit tests and
//! (b) drops in unchanged when wrapped by the `#[lez_program]` macro inside a
//! Logos workspace checkout — see `docs/decisions/002-verifier-program-shape.md`.
//!
//! Responsibilities at on-chain time:
//!   1. Read the chained attestation program's [`PublicJournal`] (decoded from the
//!      `ProgramOutput` populated by the PPE pipeline).
//!   2. Re-check the context binding (`context_id`) and threshold against caller-supplied
//!      gate parameters.
//!   3. Verify the presenter's secp256k1 signature over the verifier-supplied challenge.
//!   4. Optionally consume the `nullifier` to enforce one-shot semantics on
//!      application-controlled storage.
//!
//! The Risc0 receipt itself is not handed to this code; the PPE outer circuit
//! exercises `env::verify(ATTESTATION_PROGRAM_ID, journal)` and we trust that
//! composition has already established the journal's authenticity.

use attestation_core::PublicJournal;

pub mod signature;

#[derive(Debug)]
pub enum GateError {
    ContextMismatch,
    ThresholdTooLow,
    InvalidPubkey,
    InvalidSignature,
    SignatureRejected,
    NullifierAlreadyUsed,
}

/// All data the verifier program needs at one gate invocation.
pub struct GateInputs<'a> {
    pub attested: &'a PublicJournal,
    pub expected_context_id: &'a [u8; 32],
    pub minimum_threshold: u128,
    pub challenge_nonce: &'a [u8; 32],
    pub presenter_signature_der: &'a [u8],
}

/// Pure check; no storage. Caller is responsible for nullifier tracking.
pub fn check_gate(inputs: &GateInputs) -> Result<(), GateError> {
    if &inputs.attested.context_id != inputs.expected_context_id {
        return Err(GateError::ContextMismatch);
    }
    if inputs.attested.threshold < inputs.minimum_threshold {
        return Err(GateError::ThresholdTooLow);
    }
    signature::verify_presenter(
        inputs.attested,
        inputs.challenge_nonce,
        inputs.presenter_signature_der,
    )
}
