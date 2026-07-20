// LP-0005 attestation as a native LEZ program.
//
// WHY THIS EXISTS
//
// The standalone guest (`../../guest/src/bin/attestation.rs`) is a plain Risc0
// program: it reads a witness with `env::read()` and commits a custom
// `PublicJournal`. That shape can never be verified on chain, because:
//
//   * A LEZ *public* transaction does not prove or verify anything. The
//     sequencer simply re-executes the program
//     (`lee/state_machine/src/program.rs:73-77`, "Execute the program (without
//     proving)"), and it feeds every guest exactly four public inputs
//     (`program.rs:89-110`) with no channel for a private witness.
//   * A guest cannot call `env::verify` on an externally produced receipt
//     either: both LEZ executor environments are built without assumptions, so
//     the syscall hard-errors.
//
// The one path on LEZ v0.2.0 where a proof is genuinely verified is the
// privacy-preserving transaction. There the *client* proves locally
// (`lez/wallet/src/lib.rs:578`), and LEZ's privacy circuit composes each chained
// call with a real `env::verify` over the callee's `ProgramOutput`
// (`lee/privacy_preserving_circuit/src/execution_state.rs:149`). The sequencer
// then verifies the resulting receipt against the pinned
// `PRIVACY_PRESERVING_CIRCUIT_ID`.
//
// To take part in that composition, the attestation has to *be* a LEZ program:
// read via `read_lee_inputs`, emit a `ProgramOutput`. That is this file.
//
// PRIVACY
//
// The witness travels in the instruction. That is safe here and only here: a
// privacy `Message` publishes commitments and nullifiers, and carries neither
// `program_id` nor `instruction_data`
// (`lee/state_machine/src/privacy_preserving_transaction/message.rs:14-24`). A
// *public* `Message` does publish `instruction_data` verbatim
// (`public_transaction/message.rs:13-19`), so this program must never be invoked
// on the public path. It is not: the verifier reaches it through a ChainedCall
// inside a privacy transaction.
//
// WHAT IT PROVES
//
// Identical to the standalone guest, via the shared `attestation_core::attest`:
//   1. account_id  = SHA256(PRIVATE_ACCOUNT_ID_PREFIX || npk || identifier_LE)
//   2. commitment  = SHA256(COMMITMENT_PREFIX || account_id || program_owner_LE
//                           || balance_LE || nonce_LE || data_hash)
//   3. SHA256(commitment) folds via merkle_path to statement.merkle_root
//   4. balance >= statement.threshold
//   5. nullifier   = SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id
//                           || account_id)
//
// Any failure panics, which aborts the guest and makes the proof unobtainable.
//
// STATE
//
// The attestation changes no balances and no data: post-states are the
// pre-states unchanged, which satisfies every rule in
// `lee_core::program::validate_execution`. The observable on-chain effect comes
// from the caller (the SPEL verifier), which claims a PDA seeded by the
// nullifier this program returns.

#![no_main]

risc0_zkvm::guest::entry!(main);

use attestation_core::{attest, AttestInstruction};
use lee_core::program::{AccountPostState, ProgramInput, ProgramOutput, read_lee_inputs};

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
    ) = read_lee_inputs::<AttestInstruction>();

    // The whole zero-knowledge statement. Panics if it does not hold, which
    // means no proof can be produced for a false attestation.
    let nullifier = attest(&instruction.witness, &instruction.statement);

    // Bind the derived nullifier into the proven execution. The caller declared
    // this same instruction in its ChainedCall, and the privacy circuit asserts
    // the chained call's instruction data equals the callee's
    // (`execution_state.rs:141-144`), so a caller cannot claim a PDA for one
    // nullifier while having proved another.
    assert!(
        nullifier != [0u8; 32],
        "nullifier must be non-zero for the caller's PDA seed",
    );

    // Pure attestation: no state transition of our own, so every post-state is
    // its pre-state unchanged. That satisfies every rule in
    // `validate_execution` (nonce untouched, owner untouched, balance not
    // decreased, data not modified).
    let post_states: Vec<AccountPostState> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        pre_states,
        post_states,
    )
    .write();
}
