// LP-0005 on-chain verifier, deep variant.
//
// WHAT MAKES THIS THE REAL ON-CHAIN VERIFICATION
//
// The deployed shallow gate checks an ECDSA signature over caller-supplied
// arguments. It verifies no zero-knowledge proof, and it never could: a LEZ
// *public* transaction does not prove or verify anything, it simply re-executes
// the program host-side (`lee/state_machine/src/program.rs:73-77`).
//
// This variant targets the one path on LEZ v0.2.0 where a proof genuinely is
// verified. In a privacy-preserving transaction the client proves locally
// (`lez/wallet/src/lib.rs:578`), and for every chained call LEZ's privacy
// circuit performs a real composition:
//
//     env::verify(chained_call.program_id, program_output_words)
//     -- lee/privacy_preserving_circuit/src/execution_state.rs:149
//
// The sequencer then verifies the resulting receipt against the pinned
// `PRIVACY_PRESERVING_CIRCUIT_ID`. So when this instruction declares a chained
// call to the attestation program, the attestation's proof is verified on chain
// as a precondition of the transaction being accepted.
//
// For that composition to happen the callee must be a real LEZ program emitting
// a `ProgramOutput`. That is why this chains to `attestation_lez`, not to the
// standalone Risc0 guest: the standalone guest commits a bespoke journal that
// cannot decode as a `ProgramOutput`, so the sequencer rejects the call with
// `ProgramExecutionFailed`. That is precisely why the earlier deep variant's
// `gated_check` never confirmed.
//
// WHAT THIS PROGRAM STILL CHECKS ITSELF
//
// Composition proves the *attestation* (Merkle membership against the claimed
// root, and balance >= threshold). It does not prove that the presenter is the
// one submitting. So this program still enforces, host-side:
//   * context binding, so a proof for one gate cannot be replayed at another;
//   * the threshold floor the caller pinned;
//   * an ECDSA challenge response under `presenter_pubkey`, binding the
//     presentation to whoever holds the presenter's private key.
//
// ON-CHAIN OBSERVABILITY
//
// A privacy transaction publishes neither `program_id` nor `instruction_data`
// (`lee/state_machine/src/privacy_preserving_transaction/message.rs:14-24`), so
// without care nothing on chain would record that the gate ran. The instruction
// therefore claims a PDA seeded by the attestation nullifier. The claimed
// account lands in `public_post_states` and so in public state, stamped with
// this program's id. An observer can recompute the PDA from this program's
// ImageID plus the nullifier and see it owned by this program.
//
// It also gives replay protection for free: claiming requires the account to
// have the default program owner (`execution_state.rs:376-380`), so the same
// nullifier can be gated exactly once.

#![no_main]

use spel_framework::prelude::*;

risc0_zkvm::guest::entry!(main);

const E_THRESHOLD_TOO_LOW: u32 = 3001;
const E_CONTEXT_MISMATCH:  u32 = 3004;
const E_BAD_SIGNATURE:     u32 = 3005;
const E_BAD_PUBKEY_LEN:    u32 = 3006;
const E_BAD_WITNESS:       u32 = 3007;
const E_NULLIFIER_MISMATCH: u32 = 3008;

/// ProgramId of the LEZ-native attestation program (`attestation_lez.bin`,
/// ImageID `9b6be465fed863f89450ecf9e8ef3d2183aab83647358519230c12c0746c27da`).
///
/// Verify with:
///   spel inspect crates/attestation-circuit/methods/guest-lez/target/riscv32im-risc0-zkvm-elf/docker/attestation_lez.bin
pub const ATTESTATION_LEZ_PROGRAM_ID: nssa_core::program::ProgramId = [
    1709468571, 4167293182, 4193013908, 557707240, 918071939, 428160327, 3222408227, 3660016756,
];

#[lez_program]
mod attestation_verifier_deep {
    #[allow(unused_imports)]
    use super::*;

    /// Gate an on-chain action on a zero-knowledge balance attestation whose
    /// proof is verified on chain by composition.
    ///
    /// Accounts:
    /// - `gate_marker` (init, PDA seeded by `nullifier`): claimed as the public
    ///   record that this attestation was spent at this gate. Claiming fails if
    ///   it already exists, which is the replay guard.
    /// - `presenter` (signer): the LEZ account submitting the transaction.
    ///
    /// Args:
    /// - `witness_words`: the attestation witness, risc0-serde encoded. Carried
    ///   through to the chained call. Safe only because a privacy transaction
    ///   publishes no instruction data; this instruction must never be invoked
    ///   on the public path.
    /// - `merkle_root`, `threshold`, `context_id`, `presenter_pubkey`: the
    ///   public statement the attestation proves.
    /// - `nullifier`: derived by the circuit; also the PDA seed.
    /// - `presenter_nonce`, `presenter_signature_der`: the challenge response.
    /// - `expected_context_id`, `minimum_threshold`: what the caller demands.
    #[instruction]
    pub fn gated_check(
        #[account(init, pda = arg("nullifier"))]
        gate_marker: AccountWithMetadata,
        #[account(signer)]
        presenter: AccountWithMetadata,
        witness_words: Vec<u32>,
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
        // 1. Context binding.
        if context_id != expected_context_id {
            return Err(SpelError::custom(E_CONTEXT_MISMATCH, "context mismatch"));
        }

        // 2. Threshold floor.
        if threshold < minimum_threshold {
            return Err(SpelError::custom(E_THRESHOLD_TOO_LOW, "threshold too low"));
        }

        // 3. Presenter key shape.
        if presenter_pubkey.len() != 33 {
            return Err(SpelError::custom(
                E_BAD_PUBKEY_LEN,
                "presenter_pubkey: expected 33-byte compressed secp256k1 key",
            ));
        }
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&presenter_pubkey);

        // 4. Presenter identity binding.
        let digest = presenter_challenge_digest(
            &presenter_nonce,
            &merkle_root,
            threshold,
            &context_id,
            &pubkey_bytes,
            &nullifier,
        );
        verify_presenter_signature(&digest, &pubkey_bytes, &presenter_signature_der)?;

        // 5. Rebuild the attestation instruction and check the nullifier the
        //    caller pinned is the one this witness actually yields. Without this
        //    a caller could prove one attestation while claiming another's PDA.
        let witness: attestation_core::PrivateInputs =
            risc0_zkvm::serde::from_slice(&witness_words)
                .map_err(|_| SpelError::custom(E_BAD_WITNESS, "witness_words did not decode"))?;

        let statement = attestation_core::AttestStatement {
            merkle_root,
            threshold,
            context_id,
            presenter_pubkey: pubkey_bytes,
        };

        let account_id =
            attestation_core::derive_account_id(&witness.npk, witness.identifier);
        let derived = attestation_core::compute_nullifier(&pubkey_bytes, &context_id, &account_id);
        if derived != nullifier {
            return Err(SpelError::custom(
                E_NULLIFIER_MISMATCH,
                "nullifier does not match the supplied witness",
            ));
        }

        // 6. Declare the chained call. The privacy circuit will execute and
        //    prove the attestation program, then discharge the assumption with
        //    env::verify over its ProgramOutput. Merkle membership and the
        //    balance comparison are proved there, in zero knowledge.
        let instruction = attestation_core::AttestInstruction { witness, statement };
        let chained = vec![nssa_core::program::ChainedCall::new(
            ATTESTATION_LEZ_PROGRAM_ID,
            Vec::new(), // the attestation program reads no accounts
            &instruction,
        )];

        // 7. Claim the marker PDA and pass the presenter through unchanged.
        Ok(SpelOutput::execute(
            vec![gate_marker, presenter],
            chained,
        ))
    }
}

/// Canonical digest the presenter signs. Byte-for-byte identical to
/// `attestation_verifier_offchain::presenter_challenge_digest`, so a signature
/// produced for the off-chain path verifies here unchanged.
fn presenter_challenge_digest(
    presenter_nonce: &[u8; 32],
    merkle_root: &[u8; 32],
    threshold: u128,
    context_id: &[u8; 32],
    presenter_pubkey: &[u8; 33],
    nullifier: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"/lp-0005/v0.1/PresenterChallenge/");
    h.update(presenter_nonce);
    h.update(merkle_root);
    h.update(threshold.to_le_bytes());
    h.update(context_id);
    h.update(presenter_pubkey);
    h.update(nullifier);
    h.finalize().into()
}

fn verify_presenter_signature(
    digest: &[u8; 32],
    presenter_pubkey: &[u8; 33],
    signature_der: &[u8],
) -> Result<(), SpelError> {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let pubkey = VerifyingKey::from_sec1_bytes(presenter_pubkey)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    pubkey
        .verify(digest.as_slice(), &signature)
        .map_err(|_| SpelError::custom(E_BAD_SIGNATURE, "bad presenter signature"))?;
    Ok(())
}
