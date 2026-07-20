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
// WHAT THIS PROGRAM CHECKS ITSELF
//
// Composition proves the attestation *relative to the root the witness names*.
// That root is caller-supplied, so the proof on its own establishes possession of
// a key over a self-declared account and nothing about a real balance. Every
// argument to this instruction is likewise caller-chosen. The gate is therefore
// built so that the arguments alone cannot buy anything:
//
//   * **the presenter is the attested account** — `presenter.account_id` must
//     equal `derive_account_id(witness.npk, witness.identifier)`. Without this
//     binding the balance checked below belongs to a different account than the
//     one attested, and the check is decorative;
//   * **the balance is denominated by a named program** — the presenter's
//     `program_owner` must be LEZ's built-in `authenticated_transfer`, which is
//     what manages private balances on the testnet. `balance` is a bare u128
//     whose meaning belongs to its owning program, so the gate pins which
//     program's semantics it is trusting rather than reading the field blind;
//   * **the anchored balance** — `presenter.account.balance`, read from the
//     pre_state rather than the witness. On the privacy path LEZ computes that
//     account's commitment from this exact state and folds the caller's
//     membership proof into a digest the sequencer requires to be in
//     `root_history`, so it cannot be invented. Combined with the binding above,
//     this is what makes the gate mean "holds at least N" rather than "claims to
//     hold at least N";
//   * context binding, so a proof for one gate cannot be replayed at another;
//   * an ECDSA challenge response under `presenter_pubkey`, binding the
//     presentation to whoever holds the presenter's private key.
//
// ON-CHAIN OBSERVABILITY
//
// A privacy transaction publishes neither `program_id` nor `instruction_data`
// (`lee/state_machine/src/privacy_preserving_transaction/message.rs:14-24`), so
// without care nothing on chain would record that the gate ran, and nothing would
// record *what it enforced*. Seeding the marker by the nullifier alone is not
// enough: `minimum_threshold` is an argument, so a caller pinning it to zero would
// leave a marker indistinguishable from one earned against a real floor.
//
// The instruction therefore claims a PDA seeded by
// `compute_gate_tag(nullifier, minimum_threshold, expected_context_id)`. The
// claimed account lands in `public_post_states` and so in public state, stamped
// with this program's id. An integrator demanding "context C, at least N"
// computes the single address that can satisfy them and checks it exists and is
// owned by this program. A marker earned at a lower floor lives elsewhere.
//
// Replay protection comes for free: claiming requires the account to have the
// default program owner (`execution_state.rs:376-380`), so a given
// (nullifier, floor, context) can be gated exactly once.

#![no_main]

use spel_framework::prelude::*;

risc0_zkvm::guest::entry!(main);

const E_THRESHOLD_TOO_LOW: u32 = 3001;
const E_CONTEXT_MISMATCH:  u32 = 3004;
const E_BAD_SIGNATURE:     u32 = 3005;
const E_BAD_PUBKEY_LEN:    u32 = 3006;
const E_BAD_WITNESS:       u32 = 3007;
const E_NULLIFIER_MISMATCH: u32 = 3008;
const E_ANCHORED_BALANCE_TOO_LOW: u32 = 3009;
const E_PRESENTER_NOT_ATTESTED: u32 = 3010;
const E_PRESENTER_NOT_NATIVE: u32 = 3011;
const E_GATE_TAG_MISMATCH: u32 = 3012;

/// ProgramId of the LEZ-native attestation program (`attestation_lez.bin`,
/// ImageID `9b6be465fed863f89450ecf9e8ef3d2183aab83647358519230c12c0746c27da`).
///
/// Verify with:
///   spel inspect crates/attestation-circuit/methods/guest-lez/target/riscv32im-risc0-zkvm-elf/docker/attestation_lez.bin
pub const ATTESTATION_LEZ_PROGRAM_ID: nssa_core::program::ProgramId = [
    1709468571, 4167293182, 4193013908, 557707240, 918071939, 428160327, 3222408227, 3660016756,
];

/// ProgramId of LEZ's built-in `authenticated_transfer` program
/// (ImageID `dcbbfebc…bc3f4a71`), which is what owns a wallet's private
/// balance-bearing accounts on the public testnet.
///
/// The gate pins it because `Account::balance` has no universal meaning: it is
/// whatever the owning program decides. Reading it as "tokens held" is only
/// sound for an account managed by a program whose semantics we have actually
/// checked. Pinning names that program instead of leaving it open, so the gate
/// asserts "N tokens under this program" rather than "N of something".
///
/// Verify with:
///   spel inspect <logos-execution-zone>/artifacts/lez/programs/authenticated_transfer.bin
pub const AUTHENTICATED_TRANSFER_PROGRAM_ID: nssa_core::program::ProgramId = [
    3170810844, 2526647253, 999807262, 1205602179, 3401962591, 3484055895, 2106546407, 1900691388,
];

#[lez_program]
mod attestation_verifier_deep {
    #[allow(unused_imports)]
    use super::*;

    /// Gate an on-chain action on a zero-knowledge balance attestation whose
    /// proof is verified on chain by composition.
    ///
    /// Accounts:
    /// - `gate_marker` (init, PDA seeded by `gate_tag`): claimed as the public
    ///   record that this attestation was spent at this gate, at this floor, in
    ///   this context. Claiming fails if it already exists, which is the replay
    ///   guard.
    /// - `presenter` (signer): the LEZ account submitting the transaction, which
    ///   must be the very account the witness attests to, and must be owned by
    ///   the pinned token program.
    ///
    /// Args:
    /// - `witness_words`: the attestation witness, risc0-serde encoded. Carried
    ///   through to the chained call. Safe only because a privacy transaction
    ///   publishes no instruction data; this instruction must never be invoked
    ///   on the public path.
    /// - `merkle_root`, `threshold`, `context_id`, `presenter_pubkey`: the
    ///   public statement the attestation proves.
    /// - `nullifier`: derived by the circuit, and re-derived here from the witness.
    /// - `presenter_nonce`, `presenter_signature_der`: the challenge response.
    /// - `expected_context_id`, `minimum_threshold`: the policy being enforced.
    /// - `gate_tag`: the PDA seed, re-derived here from the three values above so
    ///   the marker address commits to the policy rather than merely to the fact
    ///   that some gate ran.
    #[instruction]
    pub fn gated_check(
        #[account(init, pda = arg("gate_tag"))]
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
        gate_tag: [u8; 32],
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

        // 6. Bind the attested account to the signing account.
        //
        //    This is the hinge of the whole gate, and its absence made every
        //    check below it decorative. The witness names an account through
        //    `npk`/`identifier`; the anchored balance lives on `presenter`.
        //    Unless the two are the same account, comparing the presenter's
        //    balance against the floor says nothing about the account whose
        //    balance was attested, and a caller could attest over any fabricated
        //    account while signing with a funded one.
        if presenter.account_id.value() != &account_id {
            return Err(SpelError::custom(
                E_PRESENTER_NOT_ATTESTED,
                "the signing account is not the account the witness attests to",
            ));
        }

        // 7. Pin which program's balance semantics the gate is trusting.
        //
        //    `Account::balance` is a bare u128 whose meaning belongs to the
        //    owning program, so "holds at least N" is only well defined once the
        //    owner is named. Without this the gate would read the balance field
        //    of an arbitrary program's account and call the number a token
        //    balance.
        if presenter.account.program_owner != AUTHENTICATED_TRANSFER_PROGRAM_ID {
            return Err(SpelError::custom(
                E_PRESENTER_NOT_NATIVE,
                "the presenter account is not owned by the pinned token program",
            ));
        }

        // 8. The anchored balance check, now that it refers to the attested account.
        //
        //    The witness's `balance` is caller-supplied, and so is its
        //    `merkle_root`: the circuit only checks that the caller's own path
        //    folds to the caller's own root, so a prover can invent a one-leaf
        //    tree holding any balance. That check alone proves possession of a
        //    key over a self-declared account, not a balance.
        //
        //    `presenter.account.balance` is different. On the privacy path, a
        //    private account appearing as an authorized pre_state has its
        //    commitment computed by LEZ from this exact state and folded against
        //    the caller's membership proof into a CommitmentSetDigest
        //    (`privacy_preserving_circuit/src/output.rs:307-315`), which the
        //    sequencer then requires to be in `root_history`
        //    (`lee/state_machine/src/state.rs:302-306`). A fabricated membership
        //    proof yields a digest that is not a historical root, and the
        //    transaction is rejected. So this balance is anchored to real chain
        //    state and cannot be invented.
        if presenter.account.balance < minimum_threshold {
            return Err(SpelError::custom(
                E_ANCHORED_BALANCE_TOO_LOW,
                "the attested account's on-chain balance is below the gate's minimum",
            ));
        }

        // 9. Bind the enforced policy into the marker address.
        //
        //    Every argument above is caller-chosen, and a privacy transaction
        //    publishes no instruction data, so a marker seeded by the nullifier
        //    alone would record that *a* gate ran without recording what it
        //    demanded. Deriving the seed from the floor and the context makes the
        //    PDA address itself the statement: a marker earned at
        //    `minimum_threshold = 0` lands at a different address than one earned
        //    at 1000, so an integrator checking the address for their own policy
        //    cannot be handed a weaker one.
        let expected_tag = attestation_core::compute_gate_tag(
            &nullifier,
            minimum_threshold,
            &expected_context_id,
        );
        if expected_tag != gate_tag {
            return Err(SpelError::custom(
                E_GATE_TAG_MISMATCH,
                "gate_tag does not commit to the enforced threshold and context",
            ));
        }

        // 10. Declare the chained call. The privacy circuit will execute and
        //    prove the attestation program, then discharge the assumption with
        //    env::verify over its ProgramOutput. Merkle membership and the
        //    balance comparison are proved there, in zero knowledge.
        let instruction = attestation_core::AttestInstruction { witness, statement };
        let chained = vec![nssa_core::program::ChainedCall::new(
            ATTESTATION_LEZ_PROGRAM_ID,
            Vec::new(), // the attestation program reads no accounts
            &instruction,
        )];

        // 11. Claim the marker PDA and pass the presenter through unchanged.
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
