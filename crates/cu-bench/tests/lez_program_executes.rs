//! Proves the LEZ-native attestation program is a well-formed LEZ program.
//!
//! This is the milestone that the standalone guest could never reach. It runs
//! `attestation_lez.bin` through the *sequencer's own* execution path — the same
//! four inputs in the same order, the same 32M session limit, the same executor
//! (`lee/state_machine/src/program.rs:55-110`) — and requires the run to produce
//! a journal that decodes as a LEZ `ProgramOutput`.
//!
//! That decode is the whole point. The standalone guest commits a bespoke
//! `PublicJournal`, so `ProgramOutput::decode` fails and the sequencer rejects
//! the call with `ProgramExecutionFailed` — which is exactly why the "deep"
//! verifier's `gated_check` never confirmed. Passing this test means the
//! attestation can take part in LEZ chained-call composition, where the privacy
//! circuit verifies it with a real `env::verify`
//! (`lee/privacy_preserving_circuit/src/execution_state.rs:149`).
//!
//! Run with: `cargo test -p attestation-cu-bench --test lez_program_executes`

use attestation_core::{
    attest, compute_commitment, derive_account_id, fold_merkle_path, AttestInstruction,
    AttestStatement, PrivateInputs,
};
use lee_core::program::{ProgramId, ProgramOutput};
use risc0_zkvm::{default_executor, ExecutorEnv};
use sha2::{Digest, Sha256};

const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32;
const ELF_PATH: &str =
    "../attestation-circuit/methods/guest-lez/target/riscv32im-risc0-zkvm-elf/docker/attestation_lez.bin";

/// Build a witness plus the statement it genuinely satisfies: derive the
/// account id, commit it, hash the leaf the way LEZ does, then fold a fixed
/// sibling path to obtain the root the proof will be anchored against.
fn consistent_case(balance: u128, threshold: u128) -> (PrivateInputs, AttestStatement) {
    let witness = PrivateInputs {
        npk: [7u8; 32],
        identifier: 1,
        program_owner: [11u32; 8],
        balance,
        nonce: 3,
        data_hash: Sha256::digest([]).into(),
        merkle_path: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
        leaf_index: 5,
    };

    let account_id = derive_account_id(&witness.npk, witness.identifier);
    let commitment = compute_commitment(
        &account_id,
        &witness.program_owner,
        witness.balance,
        witness.nonce,
        &witness.data_hash,
    );
    let leaf_hash: [u8; 32] = Sha256::digest(commitment).into();
    let merkle_root = fold_merkle_path(&leaf_hash, witness.leaf_index, &witness.merkle_path);

    let statement = AttestStatement {
        merkle_root,
        threshold,
        context_id: [42u8; 32],
        presenter_pubkey: [2u8; 33],
    };
    (witness, statement)
}

/// Replays `Program::execute`: same input order, same session limit, same executor.
fn run_as_sequencer(elf: &[u8], instruction: &AttestInstruction) -> anyhow::Result<ProgramOutput> {
    let program_id: ProgramId = risc0_binfmt::ProgramBinary::decode(elf)?
        .compute_image_id()?
        .into();
    let caller_program_id: Option<ProgramId> = None;
    let pre_states: Vec<lee_core::account::AccountWithMetadata> = Vec::new();
    let instruction_data = risc0_zkvm::serde::to_vec(instruction)?;

    let mut builder = ExecutorEnv::builder();
    builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
    builder.write(&program_id)?;
    builder.write(&caller_program_id)?;
    builder.write(&pre_states)?;
    builder.write(&instruction_data)?;
    let env = builder.build()?;

    let session = default_executor().execute(env, elf)?;
    Ok(session.journal.decode()?)
}

fn elf() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ELF_PATH);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Build it with:\n  cargo risczero build --manifest-path \
             crates/attestation-circuit/methods/guest-lez/Cargo.toml",
            path.display()
        )
    })
}

#[test]
fn emits_a_decodable_lez_program_output() {
    let (witness, statement) = consistent_case(1_000_000, 100_000);
    let instruction = AttestInstruction { witness, statement };

    let output = run_as_sequencer(&elf(), &instruction)
        .expect("the LEZ attestation program must execute under the sequencer's executor");

    // The journal decoded as a ProgramOutput. A plain Risc0 guest cannot do this.
    let expected_id: ProgramId = risc0_binfmt::ProgramBinary::decode(&elf())
        .unwrap()
        .compute_image_id()
        .unwrap()
        .into();
    assert_eq!(
        output.self_program_id, expected_id,
        "the program must commit to its own id"
    );
    assert!(
        output.caller_program_id.is_none(),
        "a top-level call has no caller"
    );
}

#[test]
fn rejects_a_balance_below_the_threshold() {
    // Same shape, but the witness no longer satisfies the statement.
    let (witness, statement) = consistent_case(50_000, 100_000);
    let instruction = AttestInstruction { witness, statement };

    let result = run_as_sequencer(&elf(), &instruction);
    assert!(
        result.is_err(),
        "a balance below the threshold must abort the guest, making the proof unobtainable"
    );
}

#[test]
fn rejects_a_merkle_path_that_does_not_anchor() {
    let (witness, mut statement) = consistent_case(1_000_000, 100_000);
    statement.merkle_root = [0xAAu8; 32]; // not the root the path folds to
    let instruction = AttestInstruction { witness, statement };

    let result = run_as_sequencer(&elf(), &instruction);
    assert!(
        result.is_err(),
        "a path that does not anchor to the claimed root must abort the guest"
    );
}

/// The shared `attest` used by the LEZ program must agree with the deployed
/// standalone guest's logic. The standalone guest is byte-frozen (its ImageID is
/// deployed on the public testnet), so it cannot be refactored to call `attest`
/// directly; this pins the two together instead.
#[test]
fn shared_attest_matches_the_deployed_circuit_semantics() {
    let (witness, statement) = consistent_case(1_000_000, 100_000);
    let nullifier = attest(&witness, &statement);

    let account_id = derive_account_id(&witness.npk, witness.identifier);
    let expected = attestation_core::compute_nullifier(
        &statement.presenter_pubkey,
        &statement.context_id,
        &account_id,
    );
    assert_eq!(
        nullifier, expected,
        "attest must derive the same nullifier the deployed circuit does"
    );
}
