//! End-to-end proof that the attestation works against **real LEZ chain state**,
//! not a synthesised witness.
//!
//! `crates/cli/src/bin/attest.rs` currently builds proofs over
//! `attestation_sdk::synthetic_merkle_path`, so the balance is a number the
//! prover types in and the Merkle root is invented. Nothing checks the account
//! actually exists on chain. This test closes that gap.
//!
//! It consumes a witness captured from a live LEZ sequencer:
//!   * the account id recomputed from the wallet's real `npk` and identifier,
//!     which must equal the account id the wallet itself reports;
//!   * the commitment recomputed from the account's real `program_owner`,
//!     `balance`, `nonce` and data hash;
//!   * the Merkle path and leaf index returned by the sequencer's own
//!     `getProofForCommitment`.
//!
//! Then it runs the LEZ-native attestation program over that witness through the
//! sequencer's execution path and requires a decodable `ProgramOutput`.
//!
//! Capture a fresh witness with `scripts/capture-witness.py` against a running
//! sequencer. The committed fixture came from a standalone chain where a private
//! account held 3000 tokens.

use attestation_core::{
    attest, compute_commitment, derive_account_id, fold_merkle_path, AttestInstruction,
    AttestStatement, PrivateInputs,
};
use lee_core::program::{ProgramId, ProgramOutput};
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32;
const ELF_PATH: &str =
    "../attestation-circuit/methods/guest-lez/target/riscv32im-risc0-zkvm-elf/docker/attestation_lez.bin";
const FIXTURE: &str = "tests/fixtures/real_chain_witness.json";

/// A witness captured from a live sequencer.
#[derive(Deserialize)]
struct CapturedWitness {
    npk: [u8; 32],
    identifier: u128,
    program_owner: [u32; 8],
    balance: u128,
    nonce: u128,
    data_hash: [u8; 32],
    merkle_path: Vec<[u8; 32]>,
    leaf_index: u64,
    /// The root the captured path folds to, recorded at capture time.
    merkle_root: [u8; 32],
    /// The account id the wallet reported, base58. Cross-checks our derivation.
    account_id_base58: String,
}

fn load() -> CapturedWitness {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("fixture is not the expected shape")
}

fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = byte as usize;
        for d in digits.iter_mut() {
            carry += (*d as usize) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = String::new();
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

/// Our `derive_account_id` must reproduce the account id LEZ itself assigned.
/// If this drifts, every commitment we build is anchored to the wrong leaf.
#[test]
fn derived_account_id_matches_the_chain() {
    let w = load();
    let derived = derive_account_id(&w.npk, w.identifier);
    assert_eq!(
        base58(&derived),
        w.account_id_base58,
        "derive_account_id disagrees with the account id the LEZ wallet assigned"
    );
}

/// The commitment we compute must be the one the sequencer indexed, which is
/// implied by the fact that `getProofForCommitment` returned a path for it at
/// capture time, and confirmed here by the path folding to the recorded root.
#[test]
fn commitment_anchors_to_the_chain_root() {
    let w = load();
    let account_id = derive_account_id(&w.npk, w.identifier);
    let commitment = compute_commitment(
        &account_id,
        &w.program_owner,
        w.balance,
        w.nonce,
        &w.data_hash,
    );
    let leaf_hash: [u8; 32] = Sha256::digest(commitment).into();
    let root = fold_merkle_path(&leaf_hash, w.leaf_index, &w.merkle_path);
    assert_eq!(
        root, w.merkle_root,
        "the sequencer's own membership proof does not fold to the recorded root"
    );
}

/// The whole point: the LEZ-native attestation program accepts a witness taken
/// from real chain state, executed the way the sequencer executes it.
#[test]
fn lez_program_accepts_a_real_chain_witness() {
    let w = load();
    let threshold = 1_000; // the captured account held 3000

    let witness = PrivateInputs {
        npk: w.npk,
        identifier: w.identifier,
        program_owner: w.program_owner,
        balance: w.balance,
        nonce: w.nonce,
        data_hash: w.data_hash,
        merkle_path: w.merkle_path.clone(),
        leaf_index: w.leaf_index,
    };
    let statement = AttestStatement {
        merkle_root: w.merkle_root,
        threshold,
        context_id: [42u8; 32],
        presenter_pubkey: [2u8; 33],
    };

    // Sanity: the shared logic accepts it before we pay for a zkVM run.
    let _nullifier = attest(&witness, &statement);

    let instruction = AttestInstruction { witness, statement };
    let elf = {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ELF_PATH);
        std::fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
    };

    let program_id: ProgramId = risc0_binfmt::ProgramBinary::decode(&elf)
        .unwrap()
        .compute_image_id()
        .unwrap()
        .into();
    let caller: Option<ProgramId> = None;
    let pre_states: Vec<lee_core::account::AccountWithMetadata> = Vec::new();
    let instruction_data = risc0_zkvm::serde::to_vec(&instruction).unwrap();

    let mut b = ExecutorEnv::builder();
    b.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
    b.write(&program_id).unwrap();
    b.write(&caller).unwrap();
    b.write(&pre_states).unwrap();
    b.write(&instruction_data).unwrap();

    let session = default_executor()
        .execute(b.build().unwrap(), &elf)
        .expect("the attestation must execute over real chain state");
    let output: ProgramOutput = session
        .journal
        .decode()
        .expect("journal must decode as a LEZ ProgramOutput");
    assert_eq!(output.self_program_id, program_id);
}

/// The same real account cannot attest to more than it holds.
#[test]
fn real_chain_witness_cannot_overstate_its_balance() {
    let w = load();
    let witness = PrivateInputs {
        npk: w.npk,
        identifier: w.identifier,
        program_owner: w.program_owner,
        balance: w.balance,
        nonce: w.nonce,
        data_hash: w.data_hash,
        merkle_path: w.merkle_path.clone(),
        leaf_index: w.leaf_index,
    };
    let statement = AttestStatement {
        merkle_root: w.merkle_root,
        threshold: w.balance + 1, // one more than the account actually holds
        context_id: [42u8; 32],
        presenter_pubkey: [2u8; 33],
    };
    let result = std::panic::catch_unwind(|| attest(&witness, &statement));
    assert!(
        result.is_err(),
        "attesting above the real on-chain balance must fail"
    );
}
