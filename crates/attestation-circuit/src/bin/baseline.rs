//! Baseline harness for the LP-0005 attestation guest.
//!
//! Build:    `cargo build --release -p attestation-circuit --bin baseline`
//! Run dev:  `RISC0_DEV_MODE=1 ./target/release/baseline`     (fast, no proof)
//! Run prod: `RISC0_DEV_MODE=0 ./target/release/baseline`     (real STARK)
//!
//! Prints proving time, receipt size, verification time, and the journal.

use anyhow::Result;
use attestation_circuit::{
    compute_commitment, compute_nullifier, derive_account_id, fold_merkle_path, PrivateInputs,
    PublicJournal,
};
use attestation_methods::{ATTESTATION_ELF, ATTESTATION_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use sha2::{Digest, Sha256};
use std::time::Instant;

const TREE_DEPTH: usize = 5; // matches LEZ genesis capacity 32 → depth 5

fn main() -> Result<()> {
    let (priv_in, journal_stub) = synth_inputs();

    let env = ExecutorEnv::builder()
        .write(&priv_in)?
        .write(&journal_stub)?
        .build()?;

    println!("== LP-0005 attestation baseline ==");
    println!(
        "dev_mode: RISC0_DEV_MODE={}",
        std::env::var("RISC0_DEV_MODE").unwrap_or_else(|_| "(unset)".into())
    );
    println!("tree_depth: {TREE_DEPTH}");
    println!("threshold: {}", journal_stub.threshold);
    println!("balance:   {}", priv_in.balance);

    let prover = default_prover();

    let t = Instant::now();
    let prove_info = prover.prove_with_opts(env, ATTESTATION_ELF, &ProverOpts::default())?;
    let prove_elapsed = t.elapsed();
    let receipt = prove_info.receipt;

    let receipt_bytes = bincode::serde::encode_to_vec(&receipt, bincode::config::standard())?;
    println!("prove:     {:?}", prove_elapsed);
    println!("receipt:   {} bytes", receipt_bytes.len());

    let t = Instant::now();
    receipt.verify(ATTESTATION_ID)?;
    println!("verify:    {:?}", t.elapsed());

    let journal: PublicJournal = receipt.journal.decode()?;
    println!("journal:");
    println!("  merkle_root:      0x{}", hex::encode(journal.merkle_root));
    println!("  threshold:        {}", journal.threshold);
    println!("  context_id:       0x{}", hex::encode(journal.context_id));
    println!(
        "  presenter_pubkey: 0x{}",
        hex::encode(journal.presenter_pubkey)
    );
    println!("  nullifier:        0x{}", hex::encode(journal.nullifier));
    Ok(())
}

fn synth_inputs() -> (PrivateInputs, PublicJournal) {
    let npk = [0x33_u8; 32];
    let identifier: u128 = 42;
    let program_owner = [0x11_22_33_44_u32; 8];
    let balance: u128 = 1_000_000;
    let nonce: u128 = 7;
    let data_hash = sha256(b"fixture-account-data");

    let account_id = derive_account_id(&npk, identifier);
    let leaf_commit = compute_commitment(&account_id, &program_owner, balance, nonce, &data_hash);
    let leaf_hash = sha256(&leaf_commit);

    let mut path: Vec<[u8; 32]> = Vec::with_capacity(TREE_DEPTH);
    for i in 0..TREE_DEPTH {
        path.push(sha256(&[i as u8; 32]));
    }
    let leaf_index: u64 = 3;
    let merkle_root = fold_merkle_path(&leaf_hash, leaf_index, &path);

    let presenter_pubkey = [0x02; 33];
    let context_id = sha256(b"lp-0005-baseline-context");
    // The host pre-fills `nullifier` here only so the wire format matches the
    // guest's `env::read` shape; the guest overwrites it from circuit inputs.
    let expected_nullifier = compute_nullifier(&presenter_pubkey, &context_id, &account_id);

    let priv_in = PrivateInputs {
        npk,
        identifier,
        program_owner,
        balance,
        nonce,
        data_hash,
        merkle_path: path,
        leaf_index,
    };
    let journal = PublicJournal {
        merkle_root,
        threshold: 100_000,
        context_id,
        presenter_pubkey,
        nullifier: expected_nullifier,
    };
    (priv_in, journal)
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}
