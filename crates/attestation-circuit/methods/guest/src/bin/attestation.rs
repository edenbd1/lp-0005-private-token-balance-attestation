// Baseline LP-0005 attestation guest.
//
// At this stage the circuit performs the load-bearing crypto work so we can
// measure proving cost on the real Risc0 prover (`RISC0_DEV_MODE=0`):
//   1. read private inputs + public params
//   2. reconstruct the LEZ private-account commitment
//   3. fold a Merkle path to a root
//   4. assert `balance >= threshold`
//   5. commit the public journal
//
// Identity binding (signature of a verifier-supplied challenge) and `npk`->`account_id`
// derivation are deferred to a follow-up commit; the cost numbers below already cover
// the dominant SHA-256 work.

#![no_main]

risc0_zkvm::guest::entry!(main);

use attestation_core::{compute_commitment, fold_merkle_path, PrivateInputs, PublicJournal};
use risc0_zkvm::guest::env;

fn main() {
    let priv_in: PrivateInputs = env::read();
    let mut pub_out: PublicJournal = env::read();

    let leaf_commitment = compute_commitment(
        &priv_in.account_id,
        &priv_in.program_owner,
        priv_in.balance,
        priv_in.nonce,
        &priv_in.data_hash,
    );

    // Leaves are SHA256-hashed once before insertion in the commitment set
    // (lez/nssa/src/merkle_tree/mod.rs:146-157).
    let leaf_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(leaf_commitment);
        h.finalize().into()
    };

    let recovered_root = fold_merkle_path(&leaf_hash, priv_in.leaf_index, &priv_in.merkle_path);
    assert_eq!(
        recovered_root, pub_out.merkle_root,
        "merkle path does not anchor to the claimed root",
    );

    assert!(
        priv_in.balance >= pub_out.threshold,
        "balance is below the attested threshold",
    );

    // Echo the public params back into the journal so on-chain & off-chain verifiers
    // both see exactly what was attested. Threshold/context/presenter_pubkey are passed
    // in by the host and re-committed here to bind them into the proof.
    env::commit(&pub_out);

    // Suppress unused_mut on `pub_out` — we may mutate it later when we add
    // derived journal fields (e.g., a nullifier).
    let _ = &mut pub_out;
}
