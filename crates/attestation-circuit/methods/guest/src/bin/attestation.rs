// LP-0005 attestation guest, v1.
//
// Statements proved (all in zero-knowledge):
//   1. account_id = SHA256(PRIVATE_ACCOUNT_ID_PREFIX || npk || identifier_LE)
//   2. commitment = SHA256(COMMITMENT_PREFIX || account_id || program_owner_LE
//                          || balance_LE || nonce_LE || data_hash)
//   3. SHA256(commitment) folds via `merkle_path` to `merkle_root` at `leaf_index`
//   4. balance >= threshold
//   5. nullifier = SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id || account_id)
//
// Public journal: `PublicJournal { merkle_root, threshold, context_id,
//                                  presenter_pubkey, nullifier }`.
// Private witness: `PrivateInputs { npk, identifier, program_owner, balance,
//                                   nonce, data_hash, merkle_path, leaf_index }`.
//
// Identity binding is enforced *outside* the circuit at presentation time: the
// presenter must sign a verifier-supplied challenge under `presenter_pubkey`.

#![no_main]

risc0_zkvm::guest::entry!(main);

use attestation_core::{
    compute_commitment, compute_nullifier, derive_account_id, fold_merkle_path,
    PrivateInputs, PublicJournal,
};
use risc0_zkvm::guest::env;

fn main() {
    let priv_in: PrivateInputs = env::read();
    // The host writes the journal stub with merkle_root, threshold, context_id,
    // presenter_pubkey; nullifier is filled in by the circuit.
    let mut journal: PublicJournal = env::read();

    let account_id = derive_account_id(&priv_in.npk, priv_in.identifier);

    let leaf_commitment = compute_commitment(
        &account_id,
        &priv_in.program_owner,
        priv_in.balance,
        priv_in.nonce,
        &priv_in.data_hash,
    );

    // LEZ hashes leaves once before insertion into the commitment set
    // (_external/lez/nssa/src/merkle_tree/mod.rs:146-157).
    let leaf_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(leaf_commitment);
        h.finalize().into()
    };

    let recovered_root = fold_merkle_path(&leaf_hash, priv_in.leaf_index, &priv_in.merkle_path);
    assert_eq!(
        recovered_root, journal.merkle_root,
        "merkle path does not anchor to the claimed root",
    );

    assert!(
        priv_in.balance >= journal.threshold,
        "balance is below the attested threshold",
    );

    journal.nullifier =
        compute_nullifier(&journal.presenter_pubkey, &journal.context_id, &account_id);

    env::commit(&journal);
}
