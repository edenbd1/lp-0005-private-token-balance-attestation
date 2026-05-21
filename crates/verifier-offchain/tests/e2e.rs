//! End-to-end off-chain happy path:
//!   1. SDK proves an attestation for `balance >= threshold`
//!   2. Off-chain verifier accepts the receipt
//!   3. Presenter signs a verifier challenge
//!   4. Verifier accepts the bound signature
//!   5. Forwarded proof (different presenter signing) is rejected

use attestation_sdk::{precompute_leaf, prove, synthetic_merkle_path, PresenterKey, ProveRequest};
use attestation_verifier_offchain::{verify_credential, VerifyError};
use sha2::{Digest, Sha256};

const TREE_DEPTH: usize = 5;

fn sha(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn build_request(presenter_pubkey: [u8; 33], balance: u128, threshold: u128) -> ProveRequest {
    let npk = [0x33_u8; 32];
    let identifier: u128 = 1;
    let program_owner = [0x11_22_33_44_u32; 8];
    let nonce: u128 = 7;
    let data_hash = sha(b"e2e-account-data");
    let mut req = ProveRequest {
        npk,
        identifier,
        program_owner,
        balance,
        nonce,
        data_hash,
        merkle_path: vec![],
        leaf_index: 3,
        merkle_root: [0u8; 32],
        threshold,
        context_id: sha(b"e2e-context"),
        presenter_pubkey,
    };
    let (_commit, leaf_hash) = precompute_leaf(&req);
    let (path, root) = synthetic_merkle_path(&leaf_hash, req.leaf_index, TREE_DEPTH);
    req.merkle_path = path;
    req.merkle_root = root;
    req
}

#[test]
// Marked `e2e_real_proof` so CI can skip when running with no Risc0 acceleration budget.
// `cargo test e2e_real_proof -- --include-ignored` will pick it up locally.
#[ignore = "real STARK proving; opt-in (set RISC0_DEV_MODE=1 to skip proving cost)"]
fn e2e_real_proof_happy_path() {
    let presenter = PresenterKey::generate();
    let req = build_request(presenter.public(), 1_000_000, 100_000);

    let proof = prove(req).expect("proof");
    let nonce = [9u8; 32];
    let sig = presenter.sign(&nonce, &proof.journal);

    let expected_context = proof.journal.context_id;
    let journal = verify_credential(&proof.receipt, &nonce, &sig, &expected_context, 100_000)
        .expect("verify_credential ok");

    assert_eq!(journal.threshold, 100_000);
    assert_eq!(journal.context_id, expected_context);
}

#[test]
#[ignore = "real STARK proving; opt-in"]
fn e2e_real_proof_rejects_forwarded_proof() {
    let alice = PresenterKey::generate();
    let bob = PresenterKey::generate();

    // Alice produces a proof committing to her own pubkey.
    let req = build_request(alice.public(), 1_000_000, 100_000);
    let proof = prove(req).expect("proof");
    let nonce = [9u8; 32];

    // Bob receives the proof and tries to present it. He doesn't have Alice's sk,
    // so he signs with his own. The verifier should reject.
    let bob_sig = bob.sign(&nonce, &proof.journal);
    let expected_context = proof.journal.context_id;
    let err = verify_credential(&proof.receipt, &nonce, &bob_sig, &expected_context, 100_000);
    assert!(matches!(err, Err(VerifyError::SignatureRejected)));
}

#[test]
#[ignore = "real STARK proving; opt-in"]
fn e2e_real_proof_rejects_wrong_context() {
    let presenter = PresenterKey::generate();
    let req = build_request(presenter.public(), 1_000_000, 100_000);
    let proof = prove(req).expect("proof");

    let nonce = [9u8; 32];
    let sig = presenter.sign(&nonce, &proof.journal);

    // A different gate (different context_id) must reject the proof.
    let other_context = sha(b"some-other-gate");
    let err = verify_credential(&proof.receipt, &nonce, &sig, &other_context, 100_000);
    assert!(matches!(err, Err(VerifyError::ContextMismatch)));
}
