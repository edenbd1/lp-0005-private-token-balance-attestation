//! End-to-end test: a real Risc0 attestation gates entry to a chat group.
//! Marked #[ignore = "real STARK proving"] so the default `cargo test` stays fast.

use attestation_sdk::{precompute_leaf, prove, synthetic_merkle_path, PresenterKey, ProveRequest};
use chat_gate::{group_context_id, AdmissionError, GroupRoster};
use sha2::{Digest, Sha256};

const TREE_DEPTH: usize = 5;

fn sha(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn make_request(
    presenter_pubkey: [u8; 33],
    group_id: &str,
    balance: u128,
    threshold: u128,
) -> ProveRequest {
    let npk = [0x33_u8; 32];
    let identifier: u128 = 1;
    let program_owner = [0x11_22_33_44_u32; 8];
    let nonce: u128 = 7;
    let data_hash = sha(b"chat-gate-fixture");
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
        context_id: group_context_id(group_id),
        presenter_pubkey,
    };
    let (_commit, leaf_hash) = precompute_leaf(&req);
    let (path, root) = synthetic_merkle_path(&leaf_hash, req.leaf_index, TREE_DEPTH);
    req.merkle_path = path;
    req.merkle_root = root;
    req
}

#[test]
#[ignore = "real STARK proving"]
fn admits_eligible_member() {
    let presenter = PresenterKey::generate();
    let req = make_request(presenter.public(), "salon-vip", 1_000_000, 100_000);
    let proof = prove(req).expect("proof");
    let nonce = [0x9C; 32];
    let sig = presenter.sign(&nonce, &proof.journal);

    let mut roster = GroupRoster::new("salon-vip", 100_000);
    let journal = roster.admit(&proof.receipt, &nonce, &sig).expect("admit");
    assert!(roster.members.contains(&journal.presenter_pubkey));
}

#[test]
#[ignore = "real STARK proving"]
fn rejects_proof_for_different_group() {
    let presenter = PresenterKey::generate();
    // attestation bound to group "salon-vip"
    let req = make_request(presenter.public(), "salon-vip", 1_000_000, 100_000);
    let proof = prove(req).expect("proof");
    let nonce = [0x9C; 32];
    let sig = presenter.sign(&nonce, &proof.journal);

    // group "other-room" tries to admit
    let mut roster = GroupRoster::new("other-room", 100_000);
    let result = roster.admit(&proof.receipt, &nonce, &sig);
    assert!(matches!(result, Err(AdmissionError::Verify(_))));
}
