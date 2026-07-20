//! The root-freshness check, against the live public testnet.
//!
//! An attestation's `merkle_root` is prover-chosen: nothing in the circuit or the
//! sequencer ties it to real chain state, so a prover can invent a tree holding
//! any balance. `docs/limitations.md` says so plainly. This is the API that lets
//! a verifier close the gap, and these tests prove it works against the real
//! chain rather than a fixture.
//!
//! Run with: `cargo test -p attestation-sequencer-client --test root_freshness -- --ignored`

use attestation_sequencer_client::{fold_membership_proof, MembershipProof, SequencerClient};

/// A commitment known to be in the public testnet's set: the private account
/// funded on 2026-07-20, whose membership proof anchors the attestation used by
/// the deep gate. Recomputed by `crates/cu-bench/tests/real_chain_attestation.rs`
/// from the account's own npk, identifier, balance, nonce and data hash.
const KNOWN_COMMITMENT: [u8; 32] = [
        0x74, 0x09, 0xcd, 0x5c, 0xac, 0x88, 0xe3, 0x1f, 0xfd, 0xe8, 0x2a, 0x9e, 0x5d, 0x4a, 0x2a,
        0x8f, 0xef, 0xdd, 0x89, 0xfa, 0xca, 0x05, 0x06, 0xb2, 0x32, 0x3d, 0xd8, 0x55, 0x5e, 0x3f,
    0xd6, 0x68,
];

/// Folding is the inverse of the tree: a one-element path must reproduce the
/// parent hash, and the sibling side must follow the index bit.
#[test]
fn folding_follows_the_index_bit() {
    use sha2::{Digest, Sha256};
    let commitment = [1u8; 32];
    let sibling = [2u8; 32];
    let leaf: [u8; 32] = Sha256::digest(commitment).into();

    // Even index: our node goes on the left.
    let left = fold_membership_proof(
        &commitment,
        &MembershipProof {
            leaf_index: 0,
            siblings: vec![sibling],
        },
    );
    let mut h = Sha256::new();
    h.update(leaf);
    h.update(sibling);
    assert_eq!(left, <[u8; 32]>::from(h.finalize()));

    // Odd index: our node goes on the right.
    let right = fold_membership_proof(
        &commitment,
        &MembershipProof {
            leaf_index: 1,
            siblings: vec![sibling],
        },
    );
    let mut h = Sha256::new();
    h.update(sibling);
    h.update(leaf);
    assert_eq!(right, <[u8; 32]>::from(h.finalize()));

    assert_ne!(left, right, "the index bit must change the result");
}

/// An empty path means the leaf is the root.
#[test]
fn an_empty_path_yields_the_hashed_leaf() {
    use sha2::{Digest, Sha256};
    let commitment = [9u8; 32];
    let folded = fold_membership_proof(
        &commitment,
        &MembershipProof {
            leaf_index: 0,
            siblings: vec![],
        },
    );
    assert_eq!(folded, <[u8; 32]>::from(Sha256::digest(commitment)));
}

#[tokio::test]
#[ignore = "hits the public testnet"]
async fn derives_the_current_root_from_the_live_chain() {
    let client = SequencerClient::public_testnet();
    let root = client
        .commitment_set_root(&KNOWN_COMMITMENT)
        .await
        .expect("RPC call failed")
        .expect("the known commitment should still be in the set");

    assert_ne!(root, [0u8; 32], "a real root is not all zeros");
    println!("current commitment-set root: {}", hex::encode(root));
}

/// The point of the whole exercise: a root the prover invented must be rejected.
#[tokio::test]
#[ignore = "hits the public testnet"]
async fn rejects_a_root_the_prover_invented() {
    let client = SequencerClient::public_testnet();

    // A one-leaf tree over a fabricated commitment. This is exactly the shape an
    // attacker uses to attest to a balance they do not hold: the circuit accepts
    // it, because the path folds to the root consistently.
    let fabricated_commitment = [0xABu8; 32];
    let invented_root = fold_membership_proof(
        &fabricated_commitment,
        &MembershipProof {
            leaf_index: 0,
            siblings: vec![],
        },
    );

    assert!(
        !client
            .is_root_current(&invented_root, &KNOWN_COMMITMENT)
            .await
            .expect("RPC call failed"),
        "an invented root must not pass the freshness check"
    );

    // And the real root must pass, so the check is not simply refusing everything.
    let real_root = client
        .commitment_set_root(&KNOWN_COMMITMENT)
        .await
        .expect("RPC call failed")
        .expect("known commitment should be in the set");
    assert!(
        client
            .is_root_current(&real_root, &KNOWN_COMMITMENT)
            .await
            .expect("RPC call failed"),
        "the root derived from the chain must pass its own check"
    );
}
