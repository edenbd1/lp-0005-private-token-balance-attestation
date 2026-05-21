//! Sanity-check `fold_merkle_path`: hand-rolled tree of depth 2 with a known leaf
//! position, recompute by hand, compare. Mirrors the LEZ convention
//! `hash_two(L, R) = SHA256(L || R)` from `_external/lez/nssa/src/merkle_tree/mod.rs:146-157`.

use attestation_core::fold_merkle_path;
use sha2::{Digest, Sha256};

fn h(b: &[u8]) -> [u8; 32] {
    let mut x = Sha256::new();
    x.update(b);
    x.finalize().into()
}

fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut x = Sha256::new();
    x.update(l);
    x.update(r);
    x.finalize().into()
}

#[test]
fn depth_2_left_left_leaf() {
    // Leaves at depth 2: positions 0..=3.
    // Tree:        root
    //             /    \
    //         L01      L23
    //         /  \    /   \
    //        L0  L1  L2   L3
    let l0 = h(b"leaf-0");
    let l1 = h(b"leaf-1");
    let l2 = h(b"leaf-2");
    let l3 = h(b"leaf-3");

    let l01 = h2(&l0, &l1);
    let l23 = h2(&l2, &l3);
    let root = h2(&l01, &l23);

    // Proof for leaf 0: siblings are (l1, l23).
    let proof = vec![l1, l23];
    let got = fold_merkle_path(&l0, 0, &proof);
    assert_eq!(got, root);
}

#[test]
fn depth_2_right_left_leaf() {
    let l0 = h(b"leaf-0");
    let l1 = h(b"leaf-1");
    let l2 = h(b"leaf-2");
    let l3 = h(b"leaf-3");

    let l01 = h2(&l0, &l1);
    let l23 = h2(&l2, &l3);
    let root = h2(&l01, &l23);

    // Proof for leaf 2 (binary index 10): siblings are (l3, l01).
    let proof = vec![l3, l01];
    let got = fold_merkle_path(&l2, 2, &proof);
    assert_eq!(got, root);
}
