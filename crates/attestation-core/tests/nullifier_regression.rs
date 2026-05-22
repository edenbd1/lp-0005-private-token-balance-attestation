//! Pin the LP-0005 nullifier scheme against a known vector so we can detect any drift
//! introduced by accidentally renaming the prefix or reordering inputs.

use attestation_core::compute_nullifier;
use sha2::{Digest, Sha256};

#[test]
fn nullifier_matches_hand_computed_vector() {
    let presenter_pubkey: [u8; 33] = [0xAA; 33];
    let context_id: [u8; 32] = [0xBB; 32];
    let account_id: [u8; 32] = [0xCC; 32];

    // Hand-rolled expectation: SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id || account_id).
    let prefix: [u8; 32] = [
        b'/', b'l', b'p', b'-', b'0', b'0', b'0', b'5', b'/', b'v', b'0', b'.', b'1', b'/', b'N',
        b'u', b'l', b'l', b'i', b'f', b'i', b'e', b'r', b'/', 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut h = Sha256::new();
    h.update(prefix);
    h.update(presenter_pubkey);
    h.update(context_id);
    h.update(account_id);
    let expected: [u8; 32] = h.finalize().into();

    let got = compute_nullifier(&presenter_pubkey, &context_id, &account_id);
    assert_eq!(got, expected);
}

#[test]
fn nullifier_distinguishes_context() {
    let pk = [0xAA; 33];
    let aid = [0xCC; 32];
    let n1 = compute_nullifier(&pk, &[0x01; 32], &aid);
    let n2 = compute_nullifier(&pk, &[0x02; 32], &aid);
    assert_ne!(
        n1, n2,
        "different context_ids must yield different nullifiers"
    );
}

#[test]
fn nullifier_distinguishes_presenter() {
    let ctx = [0x01; 32];
    let aid = [0xCC; 32];
    let n1 = compute_nullifier(&[0xAA; 33], &ctx, &aid);
    let n2 = compute_nullifier(&[0xBB; 33], &ctx, &aid);
    assert_ne!(
        n1, n2,
        "different presenter pubkeys must yield different nullifiers"
    );
}
