//! Pure-state tests for premium-features. No Risc0; we synthesize journals.

use attestation_core::PublicJournal;
use attestation_verifier_program::signature::presenter_challenge_digest;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use premium_features::Tier;

fn pk(sk: &SigningKey) -> [u8; 33] {
    let p = sk.verifying_key().to_encoded_point(true);
    p.as_bytes().try_into().unwrap()
}

#[test]
fn tier_context_ids_are_distinct() {
    let f = Tier::Free.context_id();
    let p = Tier::Pro.context_id();
    let e = Tier::Enterprise.context_id();
    assert_ne!(f, p);
    assert_ne!(p, e);
    assert_ne!(f, e);
}

#[test]
fn tier_minimum_balances_are_monotonic() {
    assert!(Tier::Free.minimum_balance() < Tier::Pro.minimum_balance());
    assert!(Tier::Pro.minimum_balance() < Tier::Enterprise.minimum_balance());
}

// A round-trip activation test that does not need a real proof — we cannot easily
// fake `Receipt::verify`, so the activate() call itself is exercised via the e2e
// integration test in chat-gate. This file pins tier-shape invariants.

#[test]
fn challenge_digest_distinguishes_journal_threshold() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pubkey = pk(&sk);
    let nonce = [0x42; 32];

    let mut j1 = PublicJournal {
        merkle_root: [0u8; 32],
        threshold: 100,
        context_id: Tier::Pro.context_id(),
        presenter_pubkey: pubkey,
        nullifier: [0u8; 32],
    };
    let d1 = presenter_challenge_digest(&nonce, &j1);
    j1.threshold = 1000;
    let d2 = presenter_challenge_digest(&nonce, &j1);
    assert_ne!(d1, d2, "challenge digest must bind to threshold");
}
