use attestation_core::PublicJournal;
use attestation_verifier_program::signature::presenter_challenge_digest;
use governance_gate::{cast_vote, ProposalState, VoteError, GOVERNANCE_CONTEXT_ID};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn make_journal(sk: &SigningKey, threshold: u128, nullifier_byte: u8) -> PublicJournal {
    let pk_pt = sk.verifying_key().to_encoded_point(true);
    let mut presenter_pubkey = [0u8; 33];
    presenter_pubkey.copy_from_slice(pk_pt.as_bytes());
    PublicJournal {
        merkle_root: [0x11; 32],
        threshold,
        context_id: GOVERNANCE_CONTEXT_ID,
        presenter_pubkey,
        nullifier: [nullifier_byte; 32],
    }
}

fn sign(sk: &SigningKey, journal: &PublicJournal, nonce: &[u8; 32]) -> Vec<u8> {
    let d = presenter_challenge_digest(nonce, journal);
    let sig: Signature = sk.sign(&d);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn yes_vote_accepted_with_valid_attestation() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let journal = make_journal(&sk, 1000, 0xAA);
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);
    let mut state = ProposalState::default();

    cast_vote(&mut state, &journal, &nonce, &sig, 500, true).expect("vote should pass");

    assert_eq!(state.yes_votes, 1);
    assert_eq!(state.no_votes, 0);
    assert_eq!(state.used_nullifiers.len(), 1);
}

#[test]
fn nullifier_replay_rejected() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let journal = make_journal(&sk, 1000, 0xBB);
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);
    let mut state = ProposalState::default();

    cast_vote(&mut state, &journal, &nonce, &sig, 500, true).expect("first vote ok");

    // Re-sign for a fresh nonce so the signature itself is valid; the nullifier replay
    // is what we are testing.
    let nonce2 = [0x77; 32];
    let sig2 = sign(&sk, &journal, &nonce2);
    let result = cast_vote(&mut state, &journal, &nonce2, &sig2, 500, true);
    assert!(matches!(result, Err(VoteError::NullifierReused)));
    assert_eq!(state.yes_votes, 1);
}

#[test]
fn insufficient_attested_threshold_rejected() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let journal = make_journal(&sk, 100, 0xCC); // attested 100
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);
    let mut state = ProposalState::default();

    let result = cast_vote(&mut state, &journal, &nonce, &sig, 1000, true); // requires 1000
    assert!(matches!(result, Err(VoteError::Gate(_))));
}
