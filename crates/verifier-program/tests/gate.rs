//! Unit tests for the portable gate kernel. No Risc0, no LEZ, no SPEL — just the
//! gate semantics that on-chain and off-chain paths share.

use attestation_core::PublicJournal;
use attestation_verifier_program::{
    check_gate, signature::presenter_challenge_digest, GateError, GateInputs,
};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};

fn make_pubkey(sk: &SigningKey) -> [u8; 33] {
    let pt = sk.verifying_key().to_encoded_point(true);
    pt.as_bytes().try_into().expect("33-byte compressed sec1")
}

fn sample_journal(
    presenter_pubkey: [u8; 33],
    context_id: [u8; 32],
    threshold: u128,
) -> PublicJournal {
    PublicJournal {
        merkle_root: [0x11; 32],
        threshold,
        context_id,
        presenter_pubkey,
        nullifier: [0x22; 32],
    }
}

fn sign(sk: &SigningKey, journal: &PublicJournal, nonce: &[u8; 32]) -> Vec<u8> {
    let digest = presenter_challenge_digest(nonce, journal);
    let sig: Signature = sk.sign(&digest);
    sig.to_der().as_bytes().to_vec()
}

#[test]
fn accepts_well_formed_gate() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pk = make_pubkey(&sk);
    let ctx = [0x33; 32];
    let journal = sample_journal(pk, ctx, 100);
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);

    assert!(matches!(
        check_gate(&GateInputs {
            attested: &journal,
            expected_context_id: &ctx,
            minimum_threshold: 100,
            challenge_nonce: &nonce,
            presenter_signature_der: &sig,
        }),
        Ok(())
    ));
}

#[test]
fn rejects_context_mismatch() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pk = make_pubkey(&sk);
    let journal = sample_journal(pk, [0x33; 32], 100);
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);

    let res = check_gate(&GateInputs {
        attested: &journal,
        expected_context_id: &[0xFF; 32], // wrong
        minimum_threshold: 100,
        challenge_nonce: &nonce,
        presenter_signature_der: &sig,
    });
    assert!(matches!(res, Err(GateError::ContextMismatch)));
}

#[test]
fn rejects_threshold_too_low() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pk = make_pubkey(&sk);
    let ctx = [0x33; 32];
    let journal = sample_journal(pk, ctx, 50);
    let nonce = [0x44; 32];
    let sig = sign(&sk, &journal, &nonce);

    let res = check_gate(&GateInputs {
        attested: &journal,
        expected_context_id: &ctx,
        minimum_threshold: 100, // attested 50 < required 100
        challenge_nonce: &nonce,
        presenter_signature_der: &sig,
    });
    assert!(matches!(res, Err(GateError::ThresholdTooLow)));
}

#[test]
fn rejects_signature_from_wrong_presenter() {
    let alice = SigningKey::random(&mut rand::thread_rng());
    let bob = SigningKey::random(&mut rand::thread_rng());
    let alice_pk = make_pubkey(&alice);
    let ctx = [0x33; 32];
    // Alice's pubkey is in the journal, but Bob signs.
    let journal = sample_journal(alice_pk, ctx, 100);
    let nonce = [0x44; 32];
    let bob_sig = sign(&bob, &journal, &nonce);

    let res = check_gate(&GateInputs {
        attested: &journal,
        expected_context_id: &ctx,
        minimum_threshold: 100,
        challenge_nonce: &nonce,
        presenter_signature_der: &bob_sig,
    });
    assert!(matches!(res, Err(GateError::SignatureRejected)));
}

#[test]
fn rejects_signature_for_different_nonce() {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pk = make_pubkey(&sk);
    let ctx = [0x33; 32];
    let journal = sample_journal(pk, ctx, 100);
    let signing_nonce = [0x44; 32];
    let presenter_sig = sign(&sk, &journal, &signing_nonce);

    let res = check_gate(&GateInputs {
        attested: &journal,
        expected_context_id: &ctx,
        minimum_threshold: 100,
        challenge_nonce: &[0x99; 32], // verifier draws a different challenge
        presenter_signature_der: &presenter_sig,
    });
    assert!(matches!(res, Err(GateError::SignatureRejected)));
}
