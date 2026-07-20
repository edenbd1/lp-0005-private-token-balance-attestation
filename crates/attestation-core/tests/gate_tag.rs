//! The gate marker seed must commit to the policy that was enforced.
//!
//! Background: an adversarial review of the deep gate found that a marker seeded
//! by the nullifier alone recorded only *that* a gate ran. Since
//! `minimum_threshold` and `expected_context_id` are instruction arguments, and a
//! privacy-preserving transaction publishes no instruction data
//! (`lee/state_machine/src/privacy_preserving_transaction/message.rs:14-24`), an
//! attacker pinning the floor to zero produced a marker byte-identical to one
//! earned against a real floor. Any integrator consuming the marker as a
//! credential was bypassed.
//!
//! `compute_gate_tag` closes that by folding the floor and the context into the
//! PDA seed, so the marker's *address* is the policy. These tests pin that
//! property: change what was demanded, and you land on a different address.

use attestation_core::compute_gate_tag;

const NULLIFIER: [u8; 32] = [0x11; 32];
const CONTEXT: [u8; 32] = [0x22; 32];

/// The attack the review described, reduced to its arithmetic: the attacker
/// enforces nothing, the honest gate enforces 1000. If both landed on the same
/// address the marker would be worthless.
#[test]
fn a_zero_floor_marker_cannot_stand_in_for_a_real_one() {
    let attacker = compute_gate_tag(&NULLIFIER, 0, &CONTEXT);
    let honest = compute_gate_tag(&NULLIFIER, 1000, &CONTEXT);

    assert_ne!(
        attacker, honest,
        "a gate enforcing nothing must not produce the marker of a gate enforcing 1000"
    );
}

/// Off-by-one matters: an integrator demanding 1000 must not accept a marker
/// earned at 999.
#[test]
fn adjacent_thresholds_are_distinct() {
    assert_ne!(
        compute_gate_tag(&NULLIFIER, 999, &CONTEXT),
        compute_gate_tag(&NULLIFIER, 1000, &CONTEXT)
    );
}

/// A marker earned at one gate must not be presentable at another, even by the
/// same account at the same floor.
#[test]
fn context_separates_gates() {
    let gate_a = compute_gate_tag(&NULLIFIER, 1000, &[0xAA; 32]);
    let gate_b = compute_gate_tag(&NULLIFIER, 1000, &[0xBB; 32]);

    assert_ne!(gate_a, gate_b, "two gates must not share a marker address");
}

/// Different attestations, same policy: still distinct, because the nullifier is
/// what carries the account identity. Without this the replay guard would collide
/// across users.
#[test]
fn distinct_attestations_yield_distinct_markers() {
    assert_ne!(
        compute_gate_tag(&[0x01; 32], 1000, &CONTEXT),
        compute_gate_tag(&[0x02; 32], 1000, &CONTEXT)
    );
}

/// The seed must be a pure function of its inputs, or the guest could not
/// re-derive and check what the caller supplied.
#[test]
fn the_tag_is_deterministic() {
    assert_eq!(
        compute_gate_tag(&NULLIFIER, 1000, &CONTEXT),
        compute_gate_tag(&NULLIFIER, 1000, &CONTEXT)
    );
}

/// The tag is domain-separated from the nullifier. If the two derivations could
/// collide, a tag might be mistaken for a nullifier somewhere downstream.
#[test]
fn the_tag_never_collides_with_a_nullifier() {
    use attestation_core::{compute_nullifier, GATE_TAG_PREFIX, NULLIFIER_PREFIX};

    assert_ne!(
        GATE_TAG_PREFIX, NULLIFIER_PREFIX,
        "the two derivations must be domain-separated"
    );

    let pubkey = [0x02u8; 33];
    let account_id = [0x33u8; 32];
    let nullifier = compute_nullifier(&pubkey, &CONTEXT, &account_id);
    let tag = compute_gate_tag(&nullifier, 1000, &CONTEXT);

    assert_ne!(tag, nullifier);
}

/// The floor is folded in as little-endian u128. Pinning the encoding keeps the
/// host and the guest in agreement: they derive the same tag from the same
/// policy, and a mismatch is what rejects a forged seed.
#[test]
fn the_encoding_is_pinned() {
    use sha2::{Digest, Sha256};
    use attestation_core::GATE_TAG_PREFIX;

    let mut h = Sha256::new();
    h.update(GATE_TAG_PREFIX);
    h.update(NULLIFIER);
    h.update(1000u128.to_le_bytes());
    h.update(CONTEXT);
    let expected: [u8; 32] = h.finalize().into();

    assert_eq!(compute_gate_tag(&NULLIFIER, 1000, &CONTEXT), expected);
}
