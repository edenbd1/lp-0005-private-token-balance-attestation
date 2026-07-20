//! Proof-generation failures must be classified and actionable, never a bare panic.
//!
//! Criterion: *"the system handles proof generation failures gracefully and
//! surfaces a clear error to the user."*
//!
//! Run under `RISC0_DEV_MODE=1` for speed; the guest still executes and still
//! asserts, which is what these tests exercise.

use attestation_sdk::{prove_checked, ProveError, ProveRequest};
use sha2::{Digest, Sha256};

/// A request whose witness genuinely satisfies its statement.
fn consistent(balance: u128, threshold: u128) -> ProveRequest {
    let mut req = ProveRequest {
        npk: [7u8; 32],
        identifier: 1,
        program_owner: [11u32; 8],
        balance,
        nonce: 3,
        data_hash: Sha256::digest([]).into(),
        merkle_path: Vec::new(),
        leaf_index: 0,
        merkle_root: [0u8; 32],
        threshold,
        context_id: [42u8; 32],
        presenter_pubkey: [2u8; 33],
    };
    let (_c, leaf) = attestation_sdk::precompute_leaf(&req);
    let (path, root) = attestation_sdk::synthetic_merkle_path(&leaf, req.leaf_index, 3);
    req.merkle_path = path;
    req.merkle_root = root;
    req
}

#[test]
fn a_balance_below_the_threshold_is_reported_as_a_false_statement() {
    let req = consistent(50_000, 100_000);
    let err = prove_checked(req).expect_err("proving a false statement must fail");

    match &err {
        ProveError::StatementFalse { reason } => {
            assert!(
                reason.contains("balance is below the attested threshold"),
                "reason should name the failing assert, got {reason:?}"
            );
        }
        other => panic!("expected StatementFalse, got {other:?}"),
    }

    // The rendered message must tell the user this is intended behaviour, not a bug.
    let shown = err.to_string();
    assert!(shown.contains("not a bug"), "message should reassure: {shown}");
    assert!(
        shown.contains("refuses to prove a false statement"),
        "message should explain why: {shown}"
    );
}

#[test]
fn a_merkle_path_that_does_not_anchor_is_reported_as_a_false_statement() {
    let mut req = consistent(1_000_000, 100_000);
    req.merkle_root = [0xAA; 32]; // not the root the path folds to

    let err = prove_checked(req).expect_err("a non-anchoring path must fail");
    match &err {
        ProveError::StatementFalse { reason } => assert!(
            reason.contains("merkle path does not anchor"),
            "reason should name the failing assert, got {reason:?}"
        ),
        other => panic!("expected StatementFalse, got {other:?}"),
    }
}

/// Every variant must render something a user can act on: no empty strings, no
/// bare debug formatting, and a next step where one exists.
#[test]
fn every_error_variant_renders_actionable_text() {
    let cases = vec![
        ProveError::StatementFalse {
            reason: "balance is below the attested threshold".into(),
        },
        ProveError::ProverUnavailable("r0vm not found".into()),
        ProveError::Groth16Unavailable("docker daemon not running".into()),
        ProveError::SessionLimit("exceeded 32M cycles".into()),
        ProveError::Other("something else".into()),
    ];
    for c in &cases {
        let s = c.to_string();
        assert!(s.len() > 20, "message too terse: {s:?}");
        assert!(!s.contains("Err("), "message leaks debug formatting: {s:?}");
    }

    // The two recoverable cases must name a concrete remedy.
    assert!(
        ProveError::ProverUnavailable("x".into())
            .to_string()
            .contains("rzup install"),
        "should tell the user how to install the prover"
    );
    assert!(
        ProveError::Groth16Unavailable("x".into())
            .to_string()
            .contains("Docker"),
        "should point at Docker"
    );
}

/// A well-formed request must still succeed, so the classifier is not simply
/// rejecting everything.
#[test]
fn a_satisfiable_request_still_proves() {
    let req = consistent(1_000_000, 100_000);
    let proof = prove_checked(req).expect("a true statement must prove");
    assert_eq!(proof.journal.threshold, 100_000);
}
