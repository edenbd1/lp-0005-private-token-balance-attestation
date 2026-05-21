//! Regression tests for `derive_account_id` against LEZ vectors.
//!
//! Source: `_external/lez/nssa/core/src/nullifier.rs::tests::account_id_from_nullifier_public_key`
//! and its sibling test with `identifier = 1`.

use attestation_core::derive_account_id;

// Pre-derived from `NullifierPublicKey::from(&NSK)` in LEZ's `from_secret_key` test;
// vendored here verbatim so this test does not depend on `_external/lez`.
const NPK_FROM_LEZ_TEST: [u8; 32] = [
    78, 20, 20, 5, 177, 198, 233, 100, 175, 134, 174, 200, 24, 205, 68, 215, 130, 74, 35, 54, 154,
    184, 219, 42, 168, 106, 126, 147, 133, 244, 18, 218,
];

#[test]
fn matches_lez_account_id_identifier_0() {
    let expected = [
        165, 52, 40, 32, 231, 171, 113, 10, 65, 241, 156, 72, 154, 207, 122, 192, 15, 46, 50, 253,
        105, 164, 89, 84, 40, 191, 182, 119, 64, 255, 67, 142,
    ];
    let got = derive_account_id(&NPK_FROM_LEZ_TEST, 0);
    assert_eq!(got, expected);
}

#[test]
fn matches_lez_account_id_identifier_1() {
    let expected = [
        203, 201, 109, 245, 40, 54, 195, 12, 55, 33, 0, 86, 245, 65, 70, 156, 24, 249, 26, 95, 56,
        247, 99, 121, 165, 182, 234, 255, 19, 127, 191, 72,
    ];
    let got = derive_account_id(&NPK_FROM_LEZ_TEST, 1);
    assert_eq!(got, expected);
}
