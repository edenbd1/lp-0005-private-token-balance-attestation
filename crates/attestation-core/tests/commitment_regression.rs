//! Regression tests against the LEZ reference vectors.
//!
//! LEZ ships `DUMMY_COMMITMENT` / `DUMMY_COMMITMENT_HASH` in
//! `_external/lez/nssa/core/src/commitment.rs:55-70` along with the test:
//!
//! ```ignore
//! fn nothing_up_my_sleeve_dummy_commitment() {
//!     let default_account = Account::default();
//!     let account_id_null = AccountId::new([0; 32]);
//!     let expected_dummy_commitment = Commitment::new(&account_id_null, &default_account);
//!     assert_eq!(DUMMY_COMMITMENT, expected_dummy_commitment);
//! }
//! ```
//!
//! Our `compute_commitment` must produce the same value when fed the corresponding inputs.

use attestation_core::compute_commitment;
use sha2::{Digest, Sha256};

const DUMMY_COMMITMENT: [u8; 32] = [
    55, 228, 215, 207, 112, 221, 239, 49, 238, 79, 71, 135, 155, 15, 184, 45, 104, 74, 51, 211,
    238, 42, 160, 243, 15, 124, 253, 62, 3, 229, 90, 27,
];

const DUMMY_COMMITMENT_HASH: [u8; 32] = [
    250, 237, 192, 113, 155, 101, 119, 30, 235, 183, 20, 84, 26, 32, 196, 229, 154, 74, 254, 249,
    129, 241, 118, 39, 41, 253, 141, 171, 184, 71, 8, 41,
];

#[test]
fn matches_lez_dummy_commitment() {
    let account_id = [0u8; 32];
    let program_owner = [0u32; 8];
    let balance: u128 = 0;
    let nonce: u128 = 0;
    let data_hash: [u8; 32] = {
        let mut h = Sha256::new();
        // Account::default has `data: empty`, and the commitment formula hashes
        // `data` once via SHA256 before inclusion.
        h.update(b"");
        h.finalize().into()
    };
    let got = compute_commitment(&account_id, &program_owner, balance, nonce, &data_hash);
    assert_eq!(
        got, DUMMY_COMMITMENT,
        "compute_commitment diverges from LEZ DUMMY_COMMITMENT"
    );
}

#[test]
fn matches_lez_dummy_commitment_hash() {
    // The Merkle leaf hash is SHA256(commitment), per LEZ's tree convention.
    let mut h = Sha256::new();
    h.update(DUMMY_COMMITMENT);
    let got: [u8; 32] = h.finalize().into();
    assert_eq!(got, DUMMY_COMMITMENT_HASH);
}
