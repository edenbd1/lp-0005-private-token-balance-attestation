//! Shared types between the attestation guest circuit and the host SDK.
//!
//! The guest is compiled `no_std`; this crate must too.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// 32-byte domain separator for LEZ private account commitments.
/// Source: `_external/lez/nssa/core/src/commitment.rs:56`.
/// ASCII `"/LEE/v0.3/Commitment/"` (21 bytes) + 11 zero bytes.
pub const COMMITMENT_PREFIX: [u8; 32] = [
    b'/', b'L', b'E', b'E', b'/', b'v', b'0', b'.', b'3', b'/', b'C', b'o', b'm', b'm', b'i', b't',
    b'm', b'e', b'n', b't', b'/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// 32-byte domain separator for LEZ private account ids.
/// Source: `_external/lez/nssa/core/src/nullifier.rs:7`.
/// ASCII `"/LEE/v0.3/AccountId/Private/"` (28 bytes) + 4 zero bytes.
pub const PRIVATE_ACCOUNT_ID_PREFIX: [u8; 32] = [
    b'/', b'L', b'E', b'E', b'/', b'v', b'0', b'.', b'3', b'/', b'A', b'c', b'c', b'o', b'u', b'n',
    b't', b'I', b'd', b'/', b'P', b'r', b'i', b'v', b'a', b't', b'e', b'/', 0, 0, 0, 0,
];

/// 32-byte domain separator for LP-0005 nullifiers. Local to this primitive, not part of LEZ.
pub const NULLIFIER_PREFIX: [u8; 32] = [
    b'/', b'l', b'p', b'-', b'0', b'0', b'0', b'5', b'/', b'v', b'0', b'.', b'1', b'/', b'N', b'u',
    b'l', b'l', b'i', b'f', b'i', b'e', b'r', b'/', 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Inputs the prover reveals neither to the verifier nor to the journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateInputs {
    /// Nullifier public key of the account holder (LEZ semantics).
    pub npk: [u8; 32],

    /// Per-account identifier; an LE u128 (LEZ `Identifier = u128`).
    pub identifier: u128,

    /// Token program owner (`ProgramId = [u32; 8]`, serialized LE per word).
    pub program_owner: [u32; 8],

    /// Private balance — the value compared against the threshold `N`.
    pub balance: u128,

    /// Account nonce (`u128`, LE).
    pub nonce: u128,

    /// `SHA256(account.data)`.
    pub data_hash: [u8; 32],

    /// Merkle sibling hashes from leaf to root-excluded. Length = tree depth.
    pub merkle_path: Vec<[u8; 32]>,

    /// 0-indexed leaf position inside the commitment set.
    pub leaf_index: u64,
}

/// Public values exposed in the Risc0 journal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicJournal {
    /// Merkle root the proof was anchored against.
    pub merkle_root: [u8; 32],

    /// Threshold `N` the proof attests `balance >= N`.
    pub threshold: u128,

    /// Application-defined context identifier (program id, group id, ...).
    pub context_id: [u8; 32],

    /// Public key the presenter must sign a verifier-supplied nonce with.
    /// secp256k1 compressed (33 bytes).
    #[serde(with = "BigArray")]
    pub presenter_pubkey: [u8; 33],

    /// Nullifier — opaque marker that integrations may track to prevent re-use.
    /// `SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id || account_id)`.
    pub nullifier: [u8; 32],
}

/// Re-derive a LEZ regular private-account id.
/// Mirrors `_external/lez/nssa/core/src/nullifier.rs:19-32` byte-for-byte.
pub fn derive_account_id(npk: &[u8; 32], identifier: u128) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut bytes = [0u8; 80];
    bytes[0..32].copy_from_slice(&PRIVATE_ACCOUNT_ID_PREFIX);
    bytes[32..64].copy_from_slice(npk);
    bytes[64..80].copy_from_slice(&identifier.to_le_bytes());
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Recompute a LEZ private-account commitment from its components.
/// Mirrors `_external/lez/nssa/core/src/commitment.rs:51-78` byte-for-byte.
pub fn compute_commitment(
    account_id: &[u8; 32],
    program_owner: &[u32; 8],
    balance: u128,
    nonce: u128,
    data_hash: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_PREFIX);
    hasher.update(account_id);
    for word in program_owner {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(balance.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update(data_hash);
    hasher.finalize().into()
}

/// Walk a Merkle path from a leaf to the root.
/// Uses `hash_two(L, R) = SHA256(L || R)` per `_external/lez/nssa/src/merkle_tree/mod.rs:146-157`.
pub fn fold_merkle_path(leaf_hash: &[u8; 32], leaf_index: u64, siblings: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut node = *leaf_hash;
    let mut idx = leaf_index;
    for sib in siblings {
        let mut hasher = Sha256::new();
        if idx & 1 == 0 {
            hasher.update(node);
            hasher.update(sib);
        } else {
            hasher.update(sib);
            hasher.update(node);
        }
        node = hasher.finalize().into();
        idx >>= 1;
    }
    node
}

/// Compute the LP-0005 nullifier.
/// `SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id || account_id)`.
pub fn compute_nullifier(
    presenter_pubkey: &[u8; 33],
    context_id: &[u8; 32],
    account_id: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(NULLIFIER_PREFIX);
    h.update(presenter_pubkey);
    h.update(context_id);
    h.update(account_id);
    h.finalize().into()
}

use sha2 as _;
