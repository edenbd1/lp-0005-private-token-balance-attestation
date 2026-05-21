//! Shared types between the attestation guest circuit and the host SDK.
//!
//! The guest is compiled `no_std`; this crate must too.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// 32-byte domain separator for LEZ private account commitments.
/// Source: `lez/nssa/core/src/commitment.rs:56`.
/// ASCII `"/LEE/v0.3/Commitment/"` (21 bytes) + 11 zero bytes.
pub const COMMITMENT_PREFIX: [u8; 32] = [
    b'/', b'L', b'E', b'E', b'/', b'v', b'0', b'.', b'3', b'/', b'C', b'o', b'm', b'm', b'i', b't',
    b'm', b'e', b'n', b't', b'/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Inputs the prover reveals neither to the verifier nor to the journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateInputs {
    /// Derived account id (32 bytes). The guest re-checks that this matches
    /// `AccountId::for_regular_private_account(npk, identifier)` for the witnessed
    /// `npk`/`identifier`, so `npk` itself never enters the journal.
    pub account_id: [u8; 32],

    /// Token program owner (`ProgramId = [u32; 8]`, serialized LE per word).
    /// 32 bytes once serialized.
    pub program_owner: [u32; 8],

    /// Private balance — the value compared against the threshold `N`.
    pub balance: u128,

    /// Account nonce (`u128`, LE).
    pub nonce: u128,

    /// `SHA256(account.data)` — the recon report shows the commitment hashes data once,
    /// then includes the digest; we pass the digest directly to avoid carrying raw data.
    pub data_hash: [u8; 32],

    /// Merkle sibling hashes from leaf to root-excluded. Length = tree depth.
    pub merkle_path: Vec<[u8; 32]>,

    /// 0-indexed leaf index inside the commitment set.
    pub leaf_index: u64,
}

/// Public values exposed in the Risc0 journal.
/// The verifier (on-chain or off-chain) checks every field against application context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicJournal {
    /// Merkle root the proof was anchored against. The on-chain verifier checks this
    /// is in `root_history`; the off-chain verifier checks it matches the expected snapshot.
    pub merkle_root: [u8; 32],

    /// Threshold `N` the proof attests `balance >= N`.
    pub threshold: u128,

    /// Application-defined context identifier (program id, group id, ...).
    /// Prevents replay across gates.
    pub context_id: [u8; 32],

    /// Public key the presenter must sign a verifier-supplied nonce with.
    /// Prevents proof-forwarding by a third party. We use secp256k1 compressed (33 bytes).
    #[serde(with = "BigArray")]
    pub presenter_pubkey: [u8; 33],
}

/// Re-compute a LEZ private account commitment from its components.
/// Mirrors `lez/nssa/core/src/commitment.rs:51-78` byte-for-byte.
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
/// Uses `hash_two(L, R) = SHA256(L || R)` per `lez/nssa/src/merkle_tree/mod.rs:146-157`.
/// `leaf_index` selects whether each sibling is left or right (LSB first = lowest level).
pub fn fold_merkle_path(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    siblings: &[[u8; 32]],
) -> [u8; 32] {
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

// Pull in `sha2` only for these helpers. `Sha256` is also the Risc0 accelerated path on the guest.
use sha2 as _;
