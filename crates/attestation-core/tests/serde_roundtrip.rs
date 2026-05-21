//! Make sure the wire types survive a bincode round-trip — `risc0-zkvm`'s
//! `env::read` / `env::commit` use the same serde wire format, so we want a
//! quick check that any future field reorder doesn't silently break the guest.

use attestation_core::{PrivateInputs, PublicJournal};

fn sample_private() -> PrivateInputs {
    PrivateInputs {
        npk: [0x01; 32],
        identifier: 7,
        program_owner: [0xDE_AD_BE_EF_u32; 8],
        balance: 999_999,
        nonce: 11,
        data_hash: [0xCC; 32],
        merkle_path: vec![[0xAA; 32], [0xBB; 32], [0xDD; 32]],
        leaf_index: 5,
    }
}

fn sample_journal() -> PublicJournal {
    PublicJournal {
        merkle_root: [0x55; 32],
        threshold: 50_000,
        context_id: [0x66; 32],
        presenter_pubkey: [0x02; 33],
        nullifier: [0x77; 32],
    }
}

#[test]
fn private_inputs_bincode_roundtrip() {
    let p = sample_private();
    let bytes = bincode::serde::encode_to_vec(&p, bincode::config::standard()).unwrap();
    let (back, _): (PrivateInputs, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(p.npk, back.npk);
    assert_eq!(p.identifier, back.identifier);
    assert_eq!(p.balance, back.balance);
    assert_eq!(p.nonce, back.nonce);
    assert_eq!(p.data_hash, back.data_hash);
    assert_eq!(p.merkle_path, back.merkle_path);
    assert_eq!(p.leaf_index, back.leaf_index);
}

#[test]
fn public_journal_bincode_roundtrip() {
    let j = sample_journal();
    let bytes = bincode::serde::encode_to_vec(&j, bincode::config::standard()).unwrap();
    let (back, _): (PublicJournal, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(j, back);
}
