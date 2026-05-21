# Sequencer client integration plan

## Where this hooks in

The SDK currently uses `attestation_sdk::synthetic_merkle_path` to build a Merkle proof in-process. Real use needs the proof returned by the LEZ sequencer's `getProofForCommitment` JSON-RPC.

## API to consume

From `docs/recon.md` §2: the sequencer exposes (on port `3040` by default, `jsonrpsee`-based HTTP):

```
getProofForCommitment(commitment: [u8; 32]) -> Option<(usize, Vec<[u8; 32]>)>
```

Return is `(leaf_index, sibling_hashes)` — exactly the inputs the guest already accepts.

## Plan

Add `crates/sequencer-client/`:

```rust
pub struct SequencerClient { /* http endpoint, optional headers */ }

impl SequencerClient {
    pub async fn get_membership_proof(&self, commitment: &[u8; 32])
        -> Result<Option<MembershipProof>, ClientError>;

    pub async fn current_root(&self) -> Result<[u8; 32], ClientError>;
}

pub struct MembershipProof {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; 32]>,
    pub root: [u8; 32],   // we recompute or fetch the matching root
}
```

`SDK::ProveRequest::from_account` constructs the rest of the inputs (`npk`, `identifier`, `balance`, `nonce`, `data_hash`, `program_owner`) from a host-held private account — a wallet integration we will pick up from `_external/lez/wallet/`.

## When this lands

After the verifier-program SPEL wrapper. Both the wallet integration and the sequencer client want a known LEZ workspace layout, so we pair them.
