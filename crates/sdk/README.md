# attestation-sdk

High-level client SDK for generating LP-0005 attestation credentials.

## API

- `PresenterKey::generate() | PresenterKey::from_bytes(&[u8; 32])`
- `PresenterKey::public() -> [u8; 33]` (secp256k1 compressed)
- `PresenterKey::sign(&nonce, &journal) -> DER-encoded signature`
- `prove(req: ProveRequest) -> Result<AttestationProof>`
- `precompute_leaf(&req)` / `synthetic_merkle_path(...)` — helpers for tests/demos

`AttestationProof` carries both the Risc0 `Receipt` and the decoded `PublicJournal`.

## Example

```rust
let presenter = PresenterKey::generate();
let req = ProveRequest {
    npk, identifier, program_owner,
    balance, nonce, data_hash,
    merkle_path, leaf_index, merkle_root,
    threshold, context_id,
    presenter_pubkey: presenter.public(),
};
let proof = prove(req)?;

// At presentation time:
let signature = presenter.sign(&verifier_nonce, &proof.journal);
send_to_peer(proof.receipt, verifier_nonce, signature);
```
