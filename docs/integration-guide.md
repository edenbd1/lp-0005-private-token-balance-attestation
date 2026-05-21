# Integration guide

Step-by-step for adding LP-0005 attestations to your application.

## Concepts

- `context_id` — 32 bytes you choose, scoped to your application. Hash `"/your-app/v1/" || feature_name` is a fine convention. Different gates pick different `context_id`s to prevent cross-gate replay.
- `threshold` — the minimum balance you require. The user proves `balance >= threshold` without revealing the actual balance.
- `presenter_pubkey` — secp256k1 compressed; the user controls the matching secret key. This binds the proof to *who is presenting*, not just to what was proven.
- `nullifier` — emitted in the journal. Track it server-side if you want one-shot semantics.

## On-chain integration (LEZ program)

1. **Define your `context_id`** as a `[u8; 32]` constant in your program.
2. **Add an instruction** that accepts `(attestation: PublicJournal, presenter_nonce: [u8; 32], presenter_signature_der: Vec<u8>)` plus whatever your gated action needs.
3. **Call `attestation_verifier_program::check_gate`** with the inputs.
4. **Declare a `ChainedCall`** in your `SpelOutput` referencing `ATTESTATION_PROGRAM_ID` so the PPE pipeline runs `env::verify` on the attestation proof.
5. **Optionally track the nullifier** in a PDA mapping if you need single-use semantics.

`integrations/governance-gate/` is the reference shape. The SPEL wrapper itself is not in-tree yet (see ADR-002) but the gate kernel is.

## Off-chain integration (Logos Messaging / Logos Delivery)

1. **Define your `context_id`** the same way.
2. **Receive** the credential envelope (`CredentialEnvelope` from `attestation-delivery-transport`).
3. **Verify** with `attestation_verifier_offchain::verify_credential(receipt, nonce, sig, &context_id, minimum_threshold)`.
4. **Track the nullifier** if you want single-use semantics.

`integrations/chat-gate/` and `integrations/premium-features/` are the reference shapes.

## Client side (generating a credential)

1. **Generate a presenter key** with `PresenterKey::generate()` (or load one from secure storage with `PresenterKey::from_bytes`).
2. **Build a `ProveRequest`** with your account inputs (`npk`, `identifier`, `balance`, `nonce`, `data_hash`, `program_owner`), the sequencer-supplied Merkle proof (`merkle_path`, `leaf_index`, `merkle_root`), and your application context (`threshold`, `context_id`, `presenter_pubkey`).
3. **Call `attestation_sdk::prove(req)`** to get an `AttestationProof { receipt, journal }`.
4. **At presentation time**, the verifier sends you a `nonce`; sign with `presenter.sign(&nonce, &journal)` and send `(receipt, nonce, signature)` to the verifier.

## What you do NOT need to think about

- Commitment format compatibility — `attestation-core` mirrors LEZ byte-for-byte (validated by regression tests against `DUMMY_COMMITMENT`).
- Nullifier construction — emitted automatically.
- Receipt verification details — the verifier crates wrap `Receipt::verify` for you.

## Testing tips

- Use `RISC0_DEV_MODE=1` for fast iteration. Switch to `=0` before benchmarks or recording the demo.
- Mark real-proving integration tests with `#[ignore = "real STARK proving"]` so the default `cargo test` stays under a few seconds.
- The in-memory transport in `crates/delivery-transport/src/inmem.rs` lets you write off-chain integration tests without spinning up Logos Delivery.
