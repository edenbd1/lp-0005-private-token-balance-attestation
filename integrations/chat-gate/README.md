# chat-gate (reference integration #2)

Off-chain token-gated chat group admission. A candidate sends a `MembershipRequest` (attestation receipt + nonce + signature) over Logos Messaging; the group operator runs `GroupRoster.admit` and, on success, adds the candidate's `presenter_pubkey` to the roster.

## Kernel API

```rust
pub fn group_context_id(group_id: &str) -> [u8; 32];

impl GroupRoster {
    pub fn new(group_id: impl Into<String>, minimum_stake: u128) -> Self;
    pub fn admit(
        &mut self,
        receipt: &Receipt,
        presenter_nonce: &[u8; 32],
        presenter_signature_der: &[u8],
    ) -> Result<PublicJournal, AdmissionError>;
}
```

## Tests

`tests/admission.rs` exercises:

- happy admission,
- proof bound to a different group is rejected.

Both are gated behind `#[ignore = "real STARK proving"]`. Run with `cargo test --release -p chat-gate -- --ignored`.

## Transport

This crate is transport-agnostic. The wiring against Logos Delivery lives in [`crates/delivery-transport`](../../crates/delivery-transport/); use the `InMemoryTransport` for tests and swap in a real backend in production.
