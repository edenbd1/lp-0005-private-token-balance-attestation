# attestation-verifier-offchain

Off-chain verifier for LP-0005 credentials. Wraps `Receipt::verify` and ECDSA signature checks.

## API

- `verify_receipt(&Receipt) -> PublicJournal` — Risc0 verification + journal decode.
- `presenter_challenge_digest(nonce, journal) -> [u8; 32]` — the canonical digest a presenter signs.
- `verify_presenter_signature(journal, nonce, signature_der)` — secp256k1 ECDSA check.
- `verify_credential(receipt, nonce, sig, expected_context, minimum_threshold) -> PublicJournal` — one-call entry point.

## Tests

Three real-proving end-to-end tests in `tests/e2e.rs` (gated behind `#[ignore = "real STARK proving"]`):

- happy path,
- proof-forwarding attempt is rejected,
- wrong-context attempt is rejected.

Run them locally with `cargo test --release -p attestation-verifier-offchain -- --ignored`.
