# attestation-verifier-program

Pure-Rust gate kernel for the LEZ on-chain verifier program. Decoupled from SPEL/nssa so it (a) compiles host-side for unit tests and (b) drops in unchanged when wrapped by `#[lez_program]` inside a Logos workspace checkout (see [ADR-002](../../docs/decisions/002-verifier-program-shape.md)).

## API

- `GateInputs { attested, expected_context_id, minimum_threshold, challenge_nonce, presenter_signature_der }`
- `check_gate(&GateInputs) -> Result<(), GateError>`
- `signature::presenter_challenge_digest(nonce, journal)`
- `signature::verify_presenter(journal, nonce, signature_der)`

## Tests

5 unit tests in `tests/gate.rs` covering happy path, context mismatch, threshold too low, wrong-presenter (forwarding), and nonce mismatch (replay).
