# Error codes

Deterministic, documented error codes for every invalid-proof scenario on both verification paths. This is the table evaluators expect (per LP-0005 "Reliability" success criterion).

## On-chain (`attestation_verifier_program::GateError`)

| Code | Variant | When it fires | Mitigation by integrator |
|---:|---|---|---|
| `001` | `ContextMismatch` | `journal.context_id != expected_context_id` | Check the application bound the right context; reject and surface a "wrong gate" message. |
| `002` | `ThresholdTooLow` | `journal.threshold < minimum_threshold` | The presenter attested to a lower threshold than the gate requires; ask them to re-prove against the higher N. |
| `003` | `InvalidPubkey` | `journal.presenter_pubkey` is not a valid SEC1-compressed secp256k1 point | The credential is malformed; reject and ask the prover to regenerate. |
| `004` | `InvalidSignature` | DER decoding of the presenter signature failed | Network truncation or bad input; ask the presenter to re-sign. |
| `005` | `SignatureRejected` | DER decodes but ECDSA verification under `presenter_pubkey` fails | Either the presenter doesn't hold the matching secret key (forwarding attempt), or the challenge was tampered with. Reject. |
| `006` | `NullifierAlreadyUsed` | The integrator's nullifier store already contains `journal.nullifier` | The credential was already consumed at this gate; do not re-apply. |

Variants are defined at `crates/verifier-program/src/lib.rs:17-25`. The numeric codes above are stable; new variants will only be appended.

## Off-chain (`attestation_verifier_offchain::VerifyError`)

| Code | Variant | When it fires | Notes |
|---:|---|---|---|
| `101` | `Receipt(_)` | The Risc0 receipt failed `Receipt::verify(ATTESTATION_ID)` | Underlying message contains Risc0's reason; *does not* expose any private input. |
| `102` | `Journal(_)` | The receipt verified but `journal.decode::<PublicJournal>()` failed | Wire-format drift between prover and verifier; suspect a version mismatch. |
| `103` | `InvalidPubkey` | Same as on-chain `003` | — |
| `104` | `InvalidSignature` | Same as on-chain `004` | — |
| `105` | `SignatureRejected` | Same as on-chain `005` | — |
| `106` | `ContextMismatch` | Same as on-chain `001` | — |
| `107` | `ThresholdTooLow` | Same as on-chain `002` | — |

Variants are defined at `crates/verifier-offchain/src/lib.rs:25-44`.

## Transport (`attestation_delivery_transport::TransportError`)

| Code | Variant | When it fires |
|---:|---|---|
| `201` | `Upstream(_)` | Logos Delivery (or test backend) returned an error |
| `202` | `Encode(_)` | Failed to serialize a `CredentialEnvelope` |
| `203` | `Decode(_)` | Failed to deserialize a received `CredentialEnvelope` |

Variants are defined at `crates/delivery-transport/src/lib.rs`.

## What's NOT in the error message

We deliberately keep the `Display` implementations free of any field from `PrivateInputs`. A failed verification might log:

- the variant name (e.g., `SignatureRejected`)
- the public journal field that disagrees (e.g., `expected_context_id != ...`)
- the underlying library's own diagnostic (e.g., Risc0's "invalid receipt")

It will never log `npk`, `identifier`, `balance`, `nonce`, `data_hash`, `merkle_path`, or any value derived from them inside the prover. This is enforced by construction — those fields never leave the prover process.
