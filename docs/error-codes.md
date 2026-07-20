# Error codes

Deterministic, documented error codes for every invalid-proof scenario on both verification paths. This is the table evaluators expect (per LP-0005 "Reliability" success criterion).

## Deployed on-chain programs (`3xxx`)

These are the codes the programs actually deployed on the public testnet return.
They are what an integrator sees from the chain, so read this table first; the
`GateError` table further down belongs to the host-side reference
implementation in `crates/verifier-program`, which is not what is deployed.

Codes `3001`-`3006` are common to all three guests. `3007`-`3012` exist only in
the deep variant, which is the one that verifies the proof on chain.

| Code | Constant | When it fires | Mitigation by integrator |
|---:|---|---|---|
| `3001` | `E_THRESHOLD_TOO_LOW` | `threshold < minimum_threshold` | The presenter attested to a lower floor than the gate demands; ask them to re-prove against the higher N. |
| `3004` | `E_CONTEXT_MISMATCH` | `context_id != expected_context_id` | A credential for another gate. Reject and surface a "wrong gate" message. |
| `3005` | `E_BAD_SIGNATURE` | The presenter challenge signature is malformed or fails ECDSA verification under `presenter_pubkey` | Either the presenter does not hold the matching secret key (a forwarding attempt), or the challenge was tampered with. Reject. |
| `3006` | `E_BAD_PUBKEY_LEN` | `presenter_pubkey` is not 33 bytes | Malformed credential; ask the prover to regenerate. |
| `3007` | `E_BAD_WITNESS` | `witness_words` did not decode as `PrivateInputs` | Wire-format drift between prover and gate; suspect a version mismatch. |
| `3008` | `E_NULLIFIER_MISMATCH` | The pinned `nullifier` is not the one the supplied witness yields | An attempt to prove one attestation while claiming another's marker. Reject. |
| `3009` | `E_ANCHORED_BALANCE_TOO_LOW` | The attested account's on-chain balance is below `minimum_threshold` | The presenter genuinely does not hold the required balance. This is the check the witness cannot lie about, since the balance is read from anchored chain state rather than the witness. |
| `3010` | `E_PRESENTER_NOT_ATTESTED` | `presenter.account_id` is not `derive_account_id(witness.npk, witness.identifier)` | The signer is not the account being attested to. Without this binding the balance in `3009` would belong to a different account than the one attested. |
| `3011` | `E_PRESENTER_NOT_NATIVE` | `presenter.account.program_owner` is not the pinned `authenticated_transfer` program (ImageID `dcbbfebc…bc3f4a71`) | The balance field belongs to a different program, whose semantics the gate has not checked. Reject: "holds at least N" is only well defined once the denominating program is named. |
| `3012` | `E_GATE_TAG_MISMATCH` | `gate_tag` is not `compute_gate_tag(nullifier, minimum_threshold, expected_context_id)` | A forged marker seed, i.e. an attempt to land a marker at an address that does not encode the policy actually enforced. Reject. |

`3002` and `3003` are unallocated. Numbering is stable; new codes are appended.

Constants are defined at
`crates/verifier-program-spel/methods/guest-deep/src/bin/attestation_verifier_deep.rs:82-91`.

A program error surfaces from the sequencer as a failed transaction rather than
as a decodable numeric field, so the code is a diagnostic for whoever built the
call, not a value an integrator can branch on from public data. What an
integrator branches on is the marker PDA: present and owned by the verifier means
the gate passed at exactly the policy folded into its address.

## Reference host-side implementation (`attestation_verifier_program::GateError`)

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
