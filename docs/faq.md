# FAQ

### Why doesn't the proof commit to my exact balance?

It's a feature, not a limit. The prize asks for a *threshold* attestation — verifying `balance >= N` without leaking how far above N the holder is. The verifier learns only that the threshold is met.

### Why is the commitment formula in the README different from the prize spec?

The prize text writes `SHA256(npk || program_owner || balance || nonce || SHA256(data))`. The actual LEZ code (`_external/lez/nssa/core/src/commitment.rs:51-78`) uses `SHA256(COMMITMENT_PREFIX || account_id || program_owner_LE || balance_LE || nonce_LE || data_hash)`. We follow the code — that's the format on-chain. `npk` enters indirectly through `account_id = SHA256(PRIVATE_ACCOUNT_ID_PREFIX || npk || identifier_LE)`. Regression tests against `DUMMY_COMMITMENT` validate byte-for-byte compatibility.

### Why secp256k1 and not Poseidon for the presenter binding?

`logos-lez-rln` uses Poseidon BN254 because its host circuit is already in BN254. Our circuit is SHA-256-heavy (commitment + Merkle path + nullifier all use SHA-256). Adding Poseidon would roughly double cycle count for no gain. secp256k1 has a Risc0 accelerator, so the in-circuit signature path (if we ever wanted to add it; currently we keep the signature outside the circuit) is cheap.

### Why is the signature check outside the circuit?

It can be — the cryptographic security argument is the same. Moving it inside would double proving time and provide no privacy benefit: `presenter_pubkey` is public either way.

### Why a Groth16 wrap for off-chain transport?

The raw STARK receipt is ~300 KB. Logos Delivery's default `maxMessageSize` is ~150 KB. Groth16 compression brings the credential to ≈ 256 bytes, fits any channel, and verifies in constant time. Risc0 3.0.5 ships `risc0-groth16` transitively, so no extra dependency.

### Can the same attestation be presented at two different gates?

Two different `context_id`s ⇒ two different proofs are needed. The journal pins `context_id`, so a proof minted for gate A is rejected at gate B. This is by design (anti-replay).

### Can the same attestation be re-presented at the same gate?

The receipt is replayable as long as the presenter still controls the secret key. Integrations that care about one-shot semantics consume the `nullifier` after first use — this is the role of `used_nullifiers` in `governance-gate` and `chat-gate`.

### What stops me from buying a proof from someone with a big balance?

Bound to nothing on the prover side beyond the LEZ account they own; bound on the *presenter* side via the secp256k1 challenge. So the buyer must convince the seller to (a) generate the proof committing to *their* (buyer's) pubkey, and (b) hand it over. The seller has every reason to sell, the buyer has every reason to buy. **Voluntary collusion is out of scope** — this is documented in [`docs/limitations.md`](./limitations.md). If you want to prevent it, you need a long-lived, audited identity that ties presenter pubkeys to real-world reputation.

### How long does proving take?

7 s on Apple Silicon CPU. Add ~1 min for Groth16 compression if you want the small off-chain credential.

### Where do I find the third integration?

[`integrations/premium-features/`](../integrations/premium-features/) — this is the slot the prize wants filled by an outside party. The kernel is in-tree so a third-party integrator only has to pick their tiers and ship.
