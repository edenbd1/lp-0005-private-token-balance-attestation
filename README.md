# LP-0005: Private Token Balance Attestation

A reusable private balance attestation primitive for the Logos Execution Zone (LEZ).

Prove that a shielded token account holds at least `N` tokens — without revealing the account's `npk`, exact balance, or identity — and verify the proof either on-chain (LEZ verifier program) or off-chain (via Logos Messaging).

> Submission for [LP-0005 on ns.com](https://ns.com/earn/lp-0005-private-token-balance-attestation).

## Status

Work in progress.

## Architecture

Two verification paths over a single proof format:

```
                    ┌───────────────────────┐
                    │  Risc0 guest circuit  │
                    │  balance >= N         │
                    │  + Merkle membership  │
                    │  + context binding    │
                    │  + identity binding   │
                    └───────────┬───────────┘
                                │ Risc0 receipt
                ┌───────────────┴───────────────┐
                ▼                               ▼
   ┌───────────────────────┐       ┌───────────────────────┐
   │ On-chain verifier     │       │ Off-chain verifier    │
   │ (LEZ program, SPEL)   │       │ (Rust lib over        │
   │                       │       │  Logos Messaging)     │
   └───────────────────────┘       └───────────────────────┘
```

### Targeted commitment format

The circuit targets the **real** LEZ private account commitment format as defined in `nssa/core/src/commitment.rs`:

```
commitment = SHA256(
    "/LEE/v0.3/Commitment/" || 11×\0     // 32-byte domain separator
    || account_id                         // 32 bytes
    || program_owner                      // 32 bytes (8 × u32 LE)
    || balance                            // 16 bytes (u128 LE)
    || nonce                              // 16 bytes (u128 LE)
    || SHA256(data)                       // 32 bytes
)
```

The prize description elides the domain separator and writes `npk` where the code uses `account_id`. The circuit follows the on-chain code. `account_id` is derived from `(npk, identifier)` via `AccountId::for_regular_private_account` (or the PDA variant), and the circuit witnesses `npk` and proves that derivation — `npk` is never revealed.

### Two verification paths, two compositions

We ship both architectures so the same primitive serves on-chain and off-chain use cases without compromise:

| Path | How proofs flow | Why |
|---|---|---|
| **On-chain (chained-call)** | Our attestation circuit is a LEZ program; the verifier program calls it through `env::verify(program_id, journal)` (Risc0 assumption mechanism). | Idiomatic LEZ; cheapest path; integrates with the privacy-preserving outer proof. |
| **Off-chain (portable receipt)** | Generate a `Receipt`, wrap it in a Groth16 succinct proof (≈ 256 bytes), transmit via Logos Messaging, verify locally. | Logos Messaging default `maxMessageSize` ≈ 150 KB; raw Risc0 inner-receipt ≈ 224 KB. Groth16 wrap gives us a small self-contained credential. |

### Context binding

Each proof commits to a public `context_id` (program ID, group ID, or application identifier) to prevent replay across gates.

### Identity binding (presenter-bound proofs)

A proof commits publicly to a `presenter_pubkey`. The presenter must sign a verifier-supplied nonce with the corresponding private key to be accepted. This prevents a third party who obtains a proof from using it as their own. We use a standard ECDSA pubkey (Risc0 has a native accelerator) rather than a Poseidon-based RLN-style id-commitment, to avoid paying Poseidon cycles on top of the SHA-256-heavy commitment reconstruction.

### Context binding

Each proof commits to a public `context_id` (program ID, group ID, or application identifier) to prevent replay across gates.

### Identity binding (presenter-bound proofs)

A proof commits publicly to a `presenter_pubkey`. The presenter must sign a verifier-supplied nonce with the corresponding private key to be accepted. This prevents a third party who obtains a proof from using it as their own.

## Components

| Component | Path | Description |
|---|---|---|
| Risc0 circuit | `circuit/` | Guest code proving `balance >= N` + Merkle + bindings |
| On-chain verifier | `programs/verifier/` | LEZ Rust program, SPEL IDL |
| Off-chain verifier | `crates/verifier/` | Local proof validation library |
| Client SDK | `crates/sdk/` | Proof generation + transport (on-chain & Logos Messaging) |
| CLI | `crates/cli/` | `prove`, `submit`, `send`, `verify` |
| Basecamp app | `app/` | GUI for end users |
| Integrations | `integrations/` | Reference integrations (governance gate, chat gate, third use case) |

## License

Dual-licensed under MIT OR Apache-2.0.

## Resources

- [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone)
- [LEZ token program](https://github.com/logos-blockchain/logos-execution-zone/tree/main/programs/token)
- [SPEL framework](https://github.com/logos-co/spel) (Logos program / IDL framework)
- [Risc0](https://github.com/risc0/risc0)
