# LP-0005: Private Token Balance Attestation

A reusable private balance attestation primitive for the Logos Execution Zone (LEZ).

Prove that a shielded token account holds at least `N` tokens — without revealing the account's `npk`, exact balance, or identity — and verify the proof either on-chain (LEZ verifier program) or off-chain (via Logos Messaging).

> Submission for [LP-0005 on ns.com](https://ns.com/earn/lp-0005-private-token-balance-attestation). For an evaluator's checklist, see [`docs/criteria-checklist.md`](./docs/criteria-checklist.md).

## Status

Work in progress. Current artifacts:

- Risc0 attestation guest circuit (`crates/attestation-circuit/`) — proves `balance >= N` over the LEZ private-account commitment, with Merkle membership, context binding, and nullifier emission.
- Off-chain verifier (`crates/verifier-offchain/`) and on-chain gate kernel (`crates/verifier-program/`).
- Client SDK (`crates/sdk/`) and CLI (`crates/cli/`).
- Three reference integrations under `integrations/`.

## Quickstart

```bash
# Install the Risc0 toolchain (one-time).
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 3.0.5
rzup install r0vm           3.0.5

# Build and run an end-to-end demo (real STARK proving by default).
cargo build --release -p attestation-cli --bin attest
./scripts/demo.sh
```

The demo generates a presenter key, proves `balance(1_000_000) >= 100_000`, and verifies the resulting credential locally.

## Performance (Apple Silicon, CPU only)

| Operation | Time | Size |
|---|---|---|
| STARK prove (guest v1) | ≈ 7.1 s | — |
| Risc0 receipt          | — | ≈ 300 KB |
| Risc0 verify           | ≈ 10 ms | — |
| ECDSA presenter check  | ≈ 1 ms | — |

Full numbers in [`docs/benchmarks/baseline.md`](./docs/benchmarks/baseline.md).

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

## Documentation

| Doc | What's in it |
|---|---|
| [`docs/architecture.md`](./docs/architecture.md) | End-to-end diagram, crate map |
| [`docs/design.md`](./docs/design.md) | Cryptographic design, threat model, public/private split |
| [`docs/security.md`](./docs/security.md) | Privacy guarantees, threat table, trust assumptions |
| [`docs/limitations.md`](./docs/limitations.md) | Known limits and workarounds |
| [`docs/integration-guide.md`](./docs/integration-guide.md) | Step-by-step for adding LP-0005 to your app |
| [`docs/benchmarks/baseline.md`](./docs/benchmarks/baseline.md) | Proving / verification numbers |
| [`docs/recon.md`](./docs/recon.md) | Verified facts about LEZ, SPEL, Logos Messaging |
| [`docs/decisions/`](./docs/decisions/) | Architecture decision records |

## License

Dual-licensed under MIT OR Apache-2.0.

## Resources

- [Logos Execution Zone](https://github.com/logos-blockchain/logos-execution-zone)
- [LEZ token program](https://github.com/logos-blockchain/logos-execution-zone/tree/main/programs/token)
- [SPEL framework](https://github.com/logos-co/spel) (Logos program / IDL framework)
- [Risc0](https://github.com/risc0/risc0)
