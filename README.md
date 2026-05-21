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

The circuit targets the existing LEZ private account commitment format used by the [LEZ token program](https://github.com/logos-blockchain/logos-execution-zone/tree/main/programs/token):

```
commitment = SHA256(npk || program_owner || balance || nonce || SHA256(data))
```

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
