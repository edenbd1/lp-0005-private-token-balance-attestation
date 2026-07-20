# LP-0005: Private Token Balance Attestation

A reusable private balance attestation primitive for the Logos Execution Zone (LEZ).

Prove that a shielded token account holds at least `N` tokens — without revealing the account's `npk`, exact balance, or identity — and verify the proof either on-chain (LEZ verifier program) or off-chain (via Logos Messaging).

> Submission for [LP-0005 on ns.com](https://ns.com/earn/lp-0005-private-token-balance-attestation). For an evaluator's checklist, see [`docs/criteria-checklist.md`](./docs/criteria-checklist.md).

## Narrated demo video

Full end-to-end walkthrough, with the `RISC0_DEV_MODE=0` banner visible in the terminal during proof generation:

[![LP-0005 narrated demo](https://img.youtube.com/vi/Ta18-p3sz3M/maxresdefault.jpg)](https://youtu.be/Ta18-p3sz3M)

<https://youtu.be/Ta18-p3sz3M> — architecture overview, live `scripts/demo.sh` run, explorer walkthrough of the deploy transactions and the confirmed `gated_check`, repository tour, and the Basecamp `.lgx` asset.

## Status

**✅ Deployed live on the public Logos Execution Zone testnet.**

- Sequencer: `https://testnet.lez.logos.co`
- Block explorer: `https://explorer.testnet.lez.logos.co`
- Signer (anchorer): [`CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r`](https://explorer.testnet.lez.logos.co/account/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r)

**Public testnet — programs deployed, and a `gated_check` whose zero-knowledge proof is VERIFIED ON CHAIN. Every tx independently verifiable via `getTransaction` JSON-RPC or by clicking the explorer link:**

| # | Action | Tx hash (click for explorer) |
|---|---|---|
| 1 | **`wallet deploy-program`** — attestation circuit (`balance ≥ N` Risc0 guest, ImageID `dbc40b94…6a9d4d`) | [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d) |
| 2 | **`wallet deploy-program`** — verifier program v2 (SPEL, flat-arg ABI, deep gate, ImageID `7715f791…d8a1db429`) | [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9) |
| 3 | **`wallet deploy-program`** — verifier program v3 (SPEL, flat-arg ABI, shallow gate, ImageID `b32c6662…df85952a`) | [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca) |
| 4 | **`spel gated_check`** — ECDSA-signed gate call, v3 shallow verifier accepts (host-side checks only, no proof verification) | [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d) |
| 5 | **`wallet deploy-program`** — LEZ-native attestation program (ImageID `9b6be465…6c27da`) | `674aa03a8a51a2eba660ec2ab136a1b6c9ca17817c7bb3160b68904375726652` |
| 6 | **`wallet deploy-program`** — deep verifier (ImageID `adc35497…43d40e`) | `c5ea829ffa2636b9a76a4eed90b80c45a20d4bb6260c1f913f4ec042e563d61f` |
| 7 | ✅ **`spel gated_check`, privacy-preserving — the zero-knowledge proof is VERIFIED ON CHAIN** | `a77fe12b7027247651580fab5b3de5203ce564f8ac1fa46d8d0c9c865f4ff731` |

### The on-chain path, and how to check it yourself

Rows 1 to 4 are the **shallow** gate. It validates context, threshold and an ECDSA
challenge response, but it verifies **no zero-knowledge proof** — and no program
on that path could. A LEZ *public* transaction proves and verifies nothing: the
sequencer merely re-executes the program (`lee/state_machine/src/program.rs:73-77`,
*"Execute the program (without proving)"*).

Rows 5 to 7 are the **deep** gate, on the privacy-preserving path. There the client
proves locally and LEZ's privacy circuit composes the chained call to the
attestation program with a real `env::verify`
(`lee/privacy_preserving_circuit/src/execution_state.rs:149`); the sequencer then
verifies that receipt against the pinned `PRIVACY_PRESERVING_CIRCUIT_ID`. The
attestation's proof is therefore verified on chain as a precondition of acceptance.

Verify it from public data alone, with only `curl`, `python3` and `jq`:

```bash
./scripts/verify-onchain-proof.sh
```

It checks that both programs are deployed, that the `gated_check` transaction is
of type `PrivacyPreserving` (borsh variant byte 1, 230,186 bytes of receipt), and
that the marker PDA `Px6D6EPbG5iJkKzbBPwJeqXGx1xZ8hLRNQEHirUDLiR` — derived from
the verifier's ImageID and the attestation nullifier — is owned by the verifier
program. That account could only be claimed by an accepted transaction.

Two behaviours confirmed against the deployed programs. A witness whose balance is
below the attested threshold **cannot produce a transaction at all**
(`ProgramProveFailed`, raised inside the chained attestation guest), and replaying
the same nullifier is likewise unprovable (`AccountAlreadyInitialized`). Both
failures occur client-side during proving, before any transaction exists — which
is the stronger outcome, but it means they are prover evidence rather than
sequencer-rejection evidence.

Full deployment record (with reproduction commands) in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

**Reproduce in 30 seconds:** `bash scripts/demo.sh` — runs the full pipeline against the public testnet, confirms all four tx hashes are on chain, generates a real Risc0 proof under `RISC0_DEV_MODE=0`, runs the challenge-response off-chain verification, and emits the `spel gated_check` call args ready to copy-paste.

**Basecamp plugin:** [`app/lp-0005-attestation.lgx`](app/lp-0005-attestation.lgx) — 2.1 MB, `lgx verify ✅`, SHA-256 `193a903a0823cdf4f8ef3a333bc28c81e240c1b2faf5b7f8fd93bc1094c89770`. Drop into `~/Library/Application Support/Logos/LogosBasecampDev/plugins/` to load.

**Reusable crates published on crates.io:** [`attestation-core`](https://crates.io/crates/attestation-core), [`attestation-verifier-program`](https://crates.io/crates/attestation-verifier-program), [`attestation-sequencer-client`](https://crates.io/crates/attestation-sequencer-client), [`attestation-delivery-transport`](https://crates.io/crates/attestation-delivery-transport). Add `attestation-core = "0.1"` to your `Cargo.toml` to consume the primitive without forking the repo.

### Repository artifacts

- Risc0 attestation guest circuit (`crates/attestation-circuit/`) — proves `balance ≥ N` over the LEZ private-account commitment, with Merkle membership, context binding, and nullifier emission.
- On-chain verifier program (`crates/verifier-program-spel/`) — SPEL `#[lez_program]` that gates application actions on a valid attestation, composes the inner proof via chained-call.
- Off-chain verifier (`crates/verifier-offchain/`) and the portable kernel (`crates/verifier-program/`).
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
