# LP-0005 — Project guide for future Claude sessions

## What this repo is

A submission for [LP-0005](https://ns.com/earn/lp-0005-private-token-balance-attestation), a $1,200 (USDC/USDT TBD) λPrize. We are building a **Risc0-based private balance attestation primitive** for the Logos Execution Zone (LEZ). The submission must include both on-chain and off-chain verification paths.

## Where the load-bearing facts live

Read these **before** changing anything cryptographic or architectural:

- [`docs/recon.md`](./docs/recon.md) — verified facts about LEZ, sequencer RPC, SPEL, RLN, Risc0 baseline, lambda-prize repo.
- [`docs/decisions/001-architecture-and-receipt-format.md`](./docs/decisions/001-architecture-and-receipt-format.md) — why we ship two paths (chained-call on-chain, Groth16-wrapped off-chain), and why ECDSA-not-Poseidon for presenter binding.
- [`docs/design.md`](./docs/design.md) — what the circuit proves, threat model, public/private split.

## Ground rules for this project

- **Commitment format follows the code, not the prize text.** Real format is `SHA256(COMMITMENT_PREFIX || account_id || program_owner_LE || balance_LE || nonce_LE || data_hash)`. Source: `_external/lez/nssa/core/src/commitment.rs:51-78`. The prize text omits the domain separator and writes `npk` where the code uses `account_id`.
- **Risc0 is pinned to 3.0.5** (matches LEZ's pin). Don't bump without coordinating.
- **`_external/` is gitignored** and holds reference repos (LEZ, SPEL, lez-multisig, logos-delivery-module, logos-basecamp, logos-lez-rln, lambda-prize, lssa-zkvm-testing, etc.). Use these for grounding, do not vendor their code.
- **No `Co-Authored-By` lines in commits.** User is sole author. Email: `eden.baudin.invest@gmail.com`.

## Workspace shape

```
Cargo.toml                                              # workspace root
crates/
├── attestation-core/                                   # shared no_std types + helpers
├── attestation-circuit/                                # host harness + bin
│   ├── src/bin/baseline.rs                             # baseline prover harness
│   └── methods/                                        # risc0-build wrapper
│       └── guest/                                      # actual Risc0 guest (EXCLUDED from workspace)
└── (planned) verifier-program/, verifier-offchain/, sdk/, cli/
integrations/                                           # (planned) governance-gate, chat-gate, third use case
app/                                                    # (planned) Basecamp app GUI
docs/
├── recon.md
├── design.md
└── decisions/
_external/                                              # gitignored, recon-only
```

The guest crate **must remain excluded** from the workspace — it builds with the `riscv32im-risc0-zkvm-elf` toolchain.

## Common commands

```bash
# Build the baseline (host + guest)
cargo build --release -p attestation-circuit --bin baseline

# Real proving baseline (slow, ~tens of seconds expected on M2 Pro)
RISC0_DEV_MODE=0 ./target/release/baseline

# Fast iteration (no proof)
RISC0_DEV_MODE=1 ./target/release/baseline
```

## Open questions tracked outside docs

See the task list (TaskList tool). The two highest-risk unresolved items are:

1. **Groth16 wrap feasibility on Risc0 3.0.5** — if unavailable, off-chain transport must fragment.
2. **Logos Delivery Rust binding** — only a Qt/C++ plugin exists; we need either a Basecamp bridge or a `liblogosdelivery` FFI.

## Submission gates (from the prize page)

- Verifier program deployed on LEZ testnet with a verified program ID.
- 3 reference integrations, at least one by a party outside the submitting team.
- End-to-end demo script that runs from clean checkout with `RISC0_DEV_MODE=0`.
- Recorded narrated demo video showing terminal output.
- Write-up: circuit design, commitment targeting, context+identity binding, both verification paths, privacy guarantees & limits, security assumptions, known limitations, integration instructions.
- Proof generation time + on-chain CU benchmarks.
- CI green on default branch.
