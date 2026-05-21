# Baseline benchmarks — `attestation-circuit`

Numbers from the harness at `crates/attestation-circuit/src/bin/baseline.rs`.

## Setup

- Risc0 toolchain: cargo-risczero **3.0.5**, r0vm **3.0.5**, rust **1.88.0** (matches LEZ pin).
- Hardware: Apple Silicon (ARM64), CPU-only (no GPU accelerators enabled in the workspace).
- Circuit at baseline date: rebuild LEZ commitment + 5-level Merkle membership + `balance >= N`. No signature check, no `npk → account_id` derivation yet (deferred).
- Tree depth: 5 (LEZ genesis commitment-set capacity).
- Synthesized fixtures (`synth_inputs` in the harness).

## Numbers (2026-05-22 — baseline scope only)

| Mode | Prove time | Receipt bytes | Verify time |
|---|---|---|---|
| `RISC0_DEV_MODE=1` (no proof, sanity) | 46 ms | 892 | 0.3 ms |
| `RISC0_DEV_MODE=0` (real STARK) | **6.24 s** | **300,609** | **10.3 ms** |

## Numbers (2026-05-22 — guest v1: + npk derivation + nullifier)

| Mode | Prove time | Receipt bytes | Verify time |
|---|---|---|---|
| `RISC0_DEV_MODE=0` (real STARK) | **7.08 s** | **300,863** | **10.2 ms** |

Δ vs baseline: +0.84 s proving (one extra SHA block for `account_id` derivation + one for the nullifier — well within the headroom budgeted). Receipt size unchanged within rounding.

## End-to-end CLI demo (`scripts/demo.sh`, RISC0_DEV_MODE=0)

| Step | Time | Notes |
|---|---|---|
| `attest keygen` | ms | secp256k1, persisted as 32-byte hex |
| `attest prove` | **6.47 s** | identical guest v1 |
| `attest verify` | < 50 ms | Risc0 verify + ECDSA verify |

Credential file size: 300,861 bytes. Confirms the off-chain transport choice (Groth16 wrap) from ADR-001 remains necessary.

## Reads

- **Proving cost is well below the LEZ team's published `auth_transfer Transfer` baseline** (13.7 s standalone in `_external/lez/docs/benchmarks/cycle_bench.md`). Our circuit is lighter — primarily 5 SHA blocks for commitment + 5 for the Merkle path + 1 for the leaf hash.
- **Receipt is ~300 KB, well above the Logos Delivery default `maxMessageSize` of ~150 KB.** This confirms the [ADR-001](../decisions/001-architecture-and-receipt-format.md) decision: off-chain transport must use a Groth16-wrapped succinct proof rather than the raw STARK receipt.
- **Risc0 3.0.5 ships `risc0-groth16` in-tree** — visible during the host build (`risc0-groth16 v3.0.4` is a transitive of `risc0-zkvm 3.0.5`). Groth16 compression is reachable from the host API; task #15 is unblocked.

## Headroom for circuit growth

Budget for the full circuit (with `npk → account_id` derivation, signature check, nullifier emit):

| Addition | Est. cost (CPU) | Cumulative |
|---|---|---|
| 1 extra SHA block (`account_id` derivation) | ≈ +0.3 s | ≈ 6.5 s |
| secp256k1 sign-knowledge check (`k256` accelerator) | ≈ +1.0 s | ≈ 7.5 s |
| 1 SHA block (nullifier) | ≈ +0.3 s | ≈ 7.8 s |
| Groth16 wrap (host-side, after STARK) | ≈ +60 s (CPU) | one-shot wall-clock penalty |

Wall-clock at 6-8 s for the STARK and a one-time ~1 min Groth16 wrap is comfortable for an interactive UX where the user accepts a short wait before sending the credential.

## Repro

```bash
cargo build --release -p attestation-circuit --bin baseline
RISC0_DEV_MODE=0 ./target/release/baseline
```
