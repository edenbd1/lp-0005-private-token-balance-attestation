# On-chain compute-unit (CU) budget

The LP-0005 prize asks us to "document the compute unit (CU) cost of each on-chain operation on LEZ devnet/testnet." The note in the prize text also reminds us that LEZ's per-transaction budget may change.

This file holds the **plan** for that measurement and will be populated with concrete numbers once the verifier program is deployed on testnet (item #3 in `docs/whats-left.md`).

## What we will measure

For the SPEL `gated_check` instruction:

| Step | Description | Expected order of magnitude |
|---|---|---|
| `env::verify(ATTESTATION_ID, journal)` | PPE outer-circuit composition of the attestation proof. | dominant cost — typically several seconds in CU equivalent, per the LEZ benchmarks in `_external/lez/docs/benchmarks/cycle_bench.md`. |
| `check_gate` ⇒ context check | 32-byte equality | cheap |
| `check_gate` ⇒ threshold check | u128 comparison | cheap |
| `check_gate` ⇒ ECDSA secp256k1 verify | k256 hardware-accelerated by the Risc0 guest target | tens of millions of cycles in the guest |
| `presenter_challenge_digest` | 5 × SHA256 blocks (~96 bytes total) | small |
| `ChainedCall::new(...)` packing | serde-to-Vec<u32> | small |

## Method

When the deploy lands:

1. Submit one transaction per integration (`governance-gate`, `chat-gate-bridge`, `premium-features`) with `RISC0_DEV_MODE=0` and `RUST_LOG=info`.
2. Capture the sequencer's reported CU count for each transaction.
3. Repeat with the threshold varied to confirm the cost is fixed in N (it should be — we only do a single `u128` comparison, not a per-bit loop).
4. Capture the wall-clock proving time for each (`scripts/demo.sh` already does this for the off-chain path).

## Why this file is not a number yet

The verifier program is not deployed on LEZ testnet at the time of this commit. Once items #1, #2, and #3 in `docs/whats-left.md` land, evaluators (or we) will run the measurement and update the table below.

## Numbers (placeholder)

| Integration | Instruction | CU | Wall-clock |
|---|---|---|---|
| `governance-gate` | `cast_vote` | TBD | TBD |
| `chat-gate-bridge` | `admit_via_attestation` | TBD | TBD |
| `premium-features` | `activate_tier` | TBD | TBD |

Off-chain proving (already measured, see `baseline.md`): 7.08 s on Apple Silicon CPU, RISC0_DEV_MODE=0.
