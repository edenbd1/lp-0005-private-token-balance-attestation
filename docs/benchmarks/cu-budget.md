# On-chain compute-unit (CU) budget

LP-0005 brief: *"document the compute unit (CU) cost of each on-chain operation on LEZ devnet/testnet."*

## Measured numbers (public testnet, 2026-05-23)

Captured live under `RISC0_DEV_MODE=0` against the deployed verifier programs on `https://testnet.lez.logos.co`. The host instrumentation (`crates/sdk/src/lib.rs::prove`) emits Risc0 prover stats on stderr after every prove call:

```
[prove-metrics] total_cycles=131072 segments=1 user_cycles=83399 paging_cycles=23185 reserved_cycles=24488
proved in 6.524752166s
```

| Metric | Value | What it measures |
|---|---|---|
| `total_cycles` | **131,072** | Sum of all RISC-V cycles executed inside the Risc0 zkVM for one attestation proof. This is the CU equivalent on LEZ. |
| `user_cycles` | **83,399** | Cycles spent executing the actual guest logic (commitment reconstruction, Merkle fold, threshold check, nullifier compute, ECDSA prep). |
| `paging_cycles` | **23,185** | Cycles charged by the Risc0 zkVM for memory paging. Fixed overhead independent of input size. |
| `reserved_cycles` | **24,488** | Cycles reserved by the zkVM for STARK setup / teardown. Fixed overhead. |
| `segments` | **1** | The full proof fits in a single Risc0 segment — no multi-segment commitment needed. |
| Wall-clock (composite) | **6.52 s** | Default prove time on Apple Silicon (M-series, CPU only). Produces a ~300 KB credential. |
| Wall-clock (Groth16-wrapped) | **150.71 s** | Same proof, wrapped through the `risc0-groth16-prover` docker sidecar. Produces a **1,479-byte** credential — fits any Logos Delivery payload limit. Reproduce: `attest prove --groth16`. |

### Composite vs Groth16 receipt comparison (measured 2026-05-24)

| Receipt kind | Credential size on disk | Prove wall-clock | Verify wall-clock |
|---|---|---|---|
| Composite (default) | **300,863 bytes** | 6.52 s | ~10 ms |
| Groth16-wrapped | **1,479 bytes** | 150.71 s | ~10 ms |
| Compression ratio | **≈ 203×** smaller | ≈ 23× slower to prove | unchanged |

The Groth16 wrap is the path to use when the credential needs to traverse a transport with a payload cap (Logos Delivery's default `maxMessageSize` is ≈ 150 KB; the composite receipt exceeds this, the Groth16-wrapped one fits with ~99 % headroom).

## On-chain cost of `gated_check` (measured)

This is the number the prize asks for: the compute cost the **sequencer** incurs
when it includes a `gated_check` transaction in a block.

The LEZ sequencer exposes no per-transaction cycle telemetry — there is no such
field on `getTransaction`, and neither the sequencer nor the indexer RPC surfaces
one — so the figure cannot be read back off the chain. It is instead obtained by
replaying the sequencer's own execution exactly: same deployed binary, same four
inputs in the same order, same 32M session limit, same executor. See
`crates/cu-bench/`, which mirrors `Program::execute` and `Program::write_inputs`
from LEZ `v0.2.0` (`lee/state_machine/src/program.rs:55-110`).

Measured 2026-07-20 against the deployed v3 shallow verifier
(ImageID `b32c6662…df85952a`), with the account pre-state fetched live from
`https://testnet.lez.logos.co`:

| Metric | Value |
|---|---|
| Instruction | `gated_check` |
| Pre-state accounts | 1 |
| Instruction data | 275 u32 words |
| Segments | 6 |
| **User cycles** | **5,673,563** |
| **Proving cycles (sum of 2^po2)** | **6,291,456** |
| Public execution budget (`MAX_NUM_CYCLES_PUBLIC_EXECUTION`) | 33,554,432 |
| **Budget consumed** | **18.75 %** |

The cost is dominated by in-guest secp256k1 ECDSA verification. At 18.75 % of the
per-transaction budget, a single `gated_check` leaves comfortable headroom, but
the budget would not absorb five such verifications in one transaction.

> **Correction.** Earlier revisions of this document estimated `gated_check` at
> roughly 51,500 cycles, extrapolated from per-step reasoning rather than
> measured. That estimate was wrong by about two orders of magnitude: the real
> cost is 5.67M user cycles. The estimate assumed a Risc0-accelerated ECDSA path
> costing ~50k cycles; the deployed guest does not hit that path. The table above
> supersedes it.

### Reproducing the measurement

```bash
# 1. Resolve the instruction without submitting it
spel --dry-run=json --idl idl/attestation_verifier_shallow.idl.json \
     --program crates/verifier-program-spel/methods/guest-shallow/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier_shallow.bin \
     -- gated_check --presenter Public/<pubkey> $(cat gated-check.args | tr '\n' ' ') > dryrun.json

# 2. Replay the sequencer's execution and report its cycle cost
cargo run --release -p attestation-cu-bench -- \
  --elf crates/verifier-program-spel/methods/guest-shallow/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier_shallow.bin \
  --tx dryrun.json
```

Add `--json` for machine-readable output.

## Deploy + submission costs (measured on public testnet)

| Tx | Wall-clock to inclusion | Tx blob size (base64) |
|---|---|---|
| Attestation circuit deploy ([`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d)) | ~15 s (1 block) | 376,580 chars |
| Verifier program v2 deploy ([`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)) | ~15 s (1 block) | 682,360 chars |
| Verifier program v3 deploy ([`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)) | ~15 s (1 block) | ~680,000 chars |
| Confirmed `gated_check` call ([`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d)) | ~15 s (1 block) | 1,720 chars |

## How to reproduce

```bash
export RISC0_DEV_MODE=0
cargo build --release -p attestation-cli --bin attest
./target/release/attest keygen --out /tmp/p.json
./target/release/attest prove \
  --presenter /tmp/p.json --balance 1000000 --threshold 100000 \
  --context "bench" --out /tmp/c.bin 2>&1 | grep prove-metrics
```

The host process prints the `[prove-metrics]` line on stderr; capture, parse, repeat as needed.

## Limitations / caveats

- The LEZ public testnet's `getTransaction` JSON-RPC returns the raw tx blob (base64) but exposes no per-instruction CU field, and neither does the indexer RPC. The on-chain figure above is therefore obtained by replaying the sequencer's execution locally rather than by reading chain telemetry. It is the identical computation — same binary, same inputs, same executor, same session limit — but it is a faithful replay, not a value reported by the node.
- The 131,072-cycle figure at the top of this document is the **off-chain prover** cost of generating an attestation proof. It is not an on-chain cost and the two should not be added together loosely.
- The table above measures the **shallow** verifier (v3). The **deep** gate is now deployed and confirmed on the privacy path, so it is measured too. An earlier revision of this document declined to quote a deep figure on the grounds that a public transaction re-executes chained calls host-side; that rationale went stale the moment the deep gate confirmed on the privacy path, and the omission is corrected here.

  | Metric | Deep gate `gated_check` |
  |---|---|
  | Segments | 6 |
  | **User cycles** | **5,815,089** |
  | **Proving cycles (sum of 2^po2)** | **6,291,456** |
  | **Budget consumed** | **18.75 %** |

  Measured by `crates/cu-bench/tests/deep_gate_rejects.rs::report_the_deep_gate_cycle_cost`, which runs the deployed `attestation_verifier_deep.bin` through the sequencer's own executor. Reproduce with:

  ```bash
  cargo test -p attestation-cu-bench --test deep_gate_rejects -- --ignored --nocapture
  ```

  The deep gate costs about 141k more user cycles than the shallow one, which is the witness decode plus the three added bindings; both land in the same 2^po2 bucket, so the budget percentage is unchanged. **This figure is the guest's own execution only.** It excludes the privacy circuit's recursive `env::verify` of the chained attestation call, which is LEZ's cost rather than this instruction's, and which is not charged against `MAX_NUM_CYCLES_PUBLIC_EXECUTION`.
