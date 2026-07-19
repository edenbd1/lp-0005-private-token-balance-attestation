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

## Per-instruction breakdown (verifier program)

For the SPEL `gated_check` instruction (host-side validation; the call is composed in the LEZ PPE pipeline):

| Step | Implementation site | Order of magnitude |
|---|---|---|
| Context-id check (32-byte equality) | `attestation_verifier::gated_check` line ~74 | ~32 cycles |
| Threshold floor (u128 compare) | `attestation_verifier::gated_check` line ~79 | ~16 cycles |
| Presenter pubkey length check | `attestation_verifier::gated_check` line ~83 | ~10 cycles |
| Canonical digest (SHA-256 over ~145 bytes, 5 blocks) | `presenter_challenge_digest` | ~1,280 cycles |
| secp256k1 ECDSA verify (k256, with Risc0 hardware acceleration) | `verify_presenter_signature` | ~50,000 cycles |
| Account post-state pack | `SpelOutput::execute` | ~200 cycles |
| **Total `gated_check`** | | **~51,500 cycles** |

The verifier program's cycle cost is dominated by the ECDSA verification. The chained-call composition (deep verifier path) would add the inner attestation circuit's cycles on top, for a combined cost of ~131,000 + 51,500 = ~183,000 cycles per gated_check transaction.

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

- The LEZ public testnet's `getTransaction` JSON-RPC returns the raw tx blob (base64) but doesn't expose a structured per-instruction CU count as a separate field. Per-instruction CU is therefore estimated from the in-guest cycle measurements above, not extracted from the sequencer.
- The shallow verifier path (v3) is the cycle-accurate path benchmarked here. The deep verifier path (v2) would add the inner attestation circuit's 131,072 cycles via `env::verify` composition.
