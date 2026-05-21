# What's left before submission

A running ledger of remaining scope. Each item links to context.

## Blocking (must be done)

| # | Item | Why |
|---|---|---|
| 1 | **Vendor the SPEL wrapper for the verifier program** inside a Logos workspace checkout (skeleton at `crates/verifier-program-spel/`, see [ADR-002](./decisions/002-verifier-program-shape.md)). | The kernel is ready and tested; only the `#[lez_program]` skin needs wiring against the LEZ workspace's path deps. |
| 2 | **Build the Logos Delivery Qt helper** (the feature-gated `qt_bridge` Rust shim is committed; the helper binary itself ships separately). | Required for the off-chain path's real-network demo. |
| 3 | **Deploy the verifier program on LEZ testnet** and record the program ID. | Submission requirement. |
| 4 | **Wire the sequencer client** (see [`sequencer-client-plan.md`](./sequencer-client-plan.md)). Wire shapes are pinned in `crates/sequencer-client/`. | Currently the SDK uses synthesized Merkle paths; real flow needs `getProofForCommitment`. |
| 5 | **Source the third integration's outside-party port** (see `integrations/premium-features/README.md`). | Submission requirement: "at least one [integration] built by a party outside the submitting team." |
| 6 | ~~CI workflow~~ — Done. `.github/workflows/ci.yml` is back, split host / guest. | Submission requirement: "CI must be green on the default branch." |
| 7 | **Record the demo video** narrating the architecture and walking through the on-chain + off-chain paths with `RISC0_DEV_MODE=0` visible. Use `scripts/record-demo.sh`. | Submission requirement. |
| 8 | **Bump receipt → Groth16 in the off-chain CLI** so credentials transmitted over Delivery fit any payload limit. | ADR-001 plan. |

## Nice-to-haves

- Property tests over `compute_commitment` and `fold_merkle_path` (`proptest`).
- A `justfile` / `xtask` for one-keystroke commands.
- A small HTML / PDF version of `writeup.md` styled for evaluators.
- Cycle benchmarks (in addition to wall-clock) using Risc0's `--profile` flag.

## Out of scope (post-submission)

- Polished Basecamp app UX (the prize says "working demos are sufficient").
- Multi-account proofs in a single circuit.
- Equality / range proofs beyond `>= threshold`.
