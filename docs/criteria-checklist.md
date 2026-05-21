# LP-0005 success-criteria checklist

Every line in this checklist comes verbatim from the LP-0005 prize text. The "Where" column points to the artifact that satisfies the criterion, or — when the criterion can only be met by a step that still needs human action — to the place in `whats-left.md` that tracks it.

## Functionality

| Criterion | Status | Where |
|---|---:|---|
| A shielded token account holder can generate a client-side proof that their balance meets a public threshold N | ✅ | `crates/sdk/`, `crates/cli/` (`attest prove`). Demo: `scripts/demo.sh` |
| The proof is verifiable without revealing npk, exact balance, or account identity — on-chain or off-chain | ✅ | `PublicJournal` (no private fields), enforced in-circuit (`crates/attestation-circuit/methods/guest/src/bin/attestation.rs`). See `docs/security.md` "What the proof hides" |
| The proof is bound to a specific context (program id, group id, …) to prevent replay across gates | ✅ | `context_id` in journal; checked by `attestation_verifier_offchain::verify_credential` and `attestation_verifier_program::check_gate` |
| The proof is bound to the presenter's identity — a third party cannot present without the presenter's private key | ✅ | `presenter_pubkey` in journal + ECDSA challenge-response (`crates/sdk` `PresenterKey::sign`, `crates/verifier-offchain` `verify_presenter_signature`). Negative test: `crates/verifier-offchain/tests/e2e.rs::e2e_real_proof_rejects_forwarded_proof` |
| The circuit correctly targets the existing LEZ private account commitment format | ✅ | `attestation_core::compute_commitment` byte-for-byte matches LEZ's `Commitment::new` (regression: `crates/attestation-core/tests/commitment_regression.rs` reproduces `DUMMY_COMMITMENT`). The prize text omits the 32-byte domain separator and writes `npk` where the code uses `account_id`; we follow the code and document this in `docs/recon.md` §1 and `docs/faq.md`. |
| **On-chain path**: a LEZ verifier program accepts and verifies the proof, gating at least one on-chain action | 🟡 | Kernel: `crates/verifier-program/`. SPEL wrapper skeleton: `crates/verifier-program-spel/`. Deployment + IDL generation tracked in `whats-left.md` items #1 and #3 |
| **Off-chain path**: the proof can be transmitted over Logos Messaging and verified locally | 🟡 | Transport: `crates/delivery-transport/` (trait + `inmem` backend + `qt_bridge` feature-gated stub). Verifier: `crates/verifier-offchain/`. Demo flow: `integrations/chat-gate/`. Real Logos Delivery binding tracked in `whats-left.md` item #2 |
| At least 3 distinct applications integrate the primitive on LEZ testnet, with at least one by an outside party | 🟠 | 3 in-repo integrations (`integrations/{governance-gate, chat-gate, premium-features}`). LEZ-testnet deployment tracked in `whats-left.md` #3, outside-party port in #5 |
| Full documentation and a clean public repository | ✅ | This document + every file under `docs/` + per-crate `README.md` |

## Usability

| Criterion | Status | Where |
|---|---:|---|
| Module/SDK for building Logos modules against the program | ✅ | `crates/sdk/` (Rust). `crates/delivery-transport` exposes the off-chain transport surface. |
| Logos Basecamp app GUI with local build instructions, downloadable assets, and loadable in Basecamp | 🟡 | Skeleton in `app/` (metadata.json, Main.qml, AttestationBridge). Loadable `.lgx` packaging tracked in `whats-left.md` (depends on a Qt build). |
| IDL for the LEZ program using SPEL | 🟡 | `crates/verifier-program-spel/` uses SPEL macros; `generate_idl!()` runs once the wrapper is built in a LEZ workspace checkout (ADR-002). |

## Reliability

| Criterion | Status | Where |
|---|---:|---|
| Proof generation failures surface a clear error to the user | ✅ | `anyhow::Result` flow through SDK and CLI; `attest prove` surfaces failures with diagnostic. |
| Off-chain verification failure surfaces a clear error without exposing private account data | ✅ | `attestation_verifier_offchain::VerifyError`; error messages never include `PrivateInputs` fields (see `docs/error-codes.md` "What's NOT in the error message"). |
| Verifier program returns deterministic, documented error codes for all invalid-proof scenarios on both verification paths | ✅ | `docs/error-codes.md` enumerates `GateError` (on-chain) and `VerifyError` (off-chain) with stable numeric codes. |

## Performance

| Criterion | Status | Where |
|---|---:|---|
| Document the CU cost of each on-chain operation on LEZ devnet/testnet | 🟡 | Plan + placeholder table in `docs/benchmarks/cu-budget.md`. Filled in after deployment (`whats-left.md` #3). |

Off-chain wall-clock (already measured): see `docs/benchmarks/baseline.md`.

## Supportability

| Criterion | Status | Where |
|---|---:|---|
| Program deployed and tested on LEZ devnet/testnet | 🟠 | `whats-left.md` #3 |
| End-to-end integration tests run against a LEZ sequencer (standalone mode) and are included in CI | 🟡 | Real-sequencer tests are gated on the sequencer-client transport (`whats-left.md` #4). The host CI builds the load-bearing crates and runs the gate-kernel and commitment-regression tests. |
| CI must be green on the default branch | ✅ | `.github/workflows/ci.yml` (host-safe crates). Concurrency group cancels stale in-flight runs. |
| README documents end-to-end usage: deployment steps, program addresses, and CLI / Basecamp instructions for both verification paths | 🟡 | `README.md` (quickstart, perf table) + `docs/integration-guide.md` (subcommands) + `docs/architecture.md`. Program addresses pending deployment. |
| A reproducible end-to-end demo script that works against a real local sequencer with `RISC0_DEV_MODE=0` | 🟡 | `scripts/demo.sh` runs end-to-end with `RISC0_DEV_MODE=0` against synthesized account state today. The `SEQUENCER_URL` env hook is documented for the real-sequencer mode (lands with the sequencer-client transport). |
| Recorded narrated demo video showing terminal output with `RISC0_DEV_MODE=0` | 🟠 | `scripts/record-demo.sh` is ready (asciinema). Manual recording step is in `whats-left.md` #7. |

## Submission requirements

| Requirement | Status | Where |
|---|---:|---|
| Public repository under MIT or Apache-2.0 | ✅ | Dual-licensed; `LICENSE-MIT` + `LICENSE-APACHE` + `NOTICE` |
| Verifier program deployed on LEZ testnet with a verified program ID | 🟠 | `whats-left.md` #3 |
| End-to-end demo video covering both paths, narrated | 🟠 | `whats-left.md` #7 |
| Write-up covering circuit design, commitment targeting, context-binding, both paths, privacy guarantees, security assumptions, limitations, integration instructions | ✅ | `docs/writeup.md` (with cross-refs to `docs/{design,security,limitations,integration-guide}.md`) |
| Proof generation time and on-chain verification gas cost benchmarks | 🟡 | Proving time: `docs/benchmarks/baseline.md`. Gas cost: `docs/benchmarks/cu-budget.md` (placeholder until deployment) |

## Legend

- ✅ Done in this repo
- 🟡 Partially done; remaining work explicitly tracked
- 🟠 Blocked on testnet deployment, video recording, or an outside party

Anything 🟡 / 🟠 has a corresponding row in [`docs/whats-left.md`](./whats-left.md).
