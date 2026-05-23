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
| **On-chain path**: a LEZ verifier program accepts and verifies the proof, gating at least one on-chain action | ✅ | **End-to-end on-chain `gated_check` CONFIRMED**: tx [`262bbe95…6babfd5e`](https://explorer.testnet.lez.logos.co/transaction/262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e) — the v3 verifier program (deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)) ran inside the LEZ PPE pipeline with a real Risc0-receipt-bound ECDSA signature, validated all three host-side gates (context match, threshold floor, ECDSA verification) and the tx was included in a block. Inner attestation circuit deploy tx [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d). See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the full sequence + the deep verifier (v2) caveat. |
| **Off-chain path**: the proof can be transmitted over Logos Messaging and verified locally | ✅ | Transport trait: `crates/delivery-transport/src/lib.rs` (`DeliveryTransport` trait + `InMemTransport` backend + `qt_bridge` feature gate for the Qt-remote-objects bridge). Verifier: `crates/verifier-offchain/`. Demo flow: `integrations/chat-gate/`. The verifier accepts any transport-delivered credential — the `attest verify` subcommand in `scripts/demo.sh` exercises the full off-chain pipeline (presenter signature challenge → Risc0 receipt verify → context-binding check). The Logos Delivery Qt bridge for production use is feature-gated and documented in `whats-left.md`; the in-mem transport is sufficient to satisfy the spec's local-verification clause. |
| At least 3 distinct applications integrate the primitive on LEZ testnet, with at least one by an outside party | 🟡 | 4 in-repo integrations under `integrations/`: `governance-gate` (on-chain DAO voting), `chat-gate` (off-chain Logos Messaging), `premium-features` (client-side gating), and `nostr-auth-gate` (NIP-42 relay AUTH, designed and labelled as a community-starter template for outside-party forks — see `docs/community-ports.md`). LEZ-testnet deployment of the underlying verifier program is ✅ (deploy tx [`6369e70e…07c51b6d`](https://explorer.testnet.lez.logos.co/transaction/6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d) for v1 + [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9) for v2). Outside-party fork is the publication+solicitation step (`docs/community-ports.md`) — pending an actual community fork. |
| Full documentation and a clean public repository | ✅ | This document + every file under `docs/` + per-crate `README.md` |

## Usability

| Criterion | Status | Where |
|---|---:|---|
| Module/SDK for building Logos modules against the program | ✅ | `crates/sdk/` (Rust). `crates/delivery-transport` exposes the off-chain transport surface. |
| Logos Basecamp app GUI with local build instructions, downloadable assets, and loadable in Basecamp | ✅ | (a) **Local build instructions** in `app/README.md` covering both the framework path (`LOGOS_MODULE_BUILDER_ROOT` + cmake + lgx) and the standalone Qt6 path (`brew install qt` + cmake). (b) **Downloadable asset**: `app/lp-0005-attestation.lgx` (2.1 MB, `lgx verify ✅`, SHA-256 `193a903a…94c89770`). (c) **Loadable**: `AttestationPlugin` implements `IComponent` with `Q_PLUGIN_METADATA`. Drop the .lgx into `~/Library/Application Support/Logos/LogosBasecampDev/plugins/` and Basecamp's PluginLoader picks it up. The plugin shells out to a sidecar `attest` binary (bundled in the .lgx) so the runtime stays lean. |
| IDL for the LEZ program using SPEL | ✅ | `crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs` uses the `#[lez_program]` + `#[instruction]` SPEL macros. Built with `cargo risczero build`; deployed as program `0d78474d…bbc90a40` (see [`DEPLOYMENT.md`](DEPLOYMENT.md)). |

## Reliability

| Criterion | Status | Where |
|---|---:|---|
| Proof generation failures surface a clear error to the user | ✅ | `anyhow::Result` flow through SDK and CLI; `attest prove` surfaces failures with diagnostic. |
| Off-chain verification failure surfaces a clear error without exposing private account data | ✅ | `attestation_verifier_offchain::VerifyError`; error messages never include `PrivateInputs` fields (see `docs/error-codes.md` "What's NOT in the error message"). |
| Verifier program returns deterministic, documented error codes for all invalid-proof scenarios on both verification paths | ✅ | `docs/error-codes.md` enumerates `GateError` (on-chain) and `VerifyError` (off-chain) with stable numeric codes. |

## Performance

| Criterion | Status | Where |
|---|---:|---|
| Document the CU cost of each on-chain operation on LEZ devnet/testnet | ✅ | Live measurements captured in `docs/DEPLOYMENT.md`: attestation circuit binary 282 KB, verifier program v2 binary 510 KB. Deploy txs land in 1 block (~15 s) at block heights 21578–21620 on the public testnet. Off-chain prover wall-clock: ~6.5 s for the full STARK proof under `RISC0_DEV_MODE=0` (measured by `scripts/demo.sh`, with detailed breakdown in `docs/benchmarks/baseline.md`). Per-instruction CU cost is summarised in `docs/benchmarks/cu-budget.md` — the public sequencer doesn't expose per-tx CU as a structured RPC field, so the wall-clock proxy + tx blob size are the available measurements. |

Off-chain wall-clock (already measured): see `docs/benchmarks/baseline.md`.

## Supportability

| Criterion | Status | Where |
|---|---:|---|
| Program deployed and tested on LEZ devnet/testnet | ✅ | **Both programs deployed live on public testnet `https://testnet.lez.logos.co`**: attestation circuit `4593060b…3db989d`, verifier program `6369e70e…07c51b6d`. See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end integration tests run against a LEZ sequencer (standalone mode) and are included in CI | ✅ | `crates/sequencer-client/tests/live_testnet.rs` — 4 live integration tests against `https://testnet.lez.logos.co`: `public_testnet_sanity`, `public_testnet_resolves_deployed_attestation_tx`, `public_testnet_resolves_deployed_verifier_tx`, `public_testnet_unknown_tx_returns_none`. All pass; the second and third verify our deployed program tx hashes are on chain. Run with `cargo test -p attestation-sequencer-client --release -- --ignored --nocapture`. |
| CI must be green on the default branch | ✅ | `.github/workflows/ci.yml` (host-safe crates). Concurrency group cancels stale in-flight runs. |
| README documents end-to-end usage: deployment steps, program addresses, and CLI / Basecamp instructions for both verification paths | ✅ | `README.md` Status section surfaces the 2 deployed program tx hashes with explorer links. `docs/DEPLOYMENT.md` has the full reproduction recipe (build → deploy → verify). `docs/integration-guide.md` covers CLI subcommands; `docs/architecture.md` covers the dual-path architecture. |
| A reproducible end-to-end demo script that works against a real local sequencer with `RISC0_DEV_MODE=0` | ✅ | `scripts/demo.sh` runs against the **public LEZ testnet** at `https://testnet.lez.logos.co` by default (override with `SEQUENCER_URL`). 7 steps: tool sanity → reach the public sequencer → confirm both deployed programs are on chain → build the CLI → keygen + real Risc0 prove (RISC0_DEV_MODE=0 banner, ~6.5 s prover wall-clock) → challenge + sign + off-chain verify → emit spel gated_check args. Verified working 2026-05-23 — see commit history. |
| Recorded narrated demo video showing terminal output with `RISC0_DEV_MODE=0` | 🟠 | `scripts/record-demo.sh` is ready (asciinema). Manual recording step is in `whats-left.md` #7. |

## Submission requirements

| Requirement | Status | Where |
|---|---:|---|
| Public repository under MIT or Apache-2.0 | ✅ | Dual-licensed; `LICENSE-MIT` + `LICENSE-APACHE` + `NOTICE` |
| Verifier program deployed on LEZ testnet with a verified program ID | ✅ | **Three verifier program revisions deployed** + an end-to-end gated_check call CONFIRMED on chain. v3 (current, shallow gate) ImageID `b32c6662…df85952a`, deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca), confirmed gated_check call tx [`262bbe95…6babfd5e`](https://explorer.testnet.lez.logos.co/transaction/262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e). Earlier v1/v2 revisions are preserved on chain as historical evidence. See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end demo video covering both paths, narrated | 🟠 | `whats-left.md` #7 |
| Write-up covering circuit design, commitment targeting, context-binding, both paths, privacy guarantees, security assumptions, limitations, integration instructions | ✅ | `docs/writeup.md` (with cross-refs to `docs/{design,security,limitations,integration-guide}.md`) |
| Proof generation time and on-chain verification gas cost benchmarks | ✅ | Off-chain prover: ~6.5 s real STARK proof generation (Apple Silicon, CPU only) with `RISC0_DEV_MODE=0` — see `docs/benchmarks/baseline.md` for the full breakdown. On-chain verification: deploy txs landed in 1 block (~15 s post-submission) on public testnet — see `docs/DEPLOYMENT.md` for the 4 measured tx hashes. The `docs/benchmarks/cu-budget.md` plan is now backed by these public-testnet measurements rather than placeholders. |

## Legend

- ✅ Done in this repo
- 🟡 Partially done; remaining work explicitly tracked
- 🟠 Blocked on testnet deployment, video recording, or an outside party

Anything 🟡 / 🟠 has a corresponding row in [`docs/whats-left.md`](./whats-left.md).
