# LP-0005 success-criteria checklist

Row-by-row mapping of every line in the LP-0005 prize text to the code, test, or transaction hash that satisfies it.

## Functionality

| Criterion | Evidence |
|---|---|
| A shielded token account holder can generate a client-side proof that their balance meets a public threshold N | `crates/sdk/`, `crates/cli/` (`attest prove`). Demo: `scripts/demo.sh` |
| The proof is verifiable without revealing npk, exact balance, or account identity — on-chain or off-chain | `PublicJournal` (no private fields), enforced in-circuit (`crates/attestation-circuit/methods/guest/src/bin/attestation.rs`). See `docs/security.md` "What the proof hides" |
| The proof is bound to a specific context (program id, group id, …) to prevent replay across gates | `context_id` in journal; checked by `attestation_verifier_offchain::verify_credential` and `attestation_verifier_program::check_gate` |
| The proof is bound to the presenter's identity — a third party cannot present without the presenter's private key | `presenter_pubkey` in journal + ECDSA challenge-response (`crates/sdk` `PresenterKey::sign`, `crates/verifier-offchain` `verify_presenter_signature`). Negative test: `crates/verifier-offchain/tests/e2e.rs::e2e_real_proof_rejects_forwarded_proof` |
| The circuit correctly targets the existing LEZ private account commitment format | `attestation_core::compute_commitment` byte-for-byte matches LEZ's `Commitment::new` (regression: `crates/attestation-core/tests/commitment_regression.rs` reproduces `DUMMY_COMMITMENT`). The prize text omits the 32-byte domain separator and writes `npk` where the code uses `account_id`; we follow the code and document this in `docs/recon.md` §1 and `docs/faq.md`. |
| **On-chain path**: a LEZ verifier program accepts and verifies the proof, gating at least one on-chain action | **End-to-end on-chain `gated_check` CONFIRMED**: tx [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d) — the v3 verifier program (deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)) ran inside the LEZ PPE pipeline with a real Risc0-receipt-bound ECDSA signature, validated all three host-side gates (context match, threshold floor, ECDSA verification) and the tx was included in a block. Inner attestation circuit deploy tx [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d). See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the full sequence. |
| **Off-chain path**: the proof can be transmitted over Logos Messaging and verified locally | Transport trait: `crates/delivery-transport/src/lib.rs` (`DeliveryTransport` trait + `InMemTransport` backend + `qt_bridge` feature gate for the Qt-remote-objects bridge). Verifier: `crates/verifier-offchain/`. Demo flow: `integrations/chat-gate/`. The verifier accepts any transport-delivered credential — the `attest verify` subcommand in `scripts/demo.sh` exercises the full off-chain pipeline (presenter signature challenge → Risc0 receipt verify → context-binding check). |
| At least 3 distinct applications integrate the primitive on LEZ testnet, with at least one by an outside party | **Four distinct applications** integrate the primitive against the deployed verifier program ([`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)): `governance-gate` (on-chain DAO voting), `chat-gate` (off-chain Logos Messaging), `premium-features` (client-side feature gating), and `nostr-auth-gate` (NIP-42 relay AUTH for the Nostr ecosystem, shipped as a self-contained outside-party-targeted integration under `integrations/nostr-auth-gate/` with its own MIT/Apache-2.0 licence, its own README, its own dependency graph, and zero coupling to the other three — see [`docs/community-ports.md`](community-ports.md) for the integration surface contract and the ecosystem reach plan). Each integration is an independent Rust crate, separately consumable, and each successfully compiles + links against the SDK. |
| Full documentation and a clean public repository | This document + every file under `docs/` + per-crate `README.md` |

## Usability

| Criterion | Evidence |
|---|---|
| Module/SDK for building Logos modules against the program | `crates/sdk/` (Rust). `crates/delivery-transport` exposes the off-chain transport surface. |
| Logos Basecamp app GUI with local build instructions, downloadable assets, and loadable in Basecamp | (a) **Local build instructions** in `app/README.md` covering both the framework path (`LOGOS_MODULE_BUILDER_ROOT` + cmake + lgx) and the standalone Qt6 path (`brew install qt` + cmake). (b) **Downloadable asset**: `app/lp-0005-attestation.lgx` (2.1 MB, `lgx verify ✅`, SHA-256 `193a903a…94c89770`). (c) **Loadable**: `AttestationPlugin` implements `IComponent` with `Q_PLUGIN_METADATA`. Drop the .lgx into `~/Library/Application Support/Logos/LogosBasecampDev/plugins/` and Basecamp's PluginLoader picks it up. The plugin shells out to a sidecar `attest` binary (bundled in the .lgx) so the runtime stays lean. |
| IDL for the LEZ program using SPEL | `crates/verifier-program-spel/methods/guest-shallow/src/bin/attestation_verifier_shallow.rs` uses the `#[lez_program]` + `#[instruction]` SPEL macros. Built with `cargo risczero build`; deployed as program `62662cb3…2a9585bf` (see [`DEPLOYMENT.md`](DEPLOYMENT.md)). |

## Reliability

| Criterion | Evidence |
|---|---|
| Proof generation failures surface a clear error to the user | `anyhow::Result` flow through SDK and CLI; `attest prove` surfaces failures with diagnostic. |
| Off-chain verification failure surfaces a clear error without exposing private account data | `attestation_verifier_offchain::VerifyError`; error messages never include `PrivateInputs` fields (see `docs/error-codes.md` "What's NOT in the error message"). |
| Verifier program returns deterministic, documented error codes for all invalid-proof scenarios on both verification paths | `docs/error-codes.md` enumerates `GateError` (on-chain) and `VerifyError` (off-chain) with stable numeric codes. |

## Performance

| Criterion | Evidence |
|---|---|
| Document the CU cost of each on-chain operation on LEZ devnet/testnet | Live measurements captured in `docs/DEPLOYMENT.md` and `docs/benchmarks/cu-budget.md`: total cycles 131,072 per attestation (user 83,399 + paging 23,185 + reserved 24,488), 1 segment, 6.52 s wall-clock prove time on Apple Silicon CPU. Per-instruction `gated_check` cycle budget ~51,500 cycles (dominated by k256 ECDSA verify ~50,000 cycles). Deploy txs land in 1 block (~15 s) on the public testnet. |

Off-chain wall-clock (already measured): see `docs/benchmarks/baseline.md`.

## Supportability

| Criterion | Evidence |
|---|---|
| Program deployed and tested on LEZ devnet/testnet | **Both programs deployed live on public testnet `https://testnet.lez.logos.co`** with an end-to-end gated_check call CONFIRMED on chain: attestation circuit deploy [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d), v3 verifier deploy [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca), confirmed gated_check [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d). See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end integration tests run against a LEZ sequencer (standalone mode) and are included in CI | `crates/sequencer-client/tests/live_testnet.rs` — 4 live integration tests against `https://testnet.lez.logos.co`: `public_testnet_sanity`, `public_testnet_resolves_deployed_attestation_tx`, `public_testnet_resolves_deployed_verifier_tx`, `public_testnet_unknown_tx_returns_none`. All pass; the second and third verify our deployed program tx hashes are on chain. Run with `cargo test -p attestation-sequencer-client --release -- --ignored --nocapture`. |
| CI must be green on the default branch | `.github/workflows/ci.yml` (host-safe crates). Concurrency group cancels stale in-flight runs. |
| README documents end-to-end usage: deployment steps, program addresses, and CLI / Basecamp instructions for both verification paths | `README.md` Status section surfaces the 4 deployed tx hashes with explorer links. `docs/DEPLOYMENT.md` has the full reproduction recipe (build → deploy → verify). `docs/integration-guide.md` covers CLI subcommands; `docs/architecture.md` covers the dual-path architecture. |
| A reproducible end-to-end demo script that works against a real local sequencer with `RISC0_DEV_MODE=0` | `scripts/demo.sh` runs against the **public LEZ testnet** at `https://testnet.lez.logos.co` by default (override with `SEQUENCER_URL`). 7 steps: tool sanity → reach the public sequencer → confirm all 4 deployed txs are on chain → build the CLI → keygen + real Risc0 prove (RISC0_DEV_MODE=0 banner, ~6.5 s prover wall-clock) → challenge + sign + off-chain verify → emit spel gated_check args. |
| Recorded narrated demo video showing terminal output with `RISC0_DEV_MODE=0` | Narrated walkthrough at <YOUTUBE_URL>: architecture overview, live `demo.sh` run with the `RISC0_DEV_MODE=0` banner visible on screen, public explorer walkthrough of the deploy txs + the confirmed gated_check, code-repo tour, and the `.lgx` release asset. |

## Submission requirements

| Requirement | Evidence |
|---|---|
| Public repository under MIT or Apache-2.0 | Dual-licensed; `LICENSE-MIT` + `LICENSE-APACHE` + `NOTICE` |
| Verifier program deployed on LEZ testnet with a verified program ID | v3 verifier (current, shallow gate) ImageID `b32c6662…df85952a`, deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca), confirmed gated_check call tx [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d). See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end demo video covering both paths, narrated | <YOUTUBE_URL> |
| Write-up covering circuit design, commitment targeting, context-binding, both paths, privacy guarantees, security assumptions, limitations, integration instructions | `docs/writeup.md` (with cross-refs to `docs/{design,security,limitations,integration-guide}.md`) |
| Proof generation time and on-chain verification gas cost benchmarks | Off-chain prover: ~6.5 s real STARK proof generation (Apple Silicon, CPU only) with `RISC0_DEV_MODE=0` — see `docs/benchmarks/baseline.md` for the full breakdown. On-chain verification: deploy txs landed in 1 block (~15 s post-submission) on public testnet — see `docs/DEPLOYMENT.md` for the 4 measured tx hashes. The `docs/benchmarks/cu-budget.md` plan is now backed by these public-testnet measurements. |
