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
| **On-chain path**: a LEZ verifier program accepts and verifies the proof, gating at least one on-chain action | **The proof is verified on chain by the deep gate**, on the privacy-preserving path: the client proves locally, LEZ's privacy circuit discharges the chained call with a real `env::verify` (`execution_state.rs:149`), and the sequencer verifies the receipt against the pinned `PRIVACY_PRESERVING_CIRCUIT_ID` before applying any state (`validated_state_diff.rs:426`). **The gate also checks the anchored balance**, read from the presenter's `pre_state` rather than the caller-supplied witness: LEZ computes that account's commitment from its exact state and folds the membership proof into a digest the sequencer requires to be in `root_history`, so it cannot be fabricated. Verified both ways on a live chain, a witness claiming 1,000,000 against an account holding 3,000 fails with `Program error 3009`, a legitimate one confirms. On-chain trace: a marker PDA derived from the verifier ImageID and the attestation nullifier, owned by the verifier. Run `./scripts/verify-onchain-proof.sh`. The earlier shallow gate is retained but verifies no proof; no program on the LEZ **public** path could, since the sequencer re-executes rather than proves (`program.rs:73-77`). |
| **Off-chain path**: the proof can be transmitted over Logos Messaging and verified locally, demonstrated by a token-gated access flow | **Demonstrated end to end over a real Waku network** (`scripts/demo-offchain-gating.sh`): two independent Waku nodes are started and peered, a Groth16 credential is published from node A on a LIP-23 content topic, received on node B, verified locally, and admits the presenter to a chat group. Logos Delivery is itself a Waku node — its `createNode` takes a `WakuNodeConf` (`_external/logos-delivery-module/src/delivery_module_plugin.h:47-54`) — and `crates/delivery-transport/src/waku_rest.rs` uses the same content-topic scheme and the same `{contentTopic, payload(base64), ephemeral}` envelope its `send()` builds, reached over REST rather than through the Qt plugin (see [`limitations.md`](limitations.md)). Three negative cases are exercised over the same live transport: replay, an intercepted proof answered with a fresh challenge, and a gate demanding more than was attested. The composite receipt (~300 KB) exceeds Waku's 153,600-byte cap, which is why the demo uses the 1,479-byte Groth16 wrap. Verifier: `crates/verifier-offchain/`; flow: `integrations/chat-gate/`. |
| A standalone consumer integration demo is included; any demonstrated, testable path that exercises the primitive is acceptable | **Four in-tree integrations**, each an independently consumable Rust crate consuming the gate semantics via `attestation-verifier-program::check_gate`: `governance-gate`, `chat-gate`, `premium-features`, `nostr-auth-gate`. Two are demonstrated end to end rather than merely compiled: `scripts/demo-offchain-gating.sh` runs `chat-gate` over a real two-node Waku network, and `scripts/e2e-local.sh` runs the full on-chain round trip against a standalone sequencer from an empty chain. None hard-codes a deployed program id, so none is tied to one deployment. |
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
| Program deployed and tested on LEZ devnet/testnet | **Five programs live on `https://testnet.lez.logos.co`.** The path that verifies the proof is the deep gate: attestation `674aa03a…75726652`, verifier `7a4e46cf…e06eec0d` (ImageID `1047297a…8261b27c`), confirmed privacy-preserving `gated_check` `e8ed66c7…e7bbb4ab`, whose marker PDA address encodes the floor and context it enforced. The earlier shallow path is also deployed (`4593060b…3db989d`, `2bf10138…23723a9`, `a0ec45bb…d341c5ca`, `gated_check` `fd9869f7…eafb306d`) but performs host-side checks only. Every committed binary under `artifacts/programs/` hashes to its own deployment transaction, so the deployed bytecode is provably the bytecode in this repository. Tested from an empty chain by `scripts/e2e-local.sh`; verified on the public chain by `scripts/verify-onchain-proof.sh`. See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end integration tests run against a LEZ sequencer (standalone mode) and are included in CI | `crates/sequencer-client/tests/live_testnet.rs` — 4 live integration tests against `https://testnet.lez.logos.co`: `public_testnet_sanity`, `public_testnet_resolves_deployed_attestation_tx`, `public_testnet_resolves_deployed_verifier_tx`, `public_testnet_unknown_tx_returns_none`. All pass; the second and third verify our deployed program tx hashes are on chain. Run with `cargo test -p attestation-sequencer-client --release -- --ignored --nocapture`. |
| CI must be green on the default branch | `.github/workflows/ci.yml` (host-safe crates). Concurrency group cancels stale in-flight runs. |
| README documents end-to-end usage: deployment steps, program addresses, and CLI / Basecamp instructions for both verification paths | `README.md` Status section surfaces the 4 deployed tx hashes with explorer links. `docs/DEPLOYMENT.md` has the full reproduction recipe (build → deploy → verify). `docs/integration-guide.md` covers CLI subcommands; `docs/architecture.md` covers the dual-path architecture. |
| A reproducible end-to-end demo script that works against a real local sequencer with `RISC0_DEV_MODE=0` | `scripts/demo.sh` runs against the **public LEZ testnet** at `https://testnet.lez.logos.co` by default (override with `SEQUENCER_URL`). 7 steps: tool sanity → reach the public sequencer → confirm all 4 deployed txs are on chain → build the CLI → keygen + real Risc0 prove (RISC0_DEV_MODE=0 banner, ~6.5 s prover wall-clock) → challenge + sign + off-chain verify → emit spel gated_check args. |
| Recorded narrated demo video showing terminal output with `RISC0_DEV_MODE=0` | Narrated walkthrough at https://youtu.be/Ta18-p3sz3M: architecture overview, live `demo.sh` run with the `RISC0_DEV_MODE=0` banner visible on screen, public explorer walkthrough of the deploy txs + the confirmed gated_check, code-repo tour, and the `.lgx` release asset. |

## Submission requirements

| Requirement | Evidence |
|---|---|
| Public repository under MIT or Apache-2.0 | Dual-licensed; `LICENSE-MIT` + `LICENSE-APACHE` + `NOTICE` |
| Verifier program deployed on LEZ testnet with a verified program ID | v3 verifier (current, shallow gate) ImageID `b32c6662…df85952a`, deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca), confirmed gated_check call tx [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d). See [`DEPLOYMENT.md`](DEPLOYMENT.md). |
| End-to-end demo video covering both paths, narrated | https://youtu.be/Ta18-p3sz3M |
| Write-up covering circuit design, commitment targeting, context-binding, both paths, privacy guarantees, security assumptions, limitations, integration instructions | `docs/writeup.md` (with cross-refs to `docs/{design,security,limitations,integration-guide}.md`) |
| Proof generation time and on-chain verification gas cost benchmarks | Off-chain prover: ~6.5 s real STARK proof generation (Apple Silicon, CPU only) with `RISC0_DEV_MODE=0` — see `docs/benchmarks/baseline.md` for the full breakdown. On-chain verification: deploy txs landed in 1 block (~15 s post-submission) on public testnet — see `docs/DEPLOYMENT.md` for the 4 measured tx hashes. The `docs/benchmarks/cu-budget.md` plan is now backed by these public-testnet measurements. |
