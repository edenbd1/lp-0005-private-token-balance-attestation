# ADR-002 — Verifier program shape (SPEL wrapping)

Date: 2026-05-22
Status: Accepted and shipped — both deep and shallow guests deployed on the public LEZ testnet (see `docs/DEPLOYMENT.md`).

## Context

The on-chain verifier program must accept an LP-0005 attestation and gate an application action. Per `docs/recon.md` §4, LEZ programs compose Risc0 proofs through `env::verify(program_id, journal)`, which the PPE outer circuit exercises automatically based on each program's declared `chained_calls` (`_external/lez/nssa/core/src/program.rs:194-228`).

Per `docs/decisions/001-architecture-and-receipt-format.md` (ADR-001), the on-chain path is "chained-call": the attestation circuit is its own program (`ATTESTATION_PROGRAM_ID`), and the verifier program references it as a chained call.

## Decision

The verifier program is structured as three pieces:

1. `crates/verifier-program/` — a **portable verification kernel** (`GateInputs`, `check_gate`) with no Logos dependencies. It depends only on `attestation-core` and `k256`. Host-testable and reusable inside any guest that needs the same gate semantics (including all four reference integrations).

2. `crates/verifier-program-spel/methods/guest/` — the **deep SPEL guest** (`#[lez_program]`), takes the journal fields + presenter signature, runs the `check_gate` semantics, and declares a `ChainedCall` to `ATTESTATION_PROGRAM_ID` so the LEZ PPE pipeline composes the inner Risc0 receipt via `env::verify`. Deployed to the public testnet (deploy tx [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)).

3. `crates/verifier-program-spel/methods/guest-shallow/` — the **shallow SPEL guest**, identical to the deep guest but without the `ChainedCall`. The shallow gate is the path the `spel` CLI can submit end-to-end today; the deep gate's chained-call composition currently requires wallet-side receipt bundling. Deployed to the public testnet (deploy tx [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)); an end-to-end `gated_check` call against it confirmed on chain at tx [`262bbe95…6babfd5e`](https://explorer.testnet.lez.logos.co/transaction/262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e).

## Why a portable kernel

- We test gate semantics with unit tests against synthesized `PublicJournal` values, no Risc0 host required.
- The same kernel can run inside the off-chain verifier and the on-chain verifier program with identical semantics — there is one source of truth for context binding, threshold checking, and signature verification.
- Each reference integration (governance gate, chat gate, premium features, nostr-auth-gate) builds on `check_gate` rather than reimplementing the rules.

## Why two on-chain variants

Shipping both lets us:

- Demonstrate the architecturally-ideal chained-call composition (deep guest) — the design intent.
- Demonstrate a confirmable end-to-end gated_check today (shallow guest) — the deployed reality.

Both share the same host-side validation logic; only the `ChainedCall` declaration differs. When the wallet's receipt-bundling support lands upstream, the deep guest becomes the canonical path and the shallow guest stays available as a defense-in-depth fallback.
