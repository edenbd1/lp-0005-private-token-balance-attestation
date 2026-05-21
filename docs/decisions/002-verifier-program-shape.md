# ADR-002 — Verifier program shape (SPEL wrapping)

Date: 2026-05-22
Status: Accepted (sketch only — real wiring deferred to next iteration)

## Context

The on-chain verifier program must accept an LP-0005 attestation and gate an application action. Per `docs/recon.md` §4, LEZ programs compose Risc0 proofs through `env::verify(program_id, journal)`, which the PPE outer circuit exercises automatically based on each program's declared `chained_calls` (`_external/lez/nssa/core/src/program.rs:194-228`).

Per `docs/decisions/001-architecture-and-receipt-format.md` (ADR-001), the on-chain path is "chained-call": the attestation circuit is its own program (`ATTESTATION_PROGRAM_ID`), and the verifier program references it as a chained call.

## Decision

The verifier program is structured as two pieces:

1. `crates/verifier-program/` — a **portable verification kernel** (`GateInputs`, `check_gate`) with no Logos dependencies. It depends only on `attestation-core` and `k256`. This is host-testable and reusable inside any guest that needs the same gate semantics (including all three reference integrations).
2. A **Logos wrapper** — added when we vendor the Logos workspace toolchain or work inside `_external/lez`. The wrapper is a `#[lez_program]` module that:
   - takes the attestation journal, gate parameters, and the presenter signature as instruction args
   - calls `check_gate`
   - declares the chained call to `ATTESTATION_PROGRAM_ID` (via `ChainedCall::new`, see `_external/lez/nssa/core/src/program.rs:207-221`)
   - returns `SpelOutput::execute(post_states, chained_calls)`

The wrapper is intentionally not committed to this repo yet because:
- SPEL framework (`spel_framework::prelude::*`) only resolves inside a Logos workspace checkout where its path-deps wire up cleanly.
- The exact `pre_states` shape for chained_calls depends on the PPE pipeline's account model, which the recon report flagged as needing one more pass before we land it.

## Plan to add the SPEL wrapper

1. Inside `_external/lez`, copy `lez-multisig/multisig_program/` as a starter.
2. Replace its instructions with a single `gated_check` that calls `attestation_verifier_program::check_gate` and emits a `ChainedCall::new(ATTESTATION_PROGRAM_ID, …)`.
3. Generate the IDL via `generate_idl!()`.
4. Deploy and verify against a local sequencer (`cargo run --features standalone -p sequencer_service sequencer/service/configs/debug`).
5. Land the wrapper as `crates/verifier-program-spel/` in this repo with the matching `methods/` build wrapper.

Until then, the kernel in `crates/verifier-program/` covers the **logical** verification — all SPEL adds is the proof composition glue and on-chain state plumbing.

## Why a portable kernel

- We test gate semantics with unit tests against synthesized `PublicJournal` values, no Risc0 host required.
- The same kernel can run inside the off-chain verifier and the on-chain verifier program with identical semantics — there is one source of truth for context binding, threshold checking, and signature verification.
- Each reference integration (governance gate, chat gate, third use case) builds on `check_gate` rather than reimplementing the rules.
