# attestation-verifier-program-spel (skeleton)

**Not in the default workspace.** This crate is a skeleton showing the intended shape of the `#[lez_program]` SPEL wrapper around `attestation-verifier-program`. It is meant to be built inside a Logos workspace checkout where SPEL framework and `nssa_core` resolve through path dependencies (see [ADR-002](../../docs/decisions/002-verifier-program-shape.md)).

## How to plug it in

1. Clone or symlink this crate into your `_external/lez/programs/attestation-verifier/`.
2. Replace the workspace-level `[patch.crates-io]` / path deps with the LEZ workspace versions of `nssa_core`, `risc0-zkvm`, and `spel_framework`.
3. Update `methods/guest/src/bin/verifier.rs` to `risc0_zkvm::guest::entry!(verifier_program::main);` — SPEL generates `main` from the `#[lez_program]` annotation.
4. `cargo build --release -p attestation-verifier-program-methods` produces the guest ELF.
5. Generate the IDL with `cargo run --bin generate_idl` (added below alongside the LEZ wiring).
6. Deploy with `just run-wallet deploy-program …` per the LEZ examples.

## Skeleton

See [`src/lib.rs`](./src/lib.rs) for the intended `#[lez_program]` shape. The handler dispatches to `attestation_verifier_program::check_gate` so the logic is shared with the host-side tests.
