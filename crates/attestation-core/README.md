# attestation-core

Shared types and helpers used by both the LP-0005 Risc0 guest and the host SDK.

`no_std + alloc` so the same crate compiles into the guest under `riscv32im-risc0-zkvm-elf`.

## What's here

- `COMMITMENT_PREFIX`, `PRIVATE_ACCOUNT_ID_PREFIX`, `NULLIFIER_PREFIX` — 32-byte domain separators.
- `compute_commitment` — reproduces `_external/lez/nssa/core/src/commitment.rs:51-78` byte-for-byte.
- `derive_account_id` — reproduces `_external/lez/nssa/core/src/nullifier.rs:19-32`.
- `fold_merkle_path` — leaf-to-root folding with the LEZ tree's `SHA256(L || R)` convention.
- `compute_nullifier` — LP-0005's nullifier scheme.
- `PrivateInputs`, `PublicJournal` — wire types for the guest's `env::read` / `env::commit`.

## Regression coverage

`tests/commitment_regression.rs` and `tests/account_id_regression.rs` pin our outputs to LEZ's published test vectors. Run with `cargo test -p attestation-core`.
