# attestation-circuit

The LP-0005 Risc0 guest + host harness.

## Layout

- `methods/` — `risc0-build` wrapper that produces `ATTESTATION_ELF` and `ATTESTATION_ID`.
- `methods/guest/` — the guest crate (its own workspace, built under the `riscv32im-risc0-zkvm-elf` toolchain).
- `src/bin/baseline.rs` — a host harness that prints proving time, receipt size, and verification time.

## In-circuit assertions

1. `account_id = derive_account_id(npk, identifier)` matches LEZ.
2. `commitment = compute_commitment(account_id, program_owner, balance, nonce, data_hash)` matches LEZ.
3. `fold_merkle_path(SHA256(commitment), leaf_index, merkle_path) == journal.merkle_root`.
4. `balance >= journal.threshold`.
5. `journal.nullifier == compute_nullifier(journal.presenter_pubkey, journal.context_id, account_id)`.

## Build & measure

```bash
cargo build --release -p attestation-circuit --bin baseline
RISC0_DEV_MODE=0 ./target/release/baseline    # real STARK
RISC0_DEV_MODE=1 ./target/release/baseline    # dev sanity
```

Numbers are tracked in [`docs/benchmarks/baseline.md`](../../docs/benchmarks/baseline.md).
