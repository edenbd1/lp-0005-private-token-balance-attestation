# Acknowledgments

This submission stands on:

- **RISC Zero** — the zkVM proving system. The guest circuit, the receipt format, the Groth16 wrap, and the assumption mechanism that lets LEZ compose program proofs all come from Risc0's stack.
- **Logos team** — the LEZ codebase (`_external/lez/`) is the canonical source for the private-account commitment format, the sequencer JSON-RPC API, and the Merkle tree semantics targeted here. Every byte layout in `attestation-core` is pinned against an `_external/lez/` reference (`nssa/core/src/commitment.rs`, `nssa/core/src/nullifier.rs`, `nssa/src/merkle_tree/mod.rs`).
- **SPEL** — the Anchor-for-LEZ framework whose `#[lez_program]` macro shapes the verifier program wrapper. `lez-multisig/` was the load-bearing template we copied from.
- **`logos-lez-rln`** — the RLN-on-LEZ implementation taught us how Logos handles per-presenter identity in ZK; we adapted the *concept* but chose secp256k1 over Poseidon to avoid Poseidon cycles inside an already SHA-256-heavy circuit.
- **The RustCrypto ecosystem** — `sha2` (in its Risc0-accelerated fork), `k256` for ECDSA, `serde` and `serde-big-array` for wire formats.

We also benefited from the recon work surfaced by the recon-mapping pass, which read the eleven cloned repos under `_external/` and translated their relevant invariants into a single reference (`docs/recon.md`).

Mistakes, omissions, and trade-off calls are ours.
