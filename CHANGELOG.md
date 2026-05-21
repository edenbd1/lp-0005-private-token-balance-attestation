# Changelog

All notable changes to this project. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Risc0 attestation guest circuit (v1): `account_id` derivation, LEZ commitment, Merkle membership, threshold check, nullifier emission.
- Off-chain verifier library with presenter signature check.
- Verifier program portable gate kernel.
- Client SDK + `attest` CLI (`keygen`, `prove`, `verify`).
- Logos Delivery transport trait + in-memory backend.
- Three reference integrations: `governance-gate`, `chat-gate`, `premium-features`.
- End-to-end demo script (`scripts/demo.sh`).
- Documentation: design, architecture, security, limitations, integration guide, FAQ, write-up draft, ADRs.

### Skeletons (not in default workspace)
- `crates/verifier-program-spel/` — `#[lez_program]` wrapper around `check_gate`. To be dropped into a LEZ workspace checkout.
- `app/` — Basecamp app skeleton (Qt manifest, QML surface, C++ bridge). Bridge shells out to `attest` until a Qt build lands.

### Pinned
- Risc0 to 3.0.5 (matches LEZ).

### Validated
- `compute_commitment` byte-for-byte against LEZ's `DUMMY_COMMITMENT` / `DUMMY_COMMITMENT_HASH`.
- `derive_account_id` against LEZ vectors for `identifier ∈ {0, 1}`.
- Nullifier scheme against a hand-rolled vector + distinctness in context/presenter.
- `fold_merkle_path` against a depth-2 hand-built tree.

### Known limitations
- Voluntary collusion not defended (see `docs/limitations.md`).
- Off-chain root freshness is the integrator's responsibility.
- Logos Delivery has no Rust binding yet; the SDK uses a `Transport` trait.
- SPEL wrapper for the verifier program ships separately (`docs/decisions/002-verifier-program-shape.md`).
