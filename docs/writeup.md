# LP-0005 — Submission write-up (draft)

## What we built

A reusable private balance attestation primitive for LEZ, with two verification paths exercised end-to-end:

- A Risc0 STARK proof that a shielded LEZ token account holds a balance at least equal to a public threshold `N`, without revealing the account's `npk`, exact balance, account identifier, or any other private state.
- An on-chain verifier program kernel (`crates/verifier-program/`) intended to be wrapped by a `#[lez_program]` macro and composed via `env::verify`-style chained calls.
- An off-chain verifier library (`crates/verifier-offchain/`) that consumes the same proof format and runs a presenter signature check to prevent passive forwarding.
- A high-level client SDK (`crates/sdk/`) and CLI (`crates/cli/`) that exercise the full prove / verify loop locally, and an in-memory transport stand-in (`crates/delivery-transport/`) for the Logos Delivery integration.
- Three reference integrations (`integrations/governance-gate`, `integrations/chat-gate`, `integrations/premium-features`).

## Circuit design

The guest's statements:

1. `account_id = SHA256(PRIVATE_ACCOUNT_ID_PREFIX || npk || identifier_LE)` — mirrors `lez/nssa/core/src/nullifier.rs:19-32`.
2. `commitment = SHA256(COMMITMENT_PREFIX || account_id || program_owner_LE || balance_LE || nonce_LE || data_hash)` — mirrors `lez/nssa/core/src/commitment.rs:51-78`.
3. Folding `merkle_path` from `SHA256(commitment)` at `leaf_index` yields the public `merkle_root`.
4. `balance >= threshold`.
5. `nullifier = SHA256(NULLIFIER_PREFIX || presenter_pubkey || context_id || account_id)`.

All five constants and byte layouts are pinned by regression tests against LEZ vectors (`crates/attestation-core/tests/{commitment,account_id,nullifier}_regression.rs`).

## Commitment-format reconciliation

The prize text writes the LEZ commitment as `SHA256(npk || program_owner || balance || nonce || SHA256(data))`. The actual code (`_external/lez/nssa/core/src/commitment.rs`) uses a 32-byte domain separator and binds to `account_id`, not directly to `npk`. We follow the code — the regression tests demonstrate byte-for-byte compatibility. The circuit witnesses `(npk, identifier)` and proves the derivation, so `npk` is never in the journal.

## Context binding

Every proof carries a 32-byte `context_id` in its journal. Each gate (program, chat group, app) picks a unique `context_id`; the verifier refuses proofs whose `context_id` doesn't match. This prevents replay across gates while keeping `npk` and `account_id` hidden.

## Identity binding (anti-forwarding)

A captured Risc0 receipt is by itself transferable — anyone holding the receipt could submit it to a verifier. To stop passive forwarding:

1. The proof commits to a `presenter_pubkey` (secp256k1 compressed, 33 bytes) chosen by the prover.
2. At presentation time, the verifier draws a fresh `challenge_nonce`.
3. The presenter signs `SHA256("/lp-0005/v0.1/PresenterChallenge/" || nonce || journal_fields)` with the secret key matching `presenter_pubkey`.
4. The verifier accepts iff the Risc0 receipt is valid **and** the signature verifies.

A third party who obtains the receipt but lacks the presenter's secret key cannot produce a valid signature.

**Remaining limitation:** voluntary collusion (Alice signs on Bob's behalf) is not defended; it is documented in `docs/limitations.md`.

## Two verification paths

See [ADR-001](./decisions/001-architecture-and-receipt-format.md).

- On-chain: the attestation circuit is published as its own LEZ program (`ATTESTATION_PROGRAM_ID`); the verifier program references it via `ChainedCall::new(ATTESTATION_PROGRAM_ID, …)` and lets the PPE outer circuit verify the composition through `env::verify`.
- Off-chain: the same Risc0 receipt is Groth16-wrapped (`risc0-groth16` ships transitively with Risc0 3.0.5) for transport over Logos Messaging, whose default `maxMessageSize` (≈ 150 KB) doesn't fit a raw STARK receipt (≈ 300 KB).

## Performance

Apple Silicon (CPU only), Risc0 3.0.5, `RISC0_DEV_MODE=0`:

| | Time | Bytes |
|---|---|---|
| STARK prove (guest v1) | 7.08 s | — |
| Receipt (uncompressed) | — | 300 863 |
| Receipt verify | 10 ms | — |
| ECDSA presenter check | 1 ms | — |

Full numbers and methodology in [`benchmarks/baseline.md`](./benchmarks/baseline.md).

## Privacy guarantees

The verifier learns from a successful presentation only that:

- some account in the public Merkle tree at the bound root,
- belonging to a token program with the bound `program_owner`,
- holds a balance ≥ the bound threshold,
- and the presenter controls the secret key matching the bound `presenter_pubkey`.

It learns nothing about:

- which account, which `npk`, which `identifier`,
- the exact balance,
- the account's `nonce` or `data` (only their hash),
- the Merkle path siblings.

Threat coverage and trust assumptions: [`security.md`](./security.md).

## Limitations

Documented in full at [`limitations.md`](./limitations.md). Notable items:

- Voluntary collusion is not defended.
- Off-chain root freshness is the integrator's responsibility.
- Logos Delivery has no Rust binding yet; the SDK uses a `Transport` trait and an in-memory backend for testing.
- The SPEL wrapper for the on-chain verifier program ships separately (depends on a Logos workspace checkout); ADR-002 documents the plan.

## Repository

- `crates/` — reusable libraries: `attestation-core`, `attestation-circuit`, `verifier-program`, `verifier-offchain`, `sdk`, `cli`, `delivery-transport`.
- `integrations/` — three reference integrations.
- `docs/` — design, security, limitations, integration guide, ADRs, benchmarks.
- `scripts/demo.sh` — reproducible end-to-end demo (`RISC0_DEV_MODE=0`).
