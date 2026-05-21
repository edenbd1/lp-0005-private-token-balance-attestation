# ADR-001 — Verification architecture and receipt format

Date: 2026-05-22
Status: Accepted

## Context

LP-0005 requires two verification paths:

- **On-chain**: a LEZ verifier program that gates on-chain actions.
- **Off-chain**: a proof transmitted over Logos Messaging and verified locally.

Two findings from `docs/recon.md` shape the decision:

1. LEZ programs compose Risc0 proofs **through `env::verify(program_id, journal)`** (the Risc0 assumption mechanism, exercised by the privacy-preserving outer circuit at `lez/program_methods/guest/src/bin/privacy_preserving_circuit/execution_state.rs:149`). There is **no idiomatic path** for a user program to call `Receipt::verify` on a user-supplied receipt byte blob.
2. The Risc0 outer `Receipt` serializes to ≈ 224 KB borsh `InnerReceipt` (per `lez/docs/benchmarks/cycle_bench.md`). Logos Messaging's default `maxMessageSize` is ≈ 150 KB.

## Decision

**Both architectures, in parallel:**

### A. On-chain — chained-call program

Our attestation circuit is published as its own LEZ program (program_id `P_att`). The verifier program (and any reference integration) accepts the attestation as a chained call:

```rust
// inside the verifier program's guest
env::verify(P_att, &journal_words);
// journal_words contains: merkle_root, threshold_N, context_id, presenter_pubkey
```

This is the cheapest, idiomatic path; the assumption mechanism folds the attestation proof into the outer PPE proof.

### B. Off-chain — Groth16-wrapped portable receipt

For Logos Messaging transport and local verification we Groth16-wrap the outer receipt:

```
Risc0 STARK Receipt (~224 KB)  --Groth16 wrap-->  ~256 bytes
```

The wrapped proof:
- fits in any Logos Messaging payload,
- is self-contained (no on-chain transaction required to verify),
- can be verified locally with a constant-time `risc0_zkvm::Groth16Receipt::verify` call.

**Fallback if Risc0 3.0.5 Groth16 wrap is unavailable or unstable:** chunked transport over Logos Messaging (split + reassemble), with a documented size penalty.

## Why not "raw receipt as instruction argument" (Option B-on-chain)?

Reviewed but rejected for the on-chain path:
- ≈ 224 KB instruction data is impractical given LEZ's compute budget.
- Recursive verification inside our guest would dominate proving time.
- Diverges from every existing LEZ program pattern — would make the submission harder to evaluate.

The same Groth16-wrapped receipt produced for the off-chain path can, in principle, be submitted on-chain too; but that becomes redundant with path A and we don't budget for it.

## Identity binding choice

Use a standard ECDSA pubkey (`secp256k1`, Risc0 has an accelerator) for `presenter_pubkey`. The circuit commits it into the journal; at presentation time the prover signs `(verifier_nonce ‖ context_id)` and the verifier checks the signature against the journal-committed pubkey.

Rejected: Poseidon-based id-commitment à la RLN. Logos's RLN program does use Poseidon BN254 (`logos-lez-rln`), but adopting it would force Poseidon cycles into a circuit already paying SHA-256 cost for commitment reconstruction. ECDSA is uniform with the rest of the off-chain stack.

## Consequences

- We publish an attestation program separately from the verifier program — two `lez_program` binaries.
- Build pipeline must produce two artifacts: the attestation program binary, and the Groth16-wrapped receipt blob.
- Documentation must explain why we deviate from the prize text's literal "submit a receipt to a verifier program" wording — point to the LEZ codebase patterns.
