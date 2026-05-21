# Security notes

## What the proof hides

The Risc0 receipt's public journal contains only:

- `merkle_root` — already public; what the proof is anchored to
- `threshold` — the lower bound the account holder is attesting to
- `context_id` — application-supplied, prevents replay across gates
- `presenter_pubkey` — 33-byte secp256k1 pubkey the presenter controls
- `nullifier` — an opaque marker; preimage is `SHA256(NULLIFIER_PREFIX ‖ presenter_pubkey ‖ context_id ‖ account_id)`

Everything else is private:

- `npk` (nullifier public key) — not in the journal, even though it derives `account_id`
- `identifier` (account index) — not in the journal
- `account_id` — not in the journal; only its preimage hash via the nullifier
- `program_owner`, `balance`, `nonce`, `data_hash` — all witnessed privately
- `merkle_path` — siblings are private; only the root is public

The verifier therefore learns *nothing* about the prover's exact balance, identity, or which specific account in the commitment set was used.

## What the proof is bound to

Each proof is bound, in-journal, to:

- A specific Merkle root (the snapshot it claims membership against).
- A specific threshold value.
- A specific context (`context_id`).
- A specific presenter pubkey.

A proof minted with these four bound values cannot be repurposed to a different gate, a different threshold, or a different root — those would all fail an in-program assertion. A proof can be replayed by the same presenter at the same gate within the staleness window; integrations that care about one-shot semantics consume the nullifier.

## How forwarding is prevented

The Risc0 receipt by itself is a transferable credential. To prevent passive forwarding:

1. The verifier draws a fresh `challenge_nonce` per presentation.
2. The presenter signs `H(/lp-0005/v0.1/PresenterChallenge/ ‖ challenge_nonce ‖ journal_fields…)` with the private key matching `presenter_pubkey`.
3. The verifier checks both (a) the Risc0 receipt and (b) the signature under the journal's `presenter_pubkey`.

A third party who obtains the receipt but lacks the presenter's secret key cannot produce a valid signature, so the verifier rejects.

## Threats considered

| Adversary | Goal | Mitigation |
|---|---|---|
| Public observer | Learn balance / npk / account_id | Only journal fields are public. |
| Verifier (honest-but-curious) | Learn private state | Same — no extra channel. |
| Different gate | Replay across applications | `context_id` mismatch. |
| Stale-root attack | Use a long-expired root on-chain | Sequencer's `root_history` (PPE pipeline). |
| Stale-root attack off-chain | Use an expired root in a peer-to-peer flow | Application picks a freshness window and rejects older roots. |
| Forwarding | Bob presents Alice's proof | secp256k1 challenge-response (`presenter_pubkey`). |
| Replay at same gate | Alice presents a previously-seen proof | Nullifier tracking in integration storage. |
| Collusion (Alice ↔ Bob, voluntary) | Alice signs on Bob's behalf | **Not defended.** Requires Alice's active participation; out of scope. |
| Compromised presenter sk | Attacker presents proofs as Alice | Reduces to standard key-management. Pubkey rotation tracked outside this primitive. |
| Sequencer DoS | Refuse `getProofForCommitment` | Inherited LEZ trust assumption. |
| Risc0 prover bug | Forge a proof that passes verification | Inherited Risc0 trust assumption. |

## In-circuit assertions (must all hold for a valid proof)

1. `account_id = SHA256(PRIVATE_ACCOUNT_ID_PREFIX ‖ npk ‖ identifier_LE)`
2. `commitment = SHA256(COMMITMENT_PREFIX ‖ account_id ‖ program_owner_LE ‖ balance_LE ‖ nonce_LE ‖ data_hash)`
3. Folding `merkle_path` from `SHA256(commitment)` at `leaf_index` yields `merkle_root`
4. `balance >= threshold`
5. `nullifier = SHA256(NULLIFIER_PREFIX ‖ presenter_pubkey ‖ context_id ‖ account_id)`

## Inherited trust

We trust:

- The Risc0 STARK prover (no soundness bug).
- The Risc0 secp256k1 accelerator (no implementation bug).
- The LEZ sequencer for root freshness on-chain.
- `k256` (RustCrypto) for off-chain ECDSA verification.

## Notes on audits

This primitive has **not** been audited. Treat it as a reference implementation; do not deploy to mainnet without an audit pass.
