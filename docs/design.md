# LP-0005 — Cryptographic Design

Companion to [`docs/recon.md`](./recon.md) and [`docs/decisions/001-architecture-and-receipt-format.md`](./decisions/001-architecture-and-receipt-format.md).

## 1. Goal statement (one sentence)

Given a private LEZ token account holding `balance` tokens under a Merkle-anchored commitment, produce a proof that `balance >= N` for a public threshold `N`, **bound to** a public application context and to a presenter who controls a private key — without revealing the account's `npk`, exact balance, identity, or any other private state — and let any verifier check the proof either through a LEZ on-chain program or off-chain from a Logos Messaging payload.

## 2. Private and public values

### Private (witnessed by the prover, never on the journal)

| Symbol | Type | Source / role |
|---|---|---|
| `npk` | `[u8; 32]` | Nullifier public key of the account holder. |
| `identifier` | `[u8; 32]` | Per-account identifier used to derive `account_id`. |
| `account_id` | `[u8; 32]` | Equal to `AccountId::for_regular_private_account(npk, identifier)` (verified inside the circuit). |
| `program_owner` | `[u32; 8]` | Token program ID owning the holding account. |
| `balance` | `u128` | The value being attested to. |
| `nonce` | `u128` | Account nonce. |
| `data_hash` | `[u8; 32]` | `SHA256(account.data)`. The data is not needed inside the circuit. |
| `merkle_path` | `Vec<[u8; 32]>` | Sibling hashes from leaf-up. |
| `leaf_index` | `u64` | 0-based index of the commitment inside the set. |
| `presenter_seed` | `[u8; 32]` | Seed `s` such that `presenter_pubkey = secp256k1_pubkey(s)`. |

### Public (committed to the Risc0 journal)

| Symbol | Type | Role |
|---|---|---|
| `merkle_root` | `[u8; 32]` | Root the proof is anchored to. |
| `threshold` | `u128` | The attested `N`. |
| `context_id` | `[u8; 32]` | Application context (program id, group id, ...). |
| `presenter_pubkey` | `[u8; 33]` | secp256k1 compressed. Used at presentation. |

## 3. Statements proved inside the circuit

1. `account_id == AccountId::for_regular_private_account(npk, identifier)`
2. `commitment == SHA256( COMMITMENT_PREFIX ‖ account_id ‖ program_owner_LE ‖ balance_LE ‖ nonce_LE ‖ data_hash )` — matching `lez/nssa/core/src/commitment.rs:51-78` byte-for-byte
3. `leaf == SHA256(commitment)` — leaf hashing per `lez/nssa/src/merkle_tree/mod.rs:146-157`
4. Folding `merkle_path` from `leaf` per `leaf_index` yields `merkle_root`
5. `balance >= threshold` — range constraint
6. `presenter_pubkey == secp256k1_pubkey(presenter_seed)` — proof of secret-key knowledge

No equality on `balance` is exposed; only the threshold check.

## 4. Replay & forwarding defenses

### 4a. Context binding (anti-replay across gates)

`context_id` is part of the journal. Each gate (program, chat group, app) picks a unique `context_id` and the verifier refuses any proof that doesn't carry the matching id. A proof minted for "governance program P" can't be reused at "chat group G".

### 4b. Identity binding (anti-forward)

The Risc0 proof commits to `presenter_pubkey` but is otherwise transferable. To prevent Alice from forwarding her proof to Bob:

1. Verifier (on-chain or off-chain) draws a fresh nonce `c ∈ {0,1}^256`.
2. Presenter signs `H(c ‖ context_id ‖ merkle_root ‖ threshold)` with the secret key matching `presenter_pubkey`.
3. Verifier accepts iff the Risc0 proof is valid **and** the signature is valid under `presenter_pubkey`.

Forwarding the proof alone is useless: Bob doesn't have the private key.

**Remaining limitation:** Alice can collude with Bob by signing on his behalf — but then Alice is necessarily participating. We can't prevent voluntary collusion; we only prevent passive forwarding.

### 4c. Why secp256k1 and not Poseidon/RLN-style

`logos-lez-rln` uses Poseidon BN254 because it natively gates on a chain that uses BN254 for its outer proofs. Our circuit is already SHA-256-heavy (5 SHA's for the commitment alone, plus the Merkle path). Adding Poseidon would roughly double the cycle count for no recognizable win. secp256k1 has a Risc0 hardware accelerator (`k256` extension), making it the cheapest in-circuit signature check.

## 5. Nullifier strategy

The prize does not strictly require a nullifier. We expose one anyway, so the same primitive can later be used for one-time-use credentials:

```
nullifier = SHA256("/lp-0005/nullifier/" ‖ presenter_pubkey ‖ context_id ‖ account_id)
```

`nullifier` is committed publicly. On-chain integrations may track used nullifiers; off-chain integrations may ignore the field. `account_id` is private; its presence inside the SHA prevents trivial collisions.

## 6. On-chain integration shape (Option A — chained-call)

```
                                            ┌── attestation program (P_att) ──┐
                                            │  guest = Risc0 circuit §3       │
                                            │  journal = §2 public            │
                                            └─────────────────────────────────┘
                                                          ▲ env::verify(P_att, journal)
                                                          │
┌── verifier / governance / app program (P_app) ───────┐
│  instruction handler:                                │
│  - read (context_id, threshold, presenter_pubkey)    │
│    from instruction args                             │
│  - read (challenge_nonce, signature) from args       │
│  - read journal from the chained P_att proof         │
│  - assert journal.context_id == expected             │
│  - assert journal.threshold == arg threshold         │
│  - verify signature with journal.presenter_pubkey    │
│  - gate the protected action                         │
└──────────────────────────────────────────────────────┘
```

Notes:
- Sequencer enforces `merkle_root ∈ root_history` automatically through the PPE pipeline; the verifier program does not need a syscall.
- Returns deterministic error codes for: stale root, threshold mismatch, context mismatch, signature failure, journal binding failure.

## 7. Off-chain integration shape (Option B — Groth16-wrapped portable proof)

```
prover:
  1. produce STARK receipt R
  2. wrap to Groth16:  R_g = compress_to_groth16(R)           // ~256 bytes
  3. craft credential C = (R_g, journal, application_meta)
  4. send via Logos Delivery to the target group/peer

verifier:
  1. receive C
  2. ask presenter for signature(challenge_nonce, journal)
  3. verify Groth16 proof against the attestation program image_id
  4. verify signature under journal.presenter_pubkey
  5. enforce business rules (context_id, threshold, expected root)
```

Logos Delivery does not ship a Rust client today (`logos-delivery-module` is Qt/C++). The SDK ships:
- a Rust trait `DeliveryTransport` modelling send/subscribe,
- a `qt-bridge` impl that shells out to a small Qt helper (initial path),
- `waku_rest::WakuRestTransport` — the working backend. Logos Delivery is a Waku node, so this
  publishes and subscribes over that node's REST interface using Delivery's own content-topic
  scheme and envelope. An FFI binding over `liblogosdelivery` would additionally exercise the Qt
  plugin surface, but is not required for headless Rust integrations.

The credential format is intentionally transport-agnostic; the trait makes the SDK testable without Logos Core present.

## 8. Threat model

| Adversary | Goal | Defended? | How |
|---|---|---|---|
| Public observer | Learn balance, npk, account_id | Yes | Only journal fields are public; balance only constrained by `≥ threshold`. |
| Verifier | Learn balance, npk, account_id | Yes | Same — verifier sees nothing extra. |
| Different gate | Replay a proof minted for gate G₁ on gate G₂ | Yes | `context_id` mismatch. |
| Pirate presenter (forwarding) | Pass a captured proof of someone else's | Yes | Must sign `challenge_nonce` under `presenter_pubkey`. |
| Honest prover, malicious recipient | Recipient reposts the proof | Partial | `context_id` blocks replays to other gates; same-gate re-use within the same nonce window is mitigated by per-presentation nonces and nullifier tracking on-chain. |
| Collusion (prover ↔ presenter) | Voluntary delegation | **Not defended** | Requires active prover participation, considered out of scope (documented). |
| Stale-root attack | Use a long-expired Merkle root | Yes (on-chain) / partial (off-chain) | On-chain: sequencer's `root_history`. Off-chain: verifier must check the root against a snapshot it trusts; staleness window is a per-application choice. |
| Sequencer DoS | Refuse to issue `getProofForCommitment` | Out of scope | Trust assumption inherited from LEZ. |

## 9. Open design decisions tracked

- secp256k1 vs ed25519 for presenter identity — Risc0 has accelerated `k256` *and* `ed25519`; both options remain on the table until baseline numbers come in.
- Whether to expose a per-credential expiry epoch in the journal. Adds 8 bytes for no extra cycles; deferred until first integration calls for it.

## 10. Mapping to success criteria

| Criterion (LP-0005 spec) | Where addressed |
|---|---|
| `balance >= N` proof from a shielded account | §3 step 5 |
| Verifiable on-chain and off-chain | §6 (on-chain) + §7 (off-chain) |
| Does not reveal npk/balance/identity | §2 (public/private split) |
| Bound to specific context | §4a (`context_id`) |
| Bound to presenter identity | §4b (signature) |
| Targets LEZ commitment format | §3 step 2 |
| Documents privacy guarantees and limits | §8 |
