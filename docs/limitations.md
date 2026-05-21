# Known limitations

## Identity binding does not stop voluntary collusion

A proof is bound to a presenter pubkey via a challenge-response signature. This stops *passive* forwarding (Bob can't present Alice's proof without Alice's secret key). It does **not** stop voluntary collusion (Alice can sign on Bob's behalf, or share her secret key). Voluntary delegation is out of scope.

## Root freshness has different guarantees on each path

- **On-chain**: the LEZ sequencer enforces `merkle_root ∈ root_history` at PPE-transaction inclusion time, so on-chain integrations get freshness for free.
- **Off-chain**: there is no equivalent enforcement. The recipient must independently know which roots are "current" and reject anything older than the application's freshness window. The SDK exposes `merkle_root` so this check is straightforward, but it is the integrator's responsibility.

## Proving cost

Real STARK proving runs in ~7 s on Apple Silicon CPU (no accelerators). On commodity x86 with no GPU this can be 2-3× slower. Production deployments should consider GPU acceleration (Risc0 supports CUDA and Metal) or batching at the user-experience layer (background proving + cached credentials).

## Off-chain transport size

A raw STARK receipt is ~300 KB; Logos Delivery's default `maxMessageSize` is ~150 KB. We mitigate via Groth16 wrapping (≈ 256 bytes), but this adds ~1 min of one-shot compression work on the prover side. Integrations sensitive to first-time latency should pre-warm credentials.

## Per-credential expiry is not enforced in-circuit

The journal exposes `merkle_root` only; there is no in-circuit "valid until block N" field. Expiry is enforced at the verifier (via the freshness window described above). This is a deliberate choice — adding an expiry field would inflate proving cost and most integrations either rely on the root window or want longer-lived credentials.

## Nullifier semantics

The nullifier is a function of `(presenter_pubkey, context_id, account_id)`. Consequences:

- The same account, presented to the same gate with the same presenter key, produces the same nullifier — so single-use semantics are natural.
- Two different presentations (different pubkeys) on the same gate from the same underlying account produce different nullifiers. The gate cannot link them. If linkability is *required* (e.g. anti-Sybil), the gate must constrain `presenter_pubkey` (e.g. via an allow-list).
- The nullifier carries no information about `account_id` beyond what `SHA256` allows.

## Compute budget on LEZ

The prize text notes that LEZ's per-transaction compute budget "may change during testnet." Our on-chain verifier program design fits within the chained-call composition model; if the budget changes such that recursive verification becomes cheaper than chained-call composition, ADR-001's choice may want reconsidering.

## Logos Delivery has no Rust binding

Logos Delivery currently ships as a Qt/C++ Logos Core module (see `_external/logos-delivery-module`). We define a Transport trait so the SDK can be written and tested today, but real off-chain transmission requires either:

1. A Qt-bridge subprocess that exposes send/subscribe over a local IPC, or
2. A Rust FFI binding over `liblogosdelivery`.

Either is straightforward but neither is in-tree yet. See task #16.

## SPEL wrapper for the verifier program is not in-tree

The on-chain verifier program kernel (`crates/verifier-program/`) is host-testable and contains the full gate semantics. The `#[lez_program]` wrapper that turns it into a deployable LEZ binary lives only inside the Logos workspace and depends on path-resolved SPEL/nssa deps that don't compose cleanly with an external project. The plan to vendor or symlink the wrapper into this repo is documented in [`decisions/002-verifier-program-shape.md`](./decisions/002-verifier-program-shape.md).
