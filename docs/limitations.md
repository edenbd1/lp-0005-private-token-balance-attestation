# Known limitations

## Identity binding does not stop voluntary collusion

A proof is bound to a presenter pubkey via a challenge-response signature. This stops *passive* forwarding (Bob can't present Alice's proof without Alice's secret key). It does **not** stop voluntary collusion (Alice can sign on Bob's behalf, or share her secret key). Voluntary delegation is out of scope.

## The Merkle root is prover-chosen, on both paths

**This is the most important limitation in this document, and an earlier revision
of it stated the opposite. Correcting the record.**

`merkle_root` is a caller-supplied argument on every path. The circuit checks
only that the caller's own `merkle_path` folds to the caller's own
`merkle_root` (`attestation-core/src/lib.rs:222-226`). Nothing compares that root
to LEZ's commitment set. A prover can therefore invent a one-leaf tree
containing an account with any balance they like, and the attestation will prove
successfully.

What the proof establishes, stated precisely:

> there exists a tree with root `R` — chosen by the prover — containing a leaf
> whose commitment is well-formed under the LEZ format and whose balance is at
> least `N`, and the prover holds the secp256k1 key bound into the journal.

Anchoring `R` to real chain state is the verifier's job, and neither path does it
for you today:

- **On-chain.** A previous version of this file claimed the sequencer enforces
  `merkle_root ∈ root_history` at inclusion time. It does not. LEZ does check
  `root_history.contains(digest)` (`lee/state_machine/src/state.rs:302-306`), but
  for the `CommitmentSetDigest` bound to a *private-account spend* in
  `message.new_nullifiers` — a different value, structurally unrelated to the
  `merkle_root` argument of `gated_check`. A prover can present a genuine digest
  for an account they really own while feeding a fabricated root to the gate in
  the very same transaction. The two are not tied together.
- **Off-chain.** No enforcement either. The recipient must know which roots are
  current and reject anything outside its freshness window.

**What integrators must do.** Fetch the current root from the sequencer and
compare it against `journal.merkle_root` before honouring an attestation. Until
that check is in place, the primitive proves possession of a private key over a
self-declared account, not a balance.

**Why it is not fixed in-program.** A LEZ program guest receives four inputs
(`lee/state_machine/src/program.rs:89-110`) and has no syscall to read the
commitment-set root, so the guest cannot perform the comparison itself on v0.2.0.
Closing it properly needs either a root-exposing syscall upstream, or a
sequencer-side check bound to the attestation, or the caller pinning a root the
verifying application already trusts. This is the top item for a follow-up.

## Proving cost

Real STARK proving runs in ~7 s on Apple Silicon CPU (no accelerators). On commodity x86 with no GPU this can be 2-3× slower. Production deployments should consider GPU acceleration (Risc0 supports CUDA and Metal) or batching at the user-experience layer (background proving + cached credentials).

## Off-chain transport size

A raw STARK receipt is ~300 KB; Waku, which Logos Delivery runs on, rejects
messages above **153,600 bytes**. This is not theoretical: publishing a composite
receipt returns `Message size exceeded maximum of 153600 bytes`. The Groth16 wrap
brings the credential to **1,479 bytes** measured, which publishes fine, at the
cost of ~1 min of one-shot compression on the prover side. Integrations sensitive
to first-time latency should pre-warm credentials.
`scripts/demo-offchain-gating.sh` exercises the Groth16 path end to end for this
reason.

## Off-chain transport reaches Waku over REST, not through the Qt plugin

`WakuRestTransport` talks to a Waku node's REST interface. Logos Delivery is
itself a Waku node — its `createNode` takes a `WakuNodeConf`
(`_external/logos-delivery-module/src/delivery_module_plugin.h:47-54`) — and this
transport uses the same LIP-23 content topics and the same
`{contentTopic, payload(base64), ephemeral}` envelope its `send()` builds. What it
does *not* do is go through the Qt/QML plugin surface, so it does not exercise
Logos Core's own plugin lifecycle. For a headless Rust integration that is a
feature; if your application already hosts Logos Core, prefer the plugin.

## Per-credential expiry is not enforced in-circuit

The journal exposes `merkle_root` only; there is no in-circuit "valid until block N" field. Expiry is enforced at the verifier (via the freshness window described above). This is a deliberate choice — adding an expiry field would inflate proving cost and most integrations either rely on the root window or want longer-lived credentials.

## Nullifier semantics

The nullifier is a function of `(presenter_pubkey, context_id, account_id)`. Consequences:

- The same account, presented to the same gate with the same presenter key, produces the same nullifier — so single-use semantics are natural.
- Two different presentations (different pubkeys) on the same gate from the same underlying account produce different nullifiers. The gate cannot link them. If linkability is *required* (e.g. anti-Sybil), the gate must constrain `presenter_pubkey` (e.g. via an allow-list).
- The nullifier carries no information about `account_id` beyond what `SHA256` allows.

## Compute budget on LEZ

The prize text notes that LEZ's per-transaction compute budget "may change during testnet." Our on-chain verifier program design fits within the chained-call composition model; if the budget changes such that recursive verification becomes cheaper than chained-call composition, ADR-001's choice may want reconsidering.

## Logos Delivery has no Rust binding — resolved by going to the Waku layer

Logos Delivery ships as a Qt/C++ Logos Core module and exposes no Rust binding.
Rather than write an FFI shim over `liblogosdelivery`, the transport reaches the
Waku node underneath it: `createNode` takes a `WakuNodeConf`
(`_external/logos-delivery-module/src/delivery_module_plugin.h:47-54`), so Logos
Delivery *is* a Waku node. `crates/delivery-transport/src/waku_rest.rs` publishes
and subscribes over that node's REST interface, using the same LIP-23 content
topics and the same envelope Delivery's `send()` builds.

`scripts/demo-offchain-gating.sh` runs it: two real Waku nodes, peered, with a
credential crossing between them and gating admission to a chat group. The
remaining gap is the Qt plugin surface itself, noted in the section above.

## SPEL wrapper for the verifier program — now in-tree

Resolved. `crates/verifier-program-spel/methods/guest-deep/` is a full
`#[lez_program]` building against upstream `spel-framework` v0.6.0 and
`lee_core` v0.2.0, deployed on the public testnet. The host-testable kernel in
`crates/verifier-program/` remains the shared gate semantics.
