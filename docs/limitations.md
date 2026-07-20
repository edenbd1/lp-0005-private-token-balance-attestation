# Known limitations

## Identity binding does not stop voluntary collusion

A proof is bound to a presenter pubkey via a challenge-response signature. This stops *passive* forwarding (Bob can't present Alice's proof without Alice's secret key). It does **not** stop voluntary collusion (Alice can sign on Bob's behalf, or share her secret key). Voluntary delegation is out of scope.

## The Merkle root in the witness is prover-chosen, and why that no longer matters on chain

**This section has been wrong twice. First it claimed the sequencer enforced root
freshness for the gate, which it does not. Then it said the gap was open. Both
are superseded by the anchored-balance check described below.**

The witness's `merkle_root` *is* caller-supplied. The circuit only checks that the
caller's own `merkle_path` folds to the caller's own `merkle_root`
(`attestation-core/src/lib.rs:222-226`), so a prover can invent a one-leaf tree
holding any balance. On its own, that proves possession of a key over a
self-declared account.

**The on-chain gate no longer relies on it.** `gated_check` reads the balance from
the presenter's `pre_state`, not from the witness
(`attestation_verifier_deep.rs`, error `3009`). On the privacy-preserving path
that value is anchored by LEZ itself:

1. The private account appears as an authorized `pre_state`.
2. The privacy circuit computes its commitment from that exact state and folds the
   caller's membership proof into a `CommitmentSetDigest`
   (`privacy_preserving_circuit/src/output.rs:307-315`).
3. The sequencer requires that digest to be in `root_history`
   (`lee/state_machine/src/state.rs:302-306`).

A fabricated membership proof yields a digest that is not a historical root, and
the transaction is rejected. Verified both ways on a live chain: a witness
claiming 1,000,000 against an account really holding 3,000 fails with
`Program error 3009: the presenter account's on-chain balance is below the gate's
minimum`, while a legitimate witness confirms. Re-using a stale account state
fails too, because its commitment has been nullified.

**Off-chain the gap remains, and is the verifier's to close.** A recipient
verifying a credential locally has no sequencer enforcing anything, so it must
compare the root itself. The API is there:

```rust
let client = SequencerClient::public_testnet();
if !client.is_root_current(&journal.merkle_root, &known_commitment).await? {
    return Err("attestation is anchored to a root this chain does not hold");
}
```

`commitment_set_root` derives the current root by fetching a membership proof and
folding it, since LEZ exposes no dedicated root RPC.
`crates/sequencer-client/tests/root_freshness.rs` exercises both directions
against the live public testnet, and `scripts/demo-offchain-gating.sh` shows the
check refusing that demo's own synthetic root.

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
