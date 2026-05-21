# Architecture

```
                                  ┌──────────────────────────────┐
                                  │      LEZ sequencer JSON-RPC   │
                                  │   getProofForCommitment(...) │
                                  └─────────────┬────────────────┘
                                                │ MembershipProof
                                                │ (leaf_index, [siblings])
                                                ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                  Client SDK  (crates/sdk)                   │
   │                                                             │
   │   PresenterKey                ProveRequest                  │
   │      │                            │                         │
   │      ▼                            ▼                         │
   │   secp256k1                  attestation-circuit            │
   │   sign(challenge ‖ journal) → ATTESTATION_ELF (Risc0 guest) │
   │                                   │                         │
   │                                   ▼                         │
   │                              Risc0 Receipt                  │
   │                                   │                         │
   └───────────────────────────────────┼─────────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │                                             │
                ▼                                             ▼
   ┌────────────────────────┐                  ┌──────────────────────────┐
   │ on-chain (chained-call)│                  │ off-chain (Groth16 wrap) │
   │                        │                  │                          │
   │ env::verify(           │                  │ CredentialEnvelope ──▶ Logos
   │   ATTESTATION_ID,      │                  │   ┌──────────────────┐   Delivery
   │   journal)             │                  │   │ Groth16 receipt   │      │
   │     │                  │                  │   │ challenge_nonce   │      │
   │     ▼                  │                  │   │ presenter_sig DER │      │
   │ verifier-program       │                  │   │ app_meta          │      │
   │  ├─ context check      │                  │   └──────────────────┘      │
   │  ├─ threshold check    │                  │           │                  │
   │  ├─ signature verify   │                  │           ▼                  │
   │  └─ chained_call to    │                  │     recipient peer           │
   │      ATTESTATION_ID    │                  │           │                  │
   └────────┬───────────────┘                  │           ▼                  │
            │                                  │  verifier-offchain           │
            ▼                                  │   ├─ Receipt::verify         │
   ┌────────────────────────┐                  │   ├─ context check           │
   │ governance-gate        │                  │   ├─ threshold check         │
   │   tally vote           │                  │   └─ signature verify        │
   └────────────────────────┘                  │           │                  │
                                               │           ▼                  │
                                               │  chat-gate / premium-features│
                                               │  (admit / activate)          │
                                               └──────────────────────────────┘
```

## Crate map

```
attestation-core              ← shared types + commitment/Merkle/nullifier math (no_std)
attestation-circuit/          ← Risc0 guest + host harness (the proof itself)
  methods/                    ← risc0-build wrapper
  methods/guest/              ← actual guest crate (isolated workspace)
attestation-verifier-program  ← portable on-chain gate kernel (no Risc0 dep)
attestation-verifier-offchain ← off-chain proof + signature verification
attestation-delivery-transport← Logos Delivery transport trait + in-memory backend
attestation-sdk               ← high-level proving API + PresenterKey
attestation-cli               ← `attest keygen | prove | verify`

integrations/governance-gate   ← on-chain voting gated by attestation
integrations/chat-gate         ← off-chain chat group admission
integrations/premium-features  ← privacy-preserving SaaS tiering (external slot)
```

## Threat model

See [`security.md`](./security.md).

## Limitations

See [`limitations.md`](./limitations.md).

## Sequencer integration

See [`recon.md`](./recon.md) sections 2 and 3 for the `getProofForCommitment` API and the Merkle-tree shape.
