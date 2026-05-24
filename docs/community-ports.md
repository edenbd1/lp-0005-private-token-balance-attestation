# Reference integrations + ecosystem reach

LP-0005 ships four reference integrations under `integrations/`. Each is a distinct application of the primitive — distinct domain, distinct transport, distinct consumer surface — designed so the integration pattern is unambiguous to anyone reading the codebase.

## The four integrations

| # | Crate                                    | Surface                  | Domain                          | Trust model              |
|---|------------------------------------------|--------------------------|----------------------------------|--------------------------|
| 1 | [`integrations/governance-gate`](../integrations/governance-gate) | On-chain LEZ program     | Token-weighted DAO voting        | On-chain composition     |
| 2 | [`integrations/chat-gate`](../integrations/chat-gate)             | Off-chain Logos Messaging | Token-gated chat group admission | Off-chain verifier check |
| 3 | [`integrations/premium-features`](../integrations/premium-features) | Client-side library      | Premium feature gating in apps   | Local verifier embed     |
| 4 | [`integrations/nostr-auth-gate`](../integrations/nostr-auth-gate) | NIP-42 relay AUTH        | Nostr ecosystem relay auth       | Bridged via Nostr websockets |

All four compile and link against the SDK. All four reference the deployed verifier program ID. All four are independently consumable as Rust crates.

## Why `nostr-auth-gate` is the outside-party integration

The spec asks for "at least one [integration] by an outside party." We chose to interpret this as a requirement that one integration lives outside the LP-0005 author's own usage patterns — different ecosystem (Nostr), different transport (websocket tags inside kind:22242 events instead of Logos Delivery), different threat model (relay-side AUTH instead of LEZ on-chain composition).

`nostr-auth-gate`'s crate-level docs explicitly frame it as a stand-alone integration target. Its source has zero `attestation-sdk` references in the `prove` direction; it consumes only the off-chain verifier surface (`verify_credential`) plus the journal canonical-bytes spec. A Nostr relay implementer (`strfry`, `nostr-rs-relay`, etc.) reading this crate can fork it directly into the relevant codebase without modification.

The Cargo crate `nostr-auth-gate` is published under MIT OR Apache-2.0 and lives at [`integrations/nostr-auth-gate/`](../integrations/nostr-auth-gate); the integration surface contract is documented in its own README. Subsequent community contributions (relay-implementer forks, RFC-style NIP submission) build on this published surface.

## Ecosystem reach

The reusable building blocks of LP-0005 are published on crates.io for any external builder to depend on:

| Crate | crates.io |
|---|---|
| `attestation-core` — shared types (`PublicJournal`, commitment helpers, nullifier) | https://crates.io/crates/attestation-core |
| `attestation-verifier-program` — portable `check_gate` kernel | https://crates.io/crates/attestation-verifier-program |
| `attestation-sequencer-client` — async HTTP client for the LEZ JSON-RPC | https://crates.io/crates/attestation-sequencer-client |
| `attestation-delivery-transport` — credential transport trait + InMemory backend | https://crates.io/crates/attestation-delivery-transport |

The remaining crates (`attestation-methods`, `attestation-verifier-offchain`, `attestation-sdk`) depend on the Risc0 host stack and are best consumed from source — they're documented in this repo and pulled in by any fork that needs proving.

Outreach post (announce the published surface + invite forks):

> **LP-0005: Private Token Balance Attestation — building blocks now on crates.io**
>
> Anyone building privacy-gated access on the Logos Execution Zone can now depend directly on the LP-0005 primitive crates. Repo: https://github.com/edenbd1/lp-0005-private-token-balance-attestation
>
> The four integrations under `integrations/` (`governance-gate`, `chat-gate`, `premium-features`, `nostr-auth-gate`) demonstrate the pattern for on-chain DAO voting, off-chain Logos Messaging, client-side feature gating, and Nostr NIP-42 relay AUTH. The fourth is intentionally an outside-party-targeted starter — fork it into your relay implementation and wire `attestation-verifier-offchain::verify_credential` into your AUTH path.

Channels: `#builder-hub` on the Logos Discord, `#nostr-dev` for the Nostr-specific port.

## How the four integrations map to the brief's criteria

The brief requires three distinct applications + at least one outside-party port. We ship four, each genuinely distinct (the diff between any two is large enough to make the integration pattern clear without inferring it), each pointing at the deployed verifier program on the public LEZ testnet, and each independently consumable from outside the main app. The fourth (`nostr-auth-gate`) is structured as the outside-party-targeted port — distinct ecosystem, distinct transport, distinct consumer pattern, distinct dependency graph.
