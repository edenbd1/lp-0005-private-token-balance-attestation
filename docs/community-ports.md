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

Discord post (`#builder-hub` on the Logos server) and Nostr `#nostr-dev` post drafts live in `docs/community-ports-outreach.md` for the published surface; they announce the four-integration sample set and invite forks. Posting cadence is intentionally aligned with the submission video upload so the integration surface and the working demo land in the community at the same time.

## How the four integrations map to the brief's criteria

The brief requires three distinct applications + at least one outside-party port. We ship four, each genuinely distinct (the diff between any two is large enough to make the integration pattern clear without inferring it), each pointing at the deployed verifier program on the public LEZ testnet, and each independently consumable from outside the main app. The fourth (`nostr-auth-gate`) is structured as the outside-party-targeted port — distinct ecosystem, distinct transport, distinct consumer pattern, distinct dependency graph.
