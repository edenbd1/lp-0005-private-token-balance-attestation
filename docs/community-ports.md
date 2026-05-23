# Community ports

Strategy and tracking for the LP-0005 brief's "at least one integration by an
outside party" criterion.

## What the spec says

> At least 3 distinct applications integrate the primitive on LEZ testnet,
> with at least one by an outside party.

## What we ship in this repo

Four reference integrations are committed under `integrations/`. The first
three are end-to-end demos that exercise the SDK from the same author voice;
the fourth (`nostr-auth-gate`) is intentionally a **community-starter
template** — distinct in domain, framing, and structure — designed to be
forked into the Nostr ecosystem by an outside builder.

| # | Integration                              | Surface | Domain                        |
|---|------------------------------------------|---------|-------------------------------|
| 1 | [`integrations/governance-gate`](../integrations/governance-gate) | On-chain DAO voting gate | Token-weighted governance       |
| 2 | [`integrations/chat-gate`](../integrations/chat-gate)     | Off-chain Logos Messaging | Token-gated chat group admission |
| 3 | [`integrations/premium-features`](../integrations/premium-features) | Client-side                | Premium feature gating         |
| 4 | [`integrations/nostr-auth-gate`](../integrations/nostr-auth-gate) | NIP-42 relay AUTH         | Nostr ecosystem starter template |

## Outside-party port — solicitation status

The `nostr-auth-gate` crate is the **starter template** we publish to outside
builders. Its README and crate-level docs are framed as a template — different
problem domain (Nostr relay AUTH instead of in-house LP-0005 mechanics),
different wire format (NIP-42 tag inside a kind:22242 event), different
transport (Nostr websockets instead of Logos Delivery / in-mem).

Step-by-step solicitation plan:

1. **Publish `nostr-auth-gate` to crates.io** under its current MIT/Apache-2.0
   dual licence. The crate self-describes as a community-starter in its
   crate-root doc comment.
2. **Post the link** in the Logos `#builder-hub` Discord channel + on Nostr
   `#nostr-dev` to invite community forks.
3. **Track community forks** as they land — first community fork → update this
   table; that constitutes the outside-party port the spec asks for.

The honest evaluator note is: until a community fork actually lands, the
"outside party" half of this criterion is not strictly met — we are publishing
the surface and soliciting. The brief allows time for community ecosystem
growth post-publication; this submission is the publication step.

## Comparison vs. similar λPrize submissions

The competing LP-0005 submission (`logos-co/lambda-prize#60` by
@Tranquil-Flow) does not deploy a verifier program on LEZ testnet at all
(maintainer-accepted as a packaged verifier-model in lieu of a deployed
program ID — see his solutions/LP-0005.md). The "3 apps + outside-party"
criterion is, in that submission, marked as "tracked future work" with no
shipped 4th integration. We ship a 4th + a documented solicitation path.
