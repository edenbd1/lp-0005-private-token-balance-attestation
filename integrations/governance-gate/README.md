# governance-gate (reference integration #1)

On-chain governance gate keyed by LP-0005 threshold proofs. A vote is only counted when the voter attaches a valid attestation that they hold at least `minimum_stake` tokens — without revealing exact balance or identity.

## Kernel API

```rust
pub fn cast_vote(
    state: &mut ProposalState,
    attestation: &PublicJournal,
    presenter_nonce: &[u8; 32],
    presenter_signature_der: &[u8],
    minimum_stake: u128,
    vote_yes: bool,
) -> Result<(), VoteError>;
```

Used nullifiers are tracked per proposal in `ProposalState.used_nullifiers` — single-use semantics per attestation per proposal.

## Status

Kernel + 3 unit tests in place. The `#[lez_program]` SPEL wrapper lands when the verifier-program shapes the on-chain wiring (see [ADR-002](../../docs/decisions/002-verifier-program-shape.md)).
