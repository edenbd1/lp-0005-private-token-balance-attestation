# premium-features (reference integration #3)

Privacy-preserving SaaS-style feature tiering. The user picks a tier (`Free` / `Pro` / `Enterprise`) and proves their balance meets the tier's threshold without revealing the actual balance. The nullifier doubles as a per-user-per-tier session identifier.

## Kernel API

```rust
impl Tier {
    pub fn minimum_balance(&self) -> u128;
    pub fn context_id(&self) -> [u8; 32];
}

impl FeatureService {
    pub fn activate(
        &mut self,
        tier: Tier,
        receipt: &Receipt,
        presenter_nonce: &[u8; 32],
        presenter_signature_der: &[u8],
    ) -> Result<PublicJournal, ActivateError>;

    pub fn tier_for(&self, nullifier: &[u8; 32]) -> Option<Tier>;
}
```

## Why this one is the "external" slot

The submission criterion says one integration must be built by a party outside the submitting team. This crate is intentionally a clean hand-off: an outside integrator only needs to pick their own tiers / thresholds / context_ids — the verification flow is the same as `chat-gate`'s.
