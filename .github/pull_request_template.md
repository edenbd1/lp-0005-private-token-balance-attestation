## What

A one-liner.

## Why

Link the issue, ADR, or doc passage that motivates this change.

## How

- Brief description of the approach
- Any deviation from the existing patterns?

## Verification

- [ ] `cargo test --workspace --release` passes
- [ ] `./scripts/demo.sh` still works under `RISC0_DEV_MODE=0` (if guest / verifier changed)
- [ ] If touching crypto constants: regression tests updated and rebuilt against `_external/lez`
