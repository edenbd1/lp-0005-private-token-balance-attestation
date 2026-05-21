# Security policy

## Reporting a vulnerability

If you find a security issue, please **do not** open a public GitHub issue.

Contact: eden.baudin.invest@gmail.com

We aim to acknowledge reports within 72 hours and provide a status update within 7 days.

## Scope

The following are in scope:

- `crates/attestation-core/` — cryptographic helpers, byte layouts.
- `crates/attestation-circuit/methods/guest/` — the Risc0 guest circuit.
- `crates/verifier-program/`, `crates/verifier-offchain/` — verification surfaces.
- `crates/sdk/`, `crates/cli/` — host-side credential generation.

Out of scope:

- Issues in upstream dependencies (`risc0-zkvm`, `k256`, `sha2`, LEZ).
- Issues in `_external/` (vendored reference repos; report upstream).
- Side-channels on the host machine outside the trust model documented in [`docs/security.md`](./docs/security.md).

## Audit status

**Unaudited.** Treat this code as a reference implementation. Do not deploy to a value-bearing context without a third-party audit.
