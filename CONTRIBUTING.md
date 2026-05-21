# Contributing

LP-0005 is a focused submission for a single λPrize. Contributions are welcome — please open an issue first to discuss scope.

## Development setup

```bash
# Host toolchain
rustup toolchain install stable

# Risc0 guest toolchain
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 3.0.5
rzup install r0vm           3.0.5
```

## Running tests

```bash
# Fast unit tests (skips real-proving e2e).
cargo test --workspace --release

# Real-proving e2e tests (require Risc0 prover, ~7 s each).
cargo test --workspace --release -- --ignored
```

## Conventions

- One logical change per commit; commit messages explain *why*, not what.
- Public API changes update the relevant `crates/*/README.md`.
- Cryptographic constants always have a `# source:` line linking back to `_external/lez/...` or the design doc.
- New gate semantics ship with at least one negative test.
- No `Co-Authored-By` lines in commits.

## Reviewing pull requests

- Read [`docs/recon.md`](./docs/recon.md), [`docs/design.md`](./docs/design.md), and [`docs/decisions/`](./docs/decisions/) before reviewing crypto changes.
- Run the demo (`scripts/demo.sh`) before approving anything that touches the guest or the verifiers.
