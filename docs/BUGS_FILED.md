# Logos tooling friction encountered

Rough edges hit while building LP-0005, each reproduced rather than inferred.
Recorded here because they cost real time and the workarounds are not obvious.
Nothing here is a blocker: everything below has a workaround already applied in
this repository.

## The explorer does not show a privacy-preserving transaction that the sequencer holds

**Observed 2026-07-20 on the public testnet.**

`gated_check` tx `a77fe12b7027247651580fab5b3de5203ce564f8ac1fa46d8d0c9c865f4ff731`
resolves through `getTransaction` on `https://testnet.lez.logos.co`, but
`https://explorer.testnet.lez.logos.co/transaction/a77fe12b…` answers
`Transaction not found`. The marker PDA page likewise showed the default program
owner where `getAccount` reported the verifier program.

This is not indexing lag. The transaction landed at a height at or below block
28481, and the indexer head passed 28589 while still not showing it, a gap of
over a hundred blocks that kept widening. Other transaction types index fine,
including a privacy-preserving transfer submitted the same day, so it is not
privacy transactions as a class.

**Workaround:** `scripts/verify-onchain-proof.sh` reads the chain through
`getTransaction` and decodes the transaction bytes directly, so it does not
depend on the indexer.

## `spel --help` exits non-zero

`spel --help` prints usage and exits `1`. That makes it unusable as a liveness
probe, which cost a CI failure on a step that had in fact installed correctly:
the log read `Installed package spel v0.6.0` immediately followed by our own
`spel did not install`.

**Workaround:** probe with `command -v spel`, and exercise a real subcommand such
as `spel program-id <binary>`.

## The `spel` crate is named `spel`, not `spel-cli`

`spel-cli` is the directory inside the repository; the package is `spel`. So
`cargo install --git https://github.com/logos-co/spel --tag v0.6.0 spel-cli`
fails with `could not find spel-cli`. Worth a line in the README.

## `#[lez_program]` emits `nssa_core::` paths against a crate named `lee_core`

The macro in `spel-framework-macros` generates code referencing `nssa_core::`,
while the dependency it needs is `lee_core` since LEZ v0.2.0. A guest crate must
therefore alias it:

```toml
nssa_core = { git = "...logos-execution-zone.git", tag = "v0.2.0", features = ["host"], package = "lee_core" }
```

which is what `spel-framework/Cargo.toml:14` itself does. Without the alias the
build fails with `cannot find module or crate nssa_core`, and the cause is not
visible from the guest source.

## The risc0 guest toolchain pins rustc 1.88, which several crates have outgrown

`cargo risczero build` fails with
`rustc 1.88.0-dev is not supported by the following packages`. Two hit us:
`enum-ordinalize` and `enum-ordinalize-derive` (both need 1.89, reached through
`risc0-zkvm → risc0-groth16 → ark-bn254 → ark-ec → educe`), plus `ruint` 1.18.

**Workaround:** pin in the guest lockfile.

```bash
cargo update -p enum-ordinalize --precise 4.3.2
cargo update -p enum-ordinalize-derive --precise 4.3.2
cargo update -p risc0-zkvm --precise 3.0.5
```

Note that pinning `enum-ordinalize` alone is not enough; the derive crate is
resolved separately.

## The wallet's home directory variable was renamed without a compatibility shim

`NSSA_WALLET_HOME_DIR` became `LEE_WALLET_HOME_DIR` in v0.2.0. An older value is
silently ignored, and the wallet then creates a fresh keystore at `~/.lee/wallet`
with a new recovery phrase rather than reporting that it could not find the
configured one. The faucet moved from `pinata claim` to `vault claim` in the same
release.

## `nwaku` fails to start without an explicit NAT setting

Running `wakuorg/nwaku:v0.38.0` with `--discv5-discovery=false` exits with
`Error in start: failed to update multiaddress in ENR updateAddressInENR: Public
key does not correspond with given private key`, which does not point at the
cause. Adding `--nat=extip:127.0.0.1` fixes it. Relevant to anyone bringing up a
local Logos Delivery node, since Delivery is a Waku node.

## Waku's message cap makes a composite Risc0 receipt untransmittable

Publishing a ~300 KB composite receipt returns
`Message size exceeded maximum of 153600 bytes`. This is a real constraint for
credential transport, not a tuning detail. The Groth16 wrap brings the credential
to 1,479 bytes measured, and `scripts/demo-offchain-gating.sh` uses it for that
reason.

## The wallet's confirmation window is shorter than a privacy proof takes

`spel` reports `Transaction NOT confirmed: Transaction not found in preconfigured
amount of blocks` for privacy-preserving transactions whose proving outruns the
polling window, and the transaction then lands anyway. Reading the CLI's verdict
as failure is wrong; check `getTransaction`.
