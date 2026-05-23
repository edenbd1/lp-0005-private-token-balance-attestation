# Deployment

Reproducible record of every successful deployment of the LP-0005 programs.
Each tx_hash here is independently verifiable on the public Logos Execution
Zone testnet via the JSON-RPC `getTransaction` method, or by clicking the
explorer link.

## Public LEZ testnet (validated 2026-05-23)

**Status:** ✅ **Live on `https://testnet.lez.logos.co`** — the public Logos
Execution Zone testnet. Two programs deployed: the LP-0005 attestation circuit
(pure Risc0 guest), and the verifier program (SPEL `#[lez_program]`) that
gates application actions on the attestation.

```
Network:                      Public LEZ testnet
Sequencer JSON-RPC:           https://testnet.lez.logos.co
Block explorer:               https://explorer.testnet.lez.logos.co
Signer:                       Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
Block height at deploy:       ~21578
```

### Deployed programs

#### 1. Attestation circuit — Risc0 guest proving `balance >= N`

The inner zero-knowledge circuit. Generates a Risc0 receipt over the LEZ
private-account commitment format. The verifier program below composes this
proof via `env::verify` (chained-call).

```
Source:           crates/attestation-circuit/methods/guest/src/bin/attestation.rs
ProgramId (hex):  940bc4db,ae37a6ed,34398a95,117cd338,532e1ae3,52d93959,60478b48,4d9d6ab4
ImageID (32B):    dbc40b94eda637ae958a393438d37c11e31a2e535939d952488b4760b46a9d4d
Binary size:      282428 bytes
Deploy tx:        4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d
```

[Open in explorer](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d)

#### 2. Verifier program — SPEL `#[lez_program]` gating attestations

The on-chain gate. Takes a `PublicJournal`, validates context binding +
threshold floor + ECDSA presenter signature, then declares a `ChainedCall` to
the attestation program so the PPE pipeline composes the inner proof.

```
Source:           crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs
ProgramId (hex):  0d78474d,29ef747c,41b9e583,c147dc47,ebc0b708,715b6e9e,d1e0520d,bbc90a40
ImageID (32B):    4d47780d7c74ef2983e5b94147dc47c108b7c0eb9e6e5b710d52e0d1400ac9bb
Binary size:      511764 bytes
Deploy tx:        6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d
```

[Open in explorer](https://explorer.testnet.lez.logos.co/transaction/6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d)

### Full transaction record (signer = `CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r`)

| # | Instruction | Explorer link |
|---|---|---|
| 1 | `wallet auth-transfer init` (signer account, set up under LP-0017 — reused) | [`dd55dd1e…7b97f0`](https://explorer.testnet.lez.logos.co/transaction/dd55dd1e5b754fb975f7b5e523bee1cc361aee78e56f904d1f152ff1747b97f0) |
| 2 | `wallet pinata claim` (faucet → 150 tokens, reused from LP-0017) | [`40b7966d…7476b4`](https://explorer.testnet.lez.logos.co/transaction/40b7966dd494645d7eaa2669ccbd734e254aecf6a359160508c7ff42707476b4) |
| 3 | **`wallet deploy-program`** — attestation circuit | [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d) |
| 4 | **`wallet deploy-program`** — verifier program (SPEL) | [`6369e70e…07c51b6d`](https://explorer.testnet.lez.logos.co/transaction/6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d) |

Account state on the explorer:

- Signer (anchorer): https://explorer.testnet.lez.logos.co/account/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r

## How to reproduce the deployment

Pre-requisites: macOS arm64 with `cargo`, `docker`, the Logos toolchain
(`wallet`, `spel`, `cargo-risczero`, `r0vm`, `rzup`). Versions verified:
`spel 0.2.0`, `cargo-risczero 3.0.5`, `r0vm 3.0.5`, `rzup 0.5.1`.

```bash
# 0. macOS-only: install_name_tool fix for wallet, if needed
install_name_tool -add_rpath /Library/Developer/CommandLineTools/Library/Frameworks "$(which wallet)"

# 1. Build the attestation guest (Risc0 native build)
cd /path/to/lp-0005
cargo risczero build --manifest-path crates/attestation-circuit/methods/guest/Cargo.toml

# 2. Build the verifier program (SPEL #[lez_program])
cargo risczero build --manifest-path crates/verifier-program-spel/methods/guest/Cargo.toml

# 3. Point wallet at the public testnet
export NSSA_WALLET_HOME_DIR=~/logos/src/logos-execution-zone/wallet/configs/debug
wallet config set sequencer_addr https://testnet.lez.logos.co

# 4. One-time per signer account: init + faucet claim
PAYER=CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
wallet auth-transfer init --account-id Public/$PAYER
wallet pinata claim       --to         Public/$PAYER

# 5. Deploy the attestation circuit (capture tx_hash)
wallet deploy-program \
  crates/attestation-circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/attestation.bin

# 6. Verify the deployed program_id matches what the verifier program expects:
spel inspect \
  crates/attestation-circuit/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/attestation.bin
# → ProgramId (decimal): 2483799259,2922882797,876186261,293393208,1395530467,1389967705,1615301448,1302162100
# This is the value pinned in
# crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs::ATTESTATION_PROGRAM_ID

# 7. Deploy the verifier program
wallet deploy-program \
  crates/verifier-program-spel/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier.bin
```

## Verifying deployments via JSON-RPC

Anyone, from anywhere, can confirm the four tx hashes above are on chain
without any Logos toolchain — just `curl` + `jq`:

```bash
curl -s -X POST https://testnet.lez.logos.co \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d"]}' \
  | jq -r '.result | if . == null then "MISSING" else "PRESENT" end'
```

Result: `PRESENT` for all four hashes (verified 2026-05-23 at block 21590).
