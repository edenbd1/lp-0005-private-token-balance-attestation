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

The on-chain gate. Takes the journal fields + presenter signature, validates
context binding + threshold floor + ECDSA signature, then declares a
`ChainedCall` to the attestation program so the PPE pipeline composes the
inner proof.

Two revisions deployed; the v2 uses flat primitive args (`u128`, `[u8; 32]`,
`Vec<u8>`) instead of a single `Defined` `PublicJournal` struct so the `spel`
CLI can serialise calls — necessary for end-to-end submission without a
custom host tool. v1 is preserved on chain as historical evidence.

**v2 (current — flat-args ABI):**

```
Source:           crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs
ProgramId (hex):  91f71577,c61bf745,5d305419,c1c0b277,38efaf94,70e7c043,6d282c32,29b41d8a
ImageID (32B):    7715f79145f71bc61954305d77b2c0c194afef3843c0e770322c286d8a1db429
Binary size:      509984 bytes
Deploy tx:        2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9
```

[Open v2 deploy tx](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)

**v1 (initial — `PublicJournal` struct ABI):**

```
ProgramId (hex):  0d78474d,29ef747c,41b9e583,c147dc47,ebc0b708,715b6e9e,d1e0520d,bbc90a40
ImageID (32B):    4d47780d7c74ef2983e5b94147dc47c108b7c0eb9e6e5b710d52e0d1400ac9bb
Deploy tx:        6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d
```

[Open v1 deploy tx](https://explorer.testnet.lez.logos.co/transaction/6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d)

#### 3. Verifier program v3 (shallow gate — confirmable today)

The v2 verifier declares a `ChainedCall` to `ATTESTATION_PROGRAM_ID` so the
LEZ PPE pipeline composes the inner Risc0 receipt via `env::verify`. That
architecture is the design ideal but currently requires the wallet to bundle
the inner receipt with the outbound transaction — a feature the `spel` CLI
does not yet expose.

v3 is a **shallow gate** with the same host-side validation (context match
+ threshold floor + ECDSA presenter-signature check, all the rules in
`check_gate`) but without the `ChainedCall`. The security argument is
defense-in-depth: an attacker cannot produce a valid presenter signature
without knowing the presenter's private key, and the off-chain verifier
re-checks the inner Risc0 receipt before signing the journal anyway. v3 is
the confirmable end-to-end path today.

```
Source:           crates/verifier-program-spel/methods/guest-shallow/src/bin/attestation_verifier_shallow.rs
ProgramId (hex):  62662cb3,46ba7ebb,6e578462,f5ec2872,a6d14387,8788beef,df3d4de9,2a9585bf
ImageID (32B):    b32c6662bb7eba466284576e7228ecf58743d1a6efbe8887e94d3ddfbf85952a
Binary size:      509072 bytes
Deploy tx:        a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca
```

[Open v3 deploy tx](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)

#### 4. End-to-end `gated_check` submission (CONFIRMED ON CHAIN)

```
gated_check call tx_hash: 262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e
Status:                    ✅ Confirmed — included in a block
Inputs:                    Real Risc0 receipt (RISC0_DEV_MODE=0, 6.5 s prover wall-clock)
                           Real secp256k1 ECDSA signature over the canonical journal-bound digest
                           Real verifier-drawn 32-byte nonce
```

[Open the gated_check call in the explorer](https://explorer.testnet.lez.logos.co/transaction/262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e)

The full pipeline runs end-to-end:

1. **Local Risc0 attestation receipt** generated under `RISC0_DEV_MODE=0`
   (6.5 s wall-clock, 300 KB credential — see `docs/benchmarks/baseline.md`).
2. **Verifier draws a fresh nonce** via `attest challenge`.
3. **Presenter signs** the canonical challenge digest (matches
   `attestation_verifier_offchain::presenter_challenge_digest` byte-for-byte)
   with secp256k1 via `attest sign-challenge`.
4. **`attest gated-check-args`** emits the 9 SPEL CLI flags ready to submit.
5. **`spel gated_check`** sends the call to the v3 verifier program; the
   guest validates context + threshold + signature and the tx confirms on
   chain in one block.

#### Deep verifier (v2) — architecturally ideal, blocked on wallet update

The deep verifier (v2, ImageID `7715f791…d8a1db429`, deploy tx [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)) declares the chained call that the LEZ PPE pipeline can compose. A `gated_check` against v2 was submitted at tx hash [`7a9065e0…f48cf`](https://explorer.testnet.lez.logos.co/transaction/7a9065e02794d3e4735e32901e4c07cf859338af3a76cae34eede01d14bf48cf) but did not confirm because (a) the wallet/spel CLI doesn't bundle the inner Risc0 receipt and (b) the verifier's canonical digest didn't match the SDK at the time of submission. The digest mismatch is fixed in v3.

Both verifiers are preserved on chain as historical evidence of the iteration.

### Full transaction record (signer = `CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r`)

| # | Instruction | Explorer link |
|---|---|---|
| 1 | `wallet auth-transfer init` (signer account, set up under LP-0017 — reused) | [`dd55dd1e…7b97f0`](https://explorer.testnet.lez.logos.co/transaction/dd55dd1e5b754fb975f7b5e523bee1cc361aee78e56f904d1f152ff1747b97f0) |
| 2 | `wallet pinata claim` (faucet → 150 tokens, reused from LP-0017) | [`40b7966d…7476b4`](https://explorer.testnet.lez.logos.co/transaction/40b7966dd494645d7eaa2669ccbd734e254aecf6a359160508c7ff42707476b4) |
| 3 | **`wallet deploy-program`** — attestation circuit | [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d) |
| 4 | **`wallet deploy-program`** — verifier program v1 (SPEL, struct-arg ABI) | [`6369e70e…07c51b6d`](https://explorer.testnet.lez.logos.co/transaction/6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d) |
| 5 | **`wallet deploy-program`** — verifier program v2 (SPEL, flat-arg ABI, deep gate with ChainedCall) | [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9) |
| 6 | **`spel gated_check`** — first attempt against v2 (didn't confirm — see "Deep verifier" note below) | [`7a9065e0…f48cf`](https://explorer.testnet.lez.logos.co/transaction/7a9065e02794d3e4735e32901e4c07cf859338af3a76cae34eede01d14bf48cf) |
| 7 | **`wallet deploy-program`** — verifier program v3 (SPEL, flat-arg ABI, shallow gate — confirmable today) | [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca) |
| 8 | ✅ **`spel gated_check`** — real ECDSA-signed gate call against the v3 verifier, **CONFIRMED on chain** | [`262bbe95…6babfd5e`](https://explorer.testnet.lez.logos.co/transaction/262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e) |

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
