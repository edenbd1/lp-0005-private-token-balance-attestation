# Deployment

Reproducible record of every successful deployment of the LP-0005 programs.
Each tx_hash here is independently verifiable on the public Logos Execution
Zone testnet via the JSON-RPC `getTransaction` method, or by clicking the
explorer link.

## Public LEZ testnet (re-validated 2026-07-19)

**Status:** ✅ **Live on `https://testnet.lez.logos.co`** — the public Logos
Execution Zone testnet. Two programs deployed: the LP-0005 attestation circuit
(pure Risc0 guest), and the verifier program (SPEL `#[lez_program]`) that
gates application actions on the attestation.

```
Network:                      Public LEZ testnet
Sequencer JSON-RPC:           https://testnet.lez.logos.co
Block explorer:               https://explorer.testnet.lez.logos.co
Signer:                       Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
LEZ version:                  v0.2.0
Block height at re-deploy:    ~27820
```

> **Note — testnet reset of 2026-07.** The public testnet was reset and upgraded
> to LEZ `v0.2.0`, which cleared the transaction history of the original
> 2026-05-23 deployment. Every program below has been re-submitted against the
> current chain and re-verified on 2026-07-19.
>
> **The three deployment tx hashes are unchanged.** A LEZ program-deployment tx
> hash is `SHA256(borsh(bytecode))` — content-addressed — so re-deploying the
> byte-identical binary reproduces the identical hash. The ImageIDs are likewise
> unchanged. The `gated_check` call is a *signed* transaction carrying a nonce,
> so it necessarily has a new hash.
>
> The binaries were built in May 2026 and were re-deployed **without
> recompilation**; the end-to-end `gated_check` confirmed on the upgraded v0.2.0
> chain, so the primitive survives a LEZ minor-version upgrade unchanged.

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

The v2 uses flat primitive args (`u128`, `[u8; 32]`, `Vec<u8>`) instead of a
single `Defined` `PublicJournal` struct so the `spel` CLI can serialise calls —
necessary for end-to-end submission without a custom host tool. An earlier v1
using the `PublicJournal` struct ABI was superseded by v2 before the testnet
reset and is not re-deployed.

**v2 (current — flat-args ABI):**

```
Source:           crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs
ProgramId (hex):  91f71577,c61bf745,5d305419,c1c0b277,38efaf94,70e7c043,6d282c32,29b41d8a
ImageID (32B):    7715f79145f71bc61954305d77b2c0c194afef3843c0e770322c286d8a1db429
Binary size:      509984 bytes
Deploy tx:        2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9
```

[Open v2 deploy tx](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)

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
Binary size:      508056 bytes
Deploy tx:        a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca
```

[Open v3 deploy tx](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca)

#### 4. End-to-end `gated_check` submission (CONFIRMED ON CHAIN)

```
gated_check call tx_hash: fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d
Status:                    ✅ Confirmed — included in a block
Inputs:                    Real Risc0 receipt (RISC0_DEV_MODE=0, 6.5 s prover wall-clock)
                           Real secp256k1 ECDSA signature over the canonical journal-bound digest
                           Real verifier-drawn 32-byte nonce
```

[Open the gated_check call in the explorer](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d)

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

The deep verifier (v2, ImageID `7715f791…d8a1db429`, deploy tx [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)) declares the chained call that the LEZ PPE pipeline can compose. A `gated_check` against v2 was submitted before the testnet reset but did not confirm, because (a) the wallet/spel CLI doesn't bundle the inner Risc0 receipt and (b) the verifier's canonical digest didn't match the SDK at the time of submission. The digest mismatch is fixed in v3.

Both verifiers are preserved on chain as historical evidence of the iteration.

### Full transaction record (signer = `CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r`)

All four are live on the current chain and independently verifiable.

| # | Instruction | Explorer link |
|---|---|---|
| 1 | **`wallet deploy-program`** — attestation circuit | [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d) |
| 2 | **`wallet deploy-program`** — verifier program v2 (SPEL, flat-arg ABI, deep gate with ChainedCall) | [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9) |
| 3 | **`wallet deploy-program`** — verifier program v3 (SPEL, flat-arg ABI, shallow gate — confirmable today) | [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca) |
| 4 | ✅ **`spel gated_check`** — real ECDSA-signed gate call against the v3 verifier, **CONFIRMED on chain** | [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d) |

Account state on the explorer:

- Signer (anchorer): https://explorer.testnet.lez.logos.co/account/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r

## How to reproduce the deployment

Pre-requisites: macOS arm64 with `cargo`, `docker`, and the Logos toolchain.
Versions verified on the 2026-07-19 re-deploy against LEZ `v0.2.0`:
`wallet` built from `logos-execution-zone` tag `v0.2.0`, `spel 0.6.0`,
`cargo-risczero 3.0.5`, `r0vm 3.0.5`.

> The `wallet` home env var was renamed `NSSA_WALLET_HOME_DIR` →
> `LEE_WALLET_HOME_DIR` in v0.2.0, the faucet moved from `pinata claim` to
> `vault claim`, and `spel` must be **≥ 0.6.0** (0.6.0 is the first release that
> speaks the `lee`/`lee_core` storage format; older builds fail with
> `missing field 'accounts'`).

```bash
# 1. Build the wallet from the LEZ release the testnet is running
git clone https://github.com/logos-blockchain/logos-execution-zone.git
cd logos-execution-zone && git checkout v0.2.0
cargo build --release -p wallet          # built-in program artifacts are committed
                                         # under artifacts/ — no guest rebuild needed
WALLET=$PWD/target/release/wallet

# 1b. macOS-only: install_name_tool fix, if the binary fails to load Python3
install_name_tool -add_rpath /Library/Developer/CommandLineTools/Library/Frameworks "$WALLET"

# 2. Install spel >= 0.6.0
cargo install --git https://github.com/logos-co/spel --tag v0.6.0

# 3. Point the wallet at the public testnet and import the signer
export LEE_WALLET_HOME_DIR=~/.lee/wallet
$WALLET config set sequencer_addr https://testnet.lez.logos.co
$WALLET check-health                     # must print: ✅ All looks good!
$WALLET account import public --private-key <signer-private-key>

# 4. Fund the signer if its balance is zero
$WALLET vault claim --account-id Public/$PAYER --amount 10000

# 5. Deploy. The tx hash is SHA256(borsh(bytecode)) — content-addressed, so
#    deploying the identical binary always reproduces the identical hash.
cd /path/to/lp-0005
$WALLET deploy-program target/riscv-guest/attestation-methods/attestation-guest/riscv32im-risc0-zkvm-elf/release/attestation.bin
$WALLET deploy-program crates/verifier-program-spel/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier.bin
$WALLET deploy-program crates/verifier-program-spel/methods/guest-shallow/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier_shallow.bin

# 6. Verify the deployed program_id matches what the verifier program expects:
spel inspect target/riscv-guest/attestation-methods/attestation-guest/riscv32im-risc0-zkvm-elf/release/attestation.bin
# → ProgramId (decimal): 2483799259,2922882797,876186261,293393208,1395530467,1389967705,1615301448,1302162100
# This is the value pinned in
# crates/verifier-program-spel/methods/guest/src/bin/attestation_verifier.rs::ATTESTATION_PROGRAM_ID

# 7. Run the end-to-end gated_check (prove → challenge → sign → submit)
./scripts/demo.sh
```

To rebuild the guests from source rather than re-deploying the committed
binaries, use `cargo risczero build --manifest-path <methods>/Cargo.toml`
(requires Docker for the reproducible `docker` profile).

## Verifying deployments via JSON-RPC

Anyone, from anywhere, can confirm the four tx hashes above are on chain
without any Logos toolchain — just `curl` + `jq`:

```bash
for tx in \
  4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d \
  2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9 \
  a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca \
  fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d
do
  printf '%s  ' "${tx:0:12}…"
  curl -s -X POST https://testnet.lez.logos.co \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$tx\"]}" \
    | jq -r '.result | if . == null then "MISSING" else "PRESENT" end'
done
```

Result: `PRESENT` for all four hashes (re-verified 2026-07-19 at block 27822,
LEZ v0.2.0).
