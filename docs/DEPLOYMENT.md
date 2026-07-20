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

The inner zero-knowledge circuit for the **off-chain** path. Generates a Risc0
receipt over the LEZ private-account commitment format, which a recipient
verifies locally.

It is a standalone Risc0 guest, not a LEZ program: it commits a bespoke
`PublicJournal` that cannot decode as a `ProgramOutput`, so LEZ cannot compose
it. The on-chain path therefore uses the LEZ-native attestation program in
section 5 instead. An earlier revision of this document claimed the verifier
composed this circuit via `env::verify`; that was the intent, and it is why the
v2 gate never confirmed.

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

The v2 verifier declares a `ChainedCall` to the standalone attestation circuit,
which cannot work: on a **public** transaction the sequencer resolves a chained
call by re-executing the callee host-side (`lee/state_machine/src/program.rs:73-77`),
and the standalone circuit's journal does not decode as a `ProgramOutput`, so
execution fails. That is the mechanical reason a `gated_check` against v2 never
confirmed. The working design is the deep gate in section 5.

v3 is a **shallow gate**: it runs the same host-side validation (context match
+ threshold floor + ECDSA presenter-signature check, all the rules in
`check_gate`) but declares no `ChainedCall`, and therefore **verifies no
zero-knowledge proof**. Every value it checks is supplied by the caller,
including `presenter_pubkey`, so what it establishes is that the submitter holds
the key they nominated — not that any attestation is valid.

That limitation is not a matter of effort. A LEZ **public** transaction proves
and verifies nothing at all: the sequencer merely re-executes the program
(`lee/state_machine/src/program.rs:73-77`, *"Execute the program (without
proving)"*), and feeds it four public inputs with no channel for a witness. No
program submitted that way can ever verify a proof.

**The v4 deep gate below does verify the proof**, on the privacy-preserving
transaction path. v3 is retained because it is cheap and confirmable in a single
public transaction, but it should not be read as proof verification.

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

#### 5. Deep gate (v4) — the proof is VERIFIED ON CHAIN

This is the path that satisfies the prize's on-chain criterion, and it is live on
the public testnet.

**How the verification actually happens.** On the privacy-preserving transaction
path the *client* proves locally (`lez/wallet/src/lib.rs:578`). For each chained
call, LEZ's privacy circuit performs a genuine recursive composition:

```rust
// lee/privacy_preserving_circuit/src/execution_state.rs:149
env::verify(chained_call.program_id, program_output_words)
```

and the sequencer then verifies the resulting receipt against the node-pinned
`PRIVACY_PRESERVING_CIRCUIT_ID`
(`privacy_preserving_transaction/circuit.rs:33-39`). So the attestation's proof
is verified on chain as a precondition of the transaction being accepted.

For that composition to apply, the callee must be a real LEZ program emitting a
`ProgramOutput`. The standalone circuit commits a bespoke journal that cannot
decode as one, which is exactly why the v2 deep gate never confirmed. `v4`
therefore chains to a **LEZ-native attestation program**.

**Privacy is preserved** because a privacy `Message` publishes only commitments
and nullifiers, never `program_id` nor `instruction_data`
(`privacy_preserving_transaction/message.rs:14-24`). The witness travels in the
instruction on that path, and only on that path.

```
Attestation program (LEZ-native)
Source:           crates/attestation-circuit/methods/guest-lez/src/bin/attestation_lez.rs
ImageID (32B):    9b6be465fed863f89450ecf9e8ef3d2183aab83647358519230c12c0746c27da
Binary:           artifacts/programs/attestation_lez.bin (298,956 bytes)
Deploy tx:        674aa03a8a51a2eba660ec2ab136a1b6c9ca17817c7bb3160b68904375726652

Verifier program (deep gate, v5 — presenter, denomination and policy bound)
Source:           crates/verifier-program-spel/methods/guest-deep/src/bin/attestation_verifier_deep.rs
ImageID (32B):    1047297a1fdd686d82435cd858c2d8acb86b20a74d5f779a8d9bcd9f8261b27c
Binary:           artifacts/programs/attestation_verifier_deep.bin (507,040 bytes)
Deploy tx:        7a4e46cfcab3a956a159d3c82a781222bdf093faa7ef8d42723f1a95e06eec0d

Confirmed gated_check (privacy-preserving)
Tx hash:          e8ed66c79373ebbea77a254db866793d68fd1b71357731ed93d70bade7bbb4ab
Transaction type: PrivacyPreserving (borsh variant byte 1)
On-chain size:    230,186 bytes — a real receipt, not a bare instruction
Enforced policy:  floor 4000, context 77023f48… (both folded into the marker seed)
Marker PDA:       HBFLDbG6r1DJFUKaA7acCKSbiNmYs2UG6UAnLSgkN2ii
                  owned by attestation_verifier_deep

Superseded (do not cite): ImageID 6d4c9453…97babc, deploy tx 4e2ac5c3…, gated_check
b9488de0…. That gate could be passed by an account holding nothing; see the
warning above the transaction record and docs/limitations.md.
```

**Verify it yourself**, with only `curl`, `python3` and `jq`, trusting nothing in
this repository:

```bash
./scripts/verify-onchain-proof.sh
```

**The balance is anchored, not asserted — but that took four bindings, not one.**
`gated_check` checks the floor against `presenter.account.balance`, taken from the
pre_state rather than the caller-supplied witness. On the privacy path LEZ
computes that account's commitment from its exact state and folds the caller's
membership proof into a `CommitmentSetDigest`
(`privacy_preserving_circuit/src/output.rs:307-315`) that the sequencer requires
to be in `root_history` (`state.rs:302-306`), so a fabricated membership proof is
rejected.

That alone is not enough, and an earlier revision of this document claimed it was.
The anchored balance means "at least N" only once the signer is bound to the
account the witness attests to (`3010`), the owning program is pinned so the
number is denominated (`3011`), and the enforced floor and context are folded into
the marker seed so the public artifact records what was demanded (`3012`).
Without the first, the balance checked belongs to a different account than the one
attested. Without the third, a caller pinning `minimum_threshold = 0` leaves a
marker indistinguishable from one earned against a real floor.

`crates/cu-bench/tests/deep_gate_rejects.rs` runs the deployed binary through the
sequencer's own execution path and requires each of `3009`/`3010`/`3011`/`3012` to
fire on the corresponding forged input, with the honest call accepted as the
control.

**The on-chain trace, and what it proves.** A privacy transaction publishes no
program id, so the instruction claims a PDA seeded by
`compute_gate_tag(nullifier, minimum_threshold, expected_context_id)`. An
integrator demanding "context C, at least N" computes the single address that can
satisfy them and checks it is owned by the verifier. That account could only be
claimed by an accepted transaction, acceptance required the sequencer to verify
the proof, and the address itself encodes the policy that was enforced. Recompute
it at a lower floor and the address moves to an unclaimed slot carrying the
default owner.

**Evidence that the composition is real, not a signature check in disguise.**
Submitting a witness whose balance is below the attested threshold fails at
proving time, inside the chained attestation guest:

```
ProgramProveFailed("Guest panicked: balance is below the attested threshold")
```

A false attestation cannot produce a transaction at all. Separately, the
sequencer has no `RISC0_DEV_MODE` in its environment and runs
`receipt.verify(...)`, so acceptance implies a genuine receipt even if a client
were in dev mode.

**Replay protection.** Re-submitting the same nullifier fails, because claiming a
PDA requires the account to still have the default program owner. Note where this
failure happens: it is raised **client-side, during proving**, before a
transaction exists. No transaction was submitted and rejected by the sequencer.
The protection is real either way, since a second claim is unprovable in-circuit
(`execution_state.rs:376-380`), but the evidence below is a prover error, not
testnet evidence:

```
ProgramProveFailed("Guest panicked: account validation failed: AccountAlreadyInitialized { account_index: 0 }")
```

**Reproducing a gated_check.** The witness comes from real chain state, not a
synthetic Merkle path: `npk` and identifier from the wallet's private account,
balance/nonce/program_owner from its on-chain state, and the membership proof
from the sequencer's own `getProofForCommitment`.

```bash
python3 scripts/build-privacy-gated-check.py \
  --witness witness.json --presenter presenter.json \
  --context <label> --threshold <N> --out gc.args

spel --idl idl/attestation_verifier_deep.idl.json \
     --program artifacts/programs/attestation_verifier_deep.bin \
     --bin-attestation artifacts/programs/attestation_lez.bin \
     -- gated_check --presenter Private/<account-id> $(tr '\n' ' ' < gc.args)
```

> **The CLI may print `Transaction NOT confirmed`.** Proving takes well over ten
> minutes and can outrun the wallet's block-polling window, so the CLI gives up
> before the transaction lands. It does land. Check with `getTransaction` rather
> than trusting the CLI's verdict — that is what happened to the transaction
> recorded above.

#### Deep verifier (v2) — superseded by v4

The deep verifier (v2, ImageID `7715f791…d8a1db429`, deploy tx [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9)) declares the chained call that the LEZ PPE pipeline can compose. A `gated_check` against v2 was submitted before the testnet reset but did not confirm, because (a) the wallet/spel CLI doesn't bundle the inner Risc0 receipt and (b) the verifier's canonical digest didn't match the SDK at the time of submission. The digest mismatch is fixed in v3.

Both verifiers are preserved on chain as historical evidence of the iteration.

### Full transaction record (signer = `CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r`)

All are live on the current chain and independently verifiable. Rows 5 and 8 to 9
are the current deep path, where the zero-knowledge proof is genuinely verified on
chain; run `./scripts/verify-onchain-proof.sh` to check it from public data alone.

> **Rows 6 and 7 are superseded and must not be cited.** An adversarial review of
> that verifier (ImageID `6d4c9453…97babc`) found the gate could be passed by an
> account holding nothing: the signing account was never bound to the account the
> witness attested to, the owning program was never pinned, and the marker PDA was
> seeded by the nullifier alone, so a caller pinning `minimum_threshold = 0` left a
> marker indistinguishable from one earned against a real floor. Row 8 deploys the
> verifier with those three bindings added (errors `3010`, `3011`, `3012`); see
> `docs/limitations.md` and `crates/cu-bench/tests/deep_gate_rejects.rs`, which
> exercises each rejection against the deployed binary.

| # | Instruction | Explorer link |
|---|---|---|
| 1 | **`wallet deploy-program`** — attestation circuit | [`4593060b…3db989d`](https://explorer.testnet.lez.logos.co/transaction/4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d) |
| 2 | **`wallet deploy-program`** — verifier program v2 (SPEL, flat-arg ABI, deep gate with ChainedCall) | [`2bf10138…23723a9`](https://explorer.testnet.lez.logos.co/transaction/2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9) |
| 3 | **`wallet deploy-program`** — verifier program v3 (SPEL, flat-arg ABI, shallow gate — confirmable today) | [`a0ec45bb…d341c5ca`](https://explorer.testnet.lez.logos.co/transaction/a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca) |
| 4 | **`spel gated_check`** — ECDSA-signed gate call against the v3 shallow verifier (no proof verification) | [`fd9869f7…eafb306d`](https://explorer.testnet.lez.logos.co/transaction/fd9869f7282ae6b5fe5c29ba31854ea68c032780207bfb6f1fba5298eafb306d) |
| 5 | **`wallet deploy-program`** — LEZ-native attestation program (v4 path) | `674aa03a8a51a2eba660ec2ab136a1b6c9ca17817c7bb3160b68904375726652` |
| 6 | ~~**`wallet deploy-program`** — deep verifier v4~~ **superseded, unbound gate** | `4e2ac5c3f07cb719bc80084837a5c86de61e0efa3c44975e88605c23e59271a9` |
| 7 | ~~**`spel gated_check`** — privacy-preserving against v4~~ **superseded** | `b9488de014c7bda54544011b3cf1e7f54562e90c5451dc402316507bd10d36b2` |
| 8 | **`wallet deploy-program`** — deep verifier v5, presenter/owner/policy bound (ImageID `1047297a…8261b27c`) | `7a4e46cfcab3a956a159d3c82a781222bdf093faa7ef8d42723f1a95e06eec0d` |
| 9 | ✅ **`spel gated_check`** — privacy-preserving against v5, **proof verified on chain, policy bound into the marker** | `e8ed66c79373ebbea77a254db866793d68fd1b71357731ed93d70bade7bbb4ab` |

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
