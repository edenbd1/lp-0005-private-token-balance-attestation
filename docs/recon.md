# LP-0005 Recon Report

Sources rooted at `/Users/eden/data/ns.com/lp-0005/_external/`. All file paths below are absolute, relative to that prefix unless noted otherwise.

---

## TL;DR (max 10 bullets — the most load-bearing facts)

1. **The prize text's commitment formula is wrong / oversimplified.** Real formula (verified at `lez/nssa/core/src/commitment.rs:55-78`) is `SHA256( "/LEE/v0.3/Commitment/" || account_id || program_owner || balance || nonce || SHA256(data) )`. There is a 32-byte domain separator and the per-account leaf binds to `account_id` (32 bytes), NOT `npk` directly. `npk` only enters indirectly through the derivation of `account_id` (e.g. `AccountId::for_regular_private_account(&npk, identifier)` — see `lez/nssa/core/src/program.rs:152-176`).
2. **Sequencer JSON-RPC** is `jsonrpsee`-based HTTP, default port `3040` (`lez/sequencer/service/src/main.rs:13`). `getProofForCommitment(commitment: Commitment) -> Option<MembershipProof>` where `MembershipProof = (usize, Vec<[u8; 32]>)` — `(leaf_index, sibling_hashes_root_to_leaf_excluded)`. Defined at `lez/sequencer/service/rpc/src/lib.rs:79-83` and `lez/nssa/core/src/commitment.rs:83`.
3. **Merkle tree** is a SHA-256, leaf-hashed-once, append-only tree with `hash_two(L,R) = SHA256(L || R)`, leaves hashed via `hash_value(v) = SHA256(v)` before insertion (`lez/nssa/src/merkle_tree/mod.rs:146-157`). Capacity auto-doubles. The current LEZ runtime initializes the private `CommitmentSet` with **capacity 32** (`lez/nssa/src/state.rs:134,169`) — i.e. depth 5 at genesis, growing dynamically.
4. **There is no on-chain Merkle-root syscall for user programs.** Root validity is enforced by the sequencer at PPE-transaction *inclusion* time: every nullifier must carry a `CommitmentSetDigest` (root) that is in `root_history` (`lez/nssa/src/state.rs:322-337`). That means user LEZ programs do **not** read the root directly; the wallet writes `(nullifier, root)` into the PPE message and the sequencer checks the root is recent.
5. **There is no "raw Risc0 receipt as instruction argument" path today.** Programs compose via the privacy-preserving outer circuit using `env::verify(program_id, journal_words)` (Risc0 assumption mechanism — `lez/program_methods/guest/src/bin/privacy_preserving_circuit/execution_state.rs:149`). The only producer of an externally-verifiable `Receipt` is `lez/nssa/src/privacy_preserving_transaction/circuit.rs:30-37`: `Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)`. The submission will need to choose between (a) shipping our circuit as a chained-call program so it gets composed by the PPE outer proof, or (b) shipping the receipt as instruction bytes and writing a verifier that calls `risc0_zkvm::Receipt::verify` inside our SPEL program's guest.
6. **Risc0 version is pinned to `3.0.5`** (`lez/Cargo.toml:89-90`, `lez-programs/Cargo.toml:39`, also matches `cycle_bench.md`). All accelerators OFF in the published benchmarks (CPU only).
7. **Proving cost baseline (M2 Pro, CPU, real proving, `RISC0_DEV_MODE=0`):** standalone `auth_transfer Transfer` ≈ 13.7 s; same instruction *inside* the PPE circuit ≈ 61.5 s (composition tax ≈ 48 s); PPE outer-proof bytes are a fixed ≈ 224 KB borsh `InnerReceipt`; `Receipt::verify` is ≈ 12 ms (`lez/docs/benchmarks/cycle_bench.md`). Plan budgets around these.
8. **SPEL is Anchor-for-LEZ.** `#[lez_program]` attribute macro over a module, `#[instruction]` fns with `#[account(...)]` attributes; auto-generates IDL, FFI client, and the CLI dispatch. Template to copy: `lez-multisig/` (35 source files). Build pipeline: `cargo risczero build` → `methods/guest/...bin` → `wallet deploy-program` (`lez-multisig/Makefile:113-128`).
9. **RLN identity binding uses Poseidon BN254, not SHA-256.** `id_commitment = Poseidon(identity_secret)` (`logos-lez-rln/lez-rln/methods/guest/src/bin/rln_registration.rs:516`, hash function at `.../guest/src/hash.rs:11-15`). This is the pattern the prize hints at for binding a proof to a presenter, but adopting it inside a Risc0 circuit will pay Poseidon cycles on top of the existing SHA-256 commitment.
10. **`logos-delivery-module` exposes its API as a Qt/C++ plugin only** — `send/subscribe` over a Qt-meta-object interface; no Rust binding is present in this repo (`logos-delivery-module/README.md`). For off-chain proof transport we will either go through a Logos Core / Basecamp plugin (C++/QML) or write our own Rust client against the underlying `liblogosdelivery` C ABI (not vendored here — would need to be pulled in separately).

---

## 1. LEZ private account commitment — exact format

### Verified formula

```rust
// lez/nssa/core/src/commitment.rs:51-78
impl Commitment {
    /// Generates the commitment to a private account owned by user for `account_id`:
    /// SHA256( `Comm_DS` || `account_id` || `program_owner` || balance || nonce || SHA256(data)).
    #[must_use]
    pub fn new(account_id: &AccountId, account: &Account) -> Self {
        const COMMITMENT_PREFIX: &[u8; 32] =
            b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        let mut bytes = Vec::new();
        bytes.extend_from_slice(COMMITMENT_PREFIX);
        bytes.extend_from_slice(account_id.value());
        let account_bytes_with_hashed_data = {
            let mut this = Vec::new();
            for word in &account.program_owner {
                this.extend_from_slice(&word.to_le_bytes());
            }
            this.extend_from_slice(&account.balance.to_le_bytes());
            this.extend_from_slice(&account.nonce.0.to_le_bytes());
            let hashed_data: [u8; 32] = Impl::hash_bytes(&account.data)
                .as_bytes()
                .try_into()
                .unwrap();
            this.extend_from_slice(&hashed_data);
            this
        };
        bytes.extend_from_slice(&account_bytes_with_hashed_data);
        Self(Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap())
    }
}
```

### Reconciliation with prize text

Prize text (`lambda-prize/prizes/LP-0005.md:15` and again line 31) claims the format is:

> `SHA256(npk || program_owner || balance || nonce || SHA256(data))`

**This is incorrect on two counts** and any submission must target the real format:

1. There is a 32-byte **domain separator** `"/LEE/v0.3/Commitment/" || 11×\0` (note `LEE` not `LEZ` — likely intentional, "Logos Execution Environment") which the circuit must reproduce byte-for-byte.
2. The first hashed field is **`account_id` (32 bytes)**, not `npk`. `npk` is one of the inputs that derives `account_id` (along with `identifier`, see below) — but the commitment binds to the derived id, not to `npk` directly. This matters for the privacy story: the circuit must witness `(npk, identifier)` and prove `account_id == AccountId::for_regular_private_account(npk, identifier)` (or the PDA variant) without revealing `npk`.

The prize success criterion at line 31 ("The circuit correctly targets the existing LEZ private account commitment format: `SHA256(npk || program_owner || balance || nonce || SHA256(data))`") is therefore self-contradicting versus the code; the only sane reading is "target the actual on-chain format", which is what we'll do. Flag this in section 11.

### Field map (each input, where it comes from, byte layout)

| Field | Bytes | Source | Notes |
|---|---|---|---|
| `Comm_DS` (COMMITMENT_PREFIX) | 32 | `lez/nssa/core/src/commitment.rs:56-57` | ASCII `/LEE/v0.3/Commitment/` (21 bytes) followed by 11 `\0`s. Constant. |
| `account_id` | 32 | `lez/nssa/core/src/account.rs:155-180` (`AccountId`) | Wraps `[u8; 32]`. Derived per private-account kind: for regular private accounts via `AccountId::for_regular_private_account(npk, identifier)`; for private PDAs via `AccountId::for_private_pda(program_id, seed, npk, identifier)` (`lez/nssa/core/src/program.rs:152-176`). |
| `program_owner` | 32 | `lez/nssa/core/src/account.rs:99` + `lez/nssa/core/src/program.rs:15` | `ProgramId = [u32; 8]`. Serialized in commit as 8 × `u32::to_le_bytes()` (lines 64-66 of commitment.rs). For the LEZ **token** holding accounts this is the token program's ID. |
| `balance` | 16 | `lez/nssa/core/src/account.rs:92,100` | `Balance = u128`, little-endian. **This is the value the proof must compare against N.** |
| `nonce` | 16 | `lez/nssa/core/src/account.rs:17-48` | `Nonce(u128)` LE. Init for new private accounts: `SHA256(account_id ‖ 0×32).first_chunk::<16>` cast to u128 LE (`account.rs:29-36`). Update: `SHA256(nsk ‖ nonce_le ‖ 0×16).first_chunk::<16>` (lines 39-47). |
| `SHA256(data)` | 32 | `lez/nssa/core/src/commitment.rs:69-73` | `data: Data` is the account's variable-length payload (`lez/nssa/core/src/account/data.rs`). For a default (empty) token holding before initialization it is `Vec::new()`. For an initialized token holding, see `lez-rln/rln-layouts/src/lib.rs:235-251` (`TokenHoldingLayout`: 1 byte type + 32-byte definition_id + 16-byte balance, total 49 bytes). |

### Important sub-derivations the circuit will need

- **AccountId for regular private accounts** (`lez/nssa/core/src/program.rs` near `AccountId::for_regular_private_account`, also visible from PDA helper at `:152-176`): the regular form uses the npk + a 128-bit `Identifier`. The exact byte layout of the regular form is the same SHA-256-with-prefix shape but with a different prefix string than PDAs. (We'll quote it precisely once we audit `account.rs` for `for_regular_private_account` — it's referenced from `program.rs:182-184` but defined elsewhere; verify before writing the guest.)
- **DUMMY_COMMITMENT** is `Commitment::new(AccountId::new([0;32]), Account::default())` (`lez/nssa/core/src/commitment.rs:14-17, 122-128`). Inserted at index 0 of every fresh `CommitmentSet` to ensure non-empty trees (`lez/nssa/src/state.rs:170`).

---

## 2. Sequencer `getProofForCommitment` API

### Transport

- **Protocol:** JSON-RPC over HTTP via `jsonrpsee` (`lez/sequencer/service/rpc/src/lib.rs:3,33`).
- **Default port:** `3040` (`lez/sequencer/service/src/main.rs:13` — `default_value = "3040"`).
- **Client builder:** `SequencerClientBuilder` is `jsonrpsee::http_client::HttpClientBuilder`; the alias `SequencerClient = jsonrpsee::http_client::HttpClient`. Cheap to clone.
- **No auth.** The example in the rustdoc just builds `http://localhost:3040`.

### Trait

```rust
// lez/sequencer/service/rpc/src/lib.rs:79-84
#[method(name = "getProofForCommitment")]
async fn get_proof_for_commitment(
    &self,
    commitment: Commitment,
) -> Result<Option<MembershipProof>, ErrorObjectOwned>;
```

```rust
// lez/sequencer/service/src/service.rs:148-154
async fn get_proof_for_commitment(
    &self,
    commitment: Commitment,
) -> Result<Option<MembershipProof>, ErrorObjectOwned> {
    let sequencer = self.sequencer.lock().await;
    Ok(sequencer.state().get_proof_for_commitment(&commitment))
}
```

### Response shape

`MembershipProof` is exactly:

```rust
// lez/nssa/core/src/commitment.rs:81-83
pub type CommitmentSetDigest = [u8; 32];
pub type MembershipProof = (usize, Vec<[u8; 32]>);
```

So the JSON body is `(leaf_index: usize, sibling_path: [32-byte hashes])`. The path length equals the current tree depth (which is dynamic — see section 3). Indexed from leaf upward; the verifier computes the resulting root via `compute_digest_for_path` (`lez/nssa/core/src/commitment.rs:87-111`):

```rust
pub fn compute_digest_for_path(
    commitment: &Commitment,
    proof: &MembershipProof,
) -> CommitmentSetDigest {
    let value_bytes = commitment.to_byte_array();
    let mut result: [u8; 32] = Impl::hash_bytes(&value_bytes)
        .as_bytes()
        .try_into()
        .unwrap();
    let mut level_index = proof.0;
    for node in &proof.1 {
        let mut bytes = [0_u8; 64];
        let is_left_child = level_index & 1 == 0;
        if is_left_child {
            bytes[..32].copy_from_slice(&result);
            bytes[32..].copy_from_slice(node);
        } else {
            bytes[..32].copy_from_slice(node);
            bytes[32..].copy_from_slice(&result);
        }
        result = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        level_index >>= 1;
    }
    result
}
```

Note `Impl::hash_bytes` is `risc0_zkvm::sha::Impl` — Risc0's accelerated SHA-256 inside the guest; matches host `sha2::Sha256` byte-for-byte.

### Related RPCs the wallet/circuit may need

Also in the same trait (`lez/sequencer/service/rpc/src/lib.rs`):
- `sendTransaction(NSSATransaction) -> HashType` — submit our PPE transaction.
- `getAccount(AccountId) -> Account` — to read the user's current account for proof input.
- `getProgramIds() -> BTreeMap<String, ProgramId>` — to discover the verifier program ID after deployment.

There is **no** dedicated `getCommitmentSetDigest` RPC — but we can synthesise the current root by calling `compute_digest_for_path` on any valid proof, or by reading the `root_history` exposed through the indexer (not verified here — investigate `lez/indexer/` if needed).

---

## 3. Merkle tree structure

### Hash + leaf encoding

- **Hash:** SHA-256 (`sha2::Sha256` on host, `risc0_zkvm::sha::Impl` in guest — byte-identical).
- **Leaf encoding:** the raw 32-byte `Commitment` is hashed once before being placed at the bottom level:

```rust
// lez/nssa/src/merkle_tree/mod.rs:99-103
let mut node_index = new_index + self.capacity - 1;
let mut node_hash = hash_value(&value);
// ...
self.set_node(node_index, node_hash);

// lez/nssa/src/merkle_tree/mod.rs:146-157
fn hash_two(left: &Node, right: &Node) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_value(value: &Value) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}
```

So the circuit's first step is `leaf = SHA256(commitment_bytes)`, then alternating `SHA256(L||R)` up the path.

### Height / depth

- The `MerkleTree` is **append-only** with **doubling capacity** (`lez/nssa/src/merkle_tree/mod.rs:74-89`). When `length == capacity`, capacity doubles and existing nodes are re-embedded as a left subtree of the new tree.
- **Genesis:** the system `V03State::default()` constructs `CommitmentSet::with_capacity(32)` (`lez/nssa/src/state.rs:134, 169`) — initial capacity 32, depth 5.
- **Effective depth at any moment** = `next_power_of_two(length).trailing_zeros()` (`lez/nssa/src/merkle_tree/mod.rs:59-62`).
- The `default_values` table holds 32 levels of pre-computed empty-subtree hashes (`lez/nssa/src/merkle_tree/default_values.rs:1` — `pub const DEFAULT_VALUES: [[u8; 32]; 32]`), giving a hard ceiling of 2^32 leaves *for the precomputed defaults*. The tree itself can technically grow beyond, but the constants stop there.

So **the circuit must support a variable depth** equal to the length of the sibling-path vector returned by `getProofForCommitment` at proof time. This is unusual versus zk-kit style fixed-depth designs.

### Root update / query

- **Update:** `CommitmentSet::extend` (`lez/nssa/src/state.rs:51-57`) inserts a list of commitments, then `root_history.insert(self.digest())` keeps the latest root.
- **Query:** `CommitmentSet::digest(&self) -> CommitmentSetDigest` returns the current root (`lez/nssa/src/state.rs:37-39`).
- **Externally exposed:** the root is **not** in a dedicated RPC; the sequencer enforces freshness by checking PPE transactions' nullifier-bound digests against `root_history` at inclusion (`lez/nssa/src/state.rs:322-337`):

```rust
pub(crate) fn check_nullifiers_are_valid(
    &self,
    new_nullifiers: &[(Nullifier, CommitmentSetDigest)],
) -> Result<(), NssaError> {
    for (nullifier, digest) in new_nullifiers {
        if self.private_state.1.contains(nullifier) {
            return Err(NssaError::InvalidInput("Nullifier already seen".to_owned()));
        }
        if !self.private_state.0.root_history.contains(digest) {
            return Err(NssaError::InvalidInput(
                "Unrecognized commitment set digest".to_owned(),
            ));
        }
    }
    Ok(())
}
```

This is the model the LP-0005 verifier must match: it accepts a proof that asserts "the commitment was in the tree at root R" + "R is a root that the chain recently knew." The verifier program must therefore have access to the recent-roots set — see section 11 for how to provide it.

### Is the root on-chain?

The root is on-chain as state, but **there is no LEZ syscall for a program to read it**. The only on-chain consumer that compares against `root_history` is the sequencer's `check_nullifiers_are_valid`, which runs as part of `ValidatedStateDiff` construction, not inside a user program. This is the central design question for our verifier program; see section 11 (a/c).

---

## 4. LEZ on-chain Risc0 receipt verification surface

### How existing programs compose: `env::verify` (Risc0 assumption)

A LEZ program does NOT call `Receipt::verify` directly. Composition is via Risc0's "assumption" mechanism. The privacy-preserving outer circuit (the one verified on-chain) reads each program's `ProgramOutput` from its journal and asserts it was produced by that program:

```rust
// lez/program_methods/guest/src/bin/privacy_preserving_circuit/execution_state.rs:138-198
while let Some((chained_call, caller_program_id)) = chained_calls.pop_front() {
    // ...
    let Some(program_output) = program_outputs_iter.next() else {
        panic!("Insufficient program outputs for chained calls");
    };
    // ...
    let program_output_words =
        &to_vec(&program_output).expect("program_output must be serializable");
    env::verify(chained_call.program_id, program_output_words).unwrap_or_else(
        |_: Infallible| unreachable!("Infallible error is never constructed"),
    );
    // ...
}
```

And the host side does `env_builder.add_assumption(inner_receipt)` for each chained call (`lez/nssa/src/privacy_preserving_transaction/circuit.rs:108`). The resulting outer proof is the single `Receipt` over `PRIVACY_PRESERVING_CIRCUIT_ELF` with image ID `PRIVACY_PRESERVING_CIRCUIT_ID`.

### Smallest working example of `Receipt::verify`

The only direct `Receipt::verify` in the LEZ codebase is on the *outer* PPE receipt, used by the sequencer (and benches) when accepting a transaction:

```rust
// lez/nssa/src/privacy_preserving_transaction/circuit.rs:18-37
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proof(pub(crate) Vec<u8>);

impl Proof {
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub const fn from_inner(inner: Vec<u8>) -> Self {
        Self(inner)
    }

    pub(crate) fn is_valid_for(&self, circuit_output: &PrivacyPreservingCircuitOutput) -> bool {
        let inner: InnerReceipt = borsh::from_slice(&self.0).unwrap();
        let receipt = Receipt::new(inner, circuit_output.to_bytes());
        receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
    }
}
```

### What this means for LP-0005

There are **two architectural options** for the on-chain verifier path:

**Option A — chained call (no raw receipt on chain):** Our verifier is itself a LEZ guest program. Its `ProgramOutput` includes the threshold N, the context binding, the presenter binding, and a `proven == true` flag. The wallet executes our program (perhaps inside a chained call from a "gate" program like governance/auth-transfer) and the PPE outer circuit's `env::verify(our_program_id, our_journal)` automatically gates inclusion. **The "Risc0 circuit" the prize talks about effectively becomes our LEZ guest itself.**

**Option B — receipt as instruction bytes:** The wallet pre-proves an independent Risc0 ELF (with its own image ID) off-chain, then submits the borsh-serialized `InnerReceipt` + journal as instruction-data bytes to a LEZ verifier program. The verifier guest internally calls `Receipt::new(inner, journal).verify(KNOWN_ATTESTATION_IMAGE_ID)`. This costs ≈ 12 ms of host verify per receipt + whatever cycles `Receipt::verify` consumes when run *inside* the Risc0 guest (recursive verification — could be expensive; verify with `risc0-zkvm-3.0.5` docs before committing).

Option A is the well-trodden path (it's how every LEZ program already composes). Option B is the path the prize text seems to imagine. Decide in section 11.

### Instruction-data carrying capacity

```rust
// lez/nssa/core/src/program.rs:16
pub type InstructionData = Vec<u32>;
```

Risc0 serde uses `Vec<u32>` words (`risc0_zkvm::serde::to_vec`). A 225 KB receipt fits as 57600 u32 words. There's no documented byte cap, but block-size benchmarks show PPE txs ≈ 225 KB on the wire (`lez/docs/benchmarks/integration_bench.md` table at "Block + tx sizes (borsh) — real proving"). Option B would roughly double that.

---

## 5. SPEL program template (from lez-multisig)

### Directory tree + one-line purpose

| Path | Purpose |
|---|---|
| `lez-multisig/Cargo.toml` | Workspace root. |
| `lez-multisig/Makefile` | Build/deploy/test/IDL/FFI orchestration. The "real" reference for repo layout. |
| `lez-multisig/README.md` | Demo runbook + high-level architecture. |
| `lez-multisig/SPEC.md` | Detailed account model, PDA derivation, instruction semantics. |
| `lez-multisig/multisig_core/Cargo.toml` + `src/lib.rs` | `no_std` shared types: `Instruction` enum, account data structs, PDA helpers. Imported by both guest and host. |
| `lez-multisig/multisig_program/Cargo.toml` + `src/lib.rs` | The SPEL program: `#[lez_program(instruction = "multisig_core::Instruction")] mod multisig_program { #[instruction] pub fn create_multisig(...) ... }` — see excerpt below. |
| `lez-multisig/multisig_program/src/{create_multisig,propose,approve,reject,execute,propose_config}.rs` | Per-instruction handler implementations (called from `lib.rs`). |
| `lez-multisig/methods/Cargo.toml` + `build.rs` + `src/lib.rs` | risc0 build glue. `build.rs` is one line: `risc0_build::embed_methods();`. `src/lib.rs` includes the generated `methods.rs`. |
| `lez-multisig/methods/guest/Cargo.toml` + `src/bin/multisig.rs` | The guest binary entry. Three lines: `risc0_zkvm::guest::entry!(multisig_program::main);`. |
| `lez-multisig/methods/guest/src/bin/generate_idl.rs` | One-line IDL generator: `spel_framework::generate_idl!("../../multisig_program/src/lib.rs");`. |
| `lez-multisig/idl-gen/Cargo.toml` + `src/main.rs` | A second IDL generator (workspace-rooted variant). |
| `lez-multisig/cli/Cargo.toml` + `src/bin/multisig.rs` | The CLI wrapper. Three lines: `#[tokio::main] async fn main() { spel::run().await; }`. |
| `lez-multisig/e2e_tests/Cargo.toml` + `src/lib.rs` + `tests/e2e_multisig.rs` + `tests/e2e_member_management.rs` | E2E integration tests against a real local sequencer. |
| `lez-multisig/lez-multisig-ffi/Cargo.toml` + `src/lib.rs` | Generated FFI client for use from C++/Qt (Basecamp module). |
| `lez-multisig/scripts/DEMO-RUNBOOK.md` | Demo walkthrough. |
| `lez-multisig/docs/{FURPS,ecosystem-project,gap-analysis,lez-framework-analysis}.md` | Design notes. |

### Key excerpts

**Guest main (`lez-multisig/methods/guest/src/bin/multisig.rs`):**

```rust
#![no_main]

risc0_zkvm::guest::entry!(multisig_program::main);
```

**Instruction handler with PDA derivation (`lez-multisig/multisig_program/src/lib.rs:21-36`):**

```rust
#[lez_program(instruction = "multisig_core::Instruction")]
mod multisig_program {
    use super::*;

    /// Create a new M-of-N multisig.
    /// multisig_state is initialized as a PDA derived from create_key.
    #[instruction]
    pub fn create_multisig(
        #[account(init, pda = arg("create_key"))]
        multisig_state: AccountWithMetadata,
        member_accounts: Vec<AccountWithMetadata>,
        create_key: [u8; 32],
        threshold: u8,
        members: Vec<[u8; 32]>,
    ) -> SpelResult {
        let accounts: Vec<AccountWithMetadata> = std::iter::once(multisig_state)
            .chain(member_accounts.into_iter())
            .collect();
        let (accounts_out, chained_calls) =
            crate::create_multisig::handle(&accounts, &create_key, threshold, &members);

        Ok(SpelOutput::execute(accounts_out, chained_calls))
    }
    // ... approve / reject / execute / propose_config follow the same pattern.
}
```

`AccountWithMetadata`, `SpelResult`, `SpelOutput`, `Claim`, `AccountPostState` all come from `spel_framework::prelude::*` (`spel/spel-framework-core/src/lib.rs:18-45`).

**Account attribute reference** (from `spel/README.md:96-106`):

| Attribute | Description |
|-----------|-------------|
| `#[account(mut)]` | Account is writable |
| `#[account(init)]` | Account is being created (use `new_claimed`) |
| `#[account(signer)]` | Account must sign the transaction |
| `#[account(pda = literal("seed"))]` | PDA derived from a constant string |
| `#[account(pda = account("other"))]` | PDA derived from another account's ID |
| `#[account(pda = arg("create_key"))]` | PDA derived from an instruction argument |
| `members: Vec<AccountWithMetadata>` | Variable-length trailing account list |

**IDL generator (`lez-multisig/methods/guest/src/bin/generate_idl.rs`):**

```rust
spel_framework::generate_idl!("../../multisig_program/src/lib.rs");
```

**CLI wrapper (`lez-multisig/cli/src/bin/multisig.rs`):**

```rust
#[tokio::main]
async fn main() {
    spel::run().await;
}
```

`spel::run()` is the IDL-driven CLI library (`spel/spel-cli/src/lib.rs:1-30`) — it parses `--idl`, `--program`, `--data`, `--dry-run`, etc., and dispatches instructions by name.

**Build pipeline (`lez-multisig/Makefile:113-128`):**

```make
build: ## Build the multisig guest binary
	cargo risczero build --manifest-path methods/guest/Cargo.toml
	@echo "✅ Guest binary built: $(MULTISIG_BIN)"

deploy: ## Deploy multisig and token programs to sequencer
	wallet deploy-program $(MULTISIG_BIN)
	wallet deploy-program $(TOKEN_BIN)
```

The output ELF is at `target/riscv32im-risc0-zkvm-elf/docker/multisig.bin`.

**E2E test env (`lez-multisig/Makefile:155`):**

```
RISC0_SKIP_BUILD=1 SEQUENCER_URL=http://127.0.0.1:3040 \
  MULTISIG_PROGRAM=$(PROGRAMS_DIR)/multisig.bin \
  TOKEN_PROGRAM=$(TOKEN_BIN) \
  cargo test -p lez-multisig-e2e --test e2e_multisig -- --nocapture
```

This is the exact integration-test scaffolding we should clone.

---

## 6. Logos Delivery / Messaging API

### What's actually shipped

`logos-delivery-module/` contains only a `README.md` + 3 docs files. There is no Rust source, no header. The build is Nix + C++/Qt (`logos-delivery-module/README.md:10-90`). The artifact is a Qt plugin `delivery_module_plugin.dylib` + `liblogosdelivery.dylib` + `librln.dylib` + `libpq.dylib`.

### Synchronous API (Qt slots, returns `LogosResult`)

From `logos-delivery-module/README.md:88-101`:

- `createNode(cfg: QString)` — initialise (JSON config). Call once.
- `start()` / `stop()`
- `send(contentTopic: QString, payload: QString) -> request_id` — sync return; delivery is async.
- `subscribe(contentTopic: QString)` / `unsubscribe(contentTopic: QString)`
- `getAvailableNodeInfoIDs()` / `getNodeInfo(id)` / `getAvailableConfigs()`

### Envelope format (across FFI)

The plugin wraps the user payload (UTF-8 → base64) in (`logos-delivery-module/README.md:158-163`):

```json
{ "contentTopic": "<topic>", "payload": "<base64>", "ephemeral": false }
```

Content-topic convention follows LIP-23 (`/myapp/1/chat/proto` format).

### Async events emitted to Qt

`messageSent`, `messagePropagated`, `messageError`, `messageReceived`, `connectionStateChanged`. Each is a `QVariantList data` payload (see README lines 174-198 for exact positional schema).

### Encryption guarantees

Underlying transport is Waku (`twn` preset = "RLN-protected Waku Network", `logos.dev` preset = "Logos Dev Network"). The `liblogosdelivery` wraps Nim `logos-delivery` (not vendored). **There is no in-module end-to-end encryption guarantee documented here** — messages are public on the relay layer; payload privacy is the application's responsibility. For LP-0005 this means the proof payload itself is in the clear unless we add a layer on top (e.g. sealed-sender or sender-supplied AEAD with a chat-group key).

### Identity / addressing

No persistent identity at the delivery layer; addressing is by content topic. RLN provides rate-limiting (via `librln.dylib` — same Zerokit lib used by `logos-lez-rln`) but RLN is for *spam prevention*, not identity binding.

### Rust integration

There is **no Rust binding to this in the vendored repos**. Options:

1. Drive the Qt plugin from a Logos Basecamp app (C++/QML, see section 7).
2. Pull in `liblogosdelivery` (the upstream C lib) directly and write our own Rust FFI binding.
3. Stand up a local Logos Core process with the module loaded and talk to it over its event interface.

This is one of the load-bearing unknowns — see section 11.

---

## 7. Basecamp app structure

### Build + run

```bash
nix build '.#app'              # local Nix build
./result/bin/LogosBasecamp     # run it
```

Portable builds (`'.#bin-bundle-dir'`, `'.#bin-appimage'`, `'.#bin-macos-app'`) ship a self-contained directory/AppImage/.app (`logos-basecamp/README.md:26-58`). Plugins live in `~/Library/Application Support/Logos/LogosBasecampDev/plugins/`.

### Packaging an app as a Basecamp plugin

`.lgx` packages produced by:

```bash
# Local
nix bundle --bundler github:logos-co/nix-bundle-lgx github:your-user/your-module#lib

# Portable
nix bundle --bundler github:logos-co/nix-bundle-lgx#portable github:your-user/your-module#lib
```

A `.lgx` is loaded by Basecamp's `package_manager` module. There is no `wasm` or pure-Rust path — plugins are Qt/C++/QML with a C-FFI backend.

### Architecture (from `logos-basecamp/CLAUDE.md`)

Three managers under `MainUIBackend` (a QML-facing facade):
- `CoreModuleManager` — wraps the `logos_core_*` C API for load/unload/stats.
- `UIPluginManager` — owns UI plugin widget lifecycle, app launcher.
- `PackageCoordinator` — talks to the `package_manager` IPC module for install/uninstall/upgrade.

For LP-0005 the Basecamp app would be a Qt/QML widget that:
1. Loads the FFI client generated from our SPEL program's IDL (same pattern as `lez-multisig-ffi`, see `lez-multisig/Makefile:64-75` for the codegen pipeline).
2. Talks to the LEZ wallet (or to the sequencer JSON-RPC over HTTP through a Qt plugin) to build proofs and submit transactions.
3. Optionally talks to `delivery_module_plugin` to send/subscribe proofs over Logos Messaging.

### SDK for talking to a deployed LEZ program

- **From C/C++ (Basecamp):** the `spel-client-gen` tool (`spel/spel-client-gen/`) generates a Rust `*-ffi` crate from an IDL JSON. Build that as a `.so` and call via `extern "C"` from Qt. See `lez-multisig/lez-multisig-ffi/src/lib.rs` for a real example.
- **From Rust (CLI / tests):** import the IDL and use `spel::run()` directly (`spel/spel-cli/src/lib.rs:43-100`).
- **From `wallet` (cargo binary):** `wallet deploy-program <ELF>`; `wallet send-transaction ...` (see e2e test env in section 5).

---

## 8. logos-lez-rln: identity binding pattern

### `id_commitment` construction

```rust
// logos-lez-rln/lez-rln/methods/guest/src/bin/rln_registration.rs:505-516
fn slash(
    self_program_id: ProgramId,
    identity_secret: [u8; 32],
    config_account: &AccountWithMetadata,
    tree_main: &AccountWithMetadata,
    membership_account: &AccountWithMetadata,
    bottom_subtree: &AccountWithMetadata,
    instruction_data: Vec<u32>,
) {
    validate_field_element(&identity_secret);

    let id_commitment = hash_single(&identity_secret);
    let config = RegistrationConfig::from_data(config_account.account.data.as_ref());
```

`hash_single` is BN254 Poseidon, not SHA-256:

```rust
// logos-lez-rln/lez-rln/methods/guest/src/hash.rs:1-25
use rust_poseidon_bn254_pure::bn254::field::Felt;
use rust_poseidon_bn254_pure::poseidon::permutation::{compress_1, compress_2};

pub const ZERO: [u8; 32] = [0u8; 32];

pub fn validate_field_element(bytes: &[u8; 32]) {
    let felt = Felt::unsafe_from_le_bytes(bytes);
    assert!(Felt::is_valid(&felt), "Input is not a valid BN254 field element (must be < prime)");
}

pub fn hash_single(input: &[u8; 32]) -> [u8; 32] {
    validate_field_element(input);
    let hash_felt = compress_1(Felt::unsafe_from_le_bytes(input));
    Felt::to_le_bytes(&hash_felt)
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    validate_field_element(left);
    validate_field_element(right);
    let hash_felt = compress_2([
        Felt::unsafe_from_le_bytes(left),
        Felt::unsafe_from_le_bytes(right),
    ]);
    Felt::to_le_bytes(&hash_felt)
}
```

The host side uses Zerokit's `seeded_keygen` to derive `(identity_secret, id_commitment)` together (`logos-lez-rln/lez-rln/lez-rln-ffi/src/lib.rs:417-442`):

```rust
// logos-lez-rln/lez-rln/lez-rln-ffi/src/lib.rs:417-442
/// Uses zerokit's seeded_keygen to derive identity_secret and id_commitment.
pub unsafe extern "C" fn rln_ffi_generate_identity(...) {
    let (mut identity_secret_fr, id_commitment_fr) = rln::prelude::seeded_keygen(seed);
    // zeroize the secret before returning
    let id_secret_hash_bytes = rln::utils::fr_to_bytes_le(&identity_secret_fr);
    // ...
    identity_secret_fr = rln::prelude::Fr::from(0u64);
```

### Registration leaf

The Merkle leaf is **not** `id_commitment` directly — it's the rate-bound commitment:

```rust
// logos-lez-rln/lez-rln/methods/guest/src/registration.rs:207-212
/// The leaf is H(id_commitment, rate_limit).
pub fn compute_registration_leaf(id_commitment: &[u8; 32], rate_limit: u64) -> [u8; 32] {
    validate_field_element(id_commitment);
    let rate_bytes = ...;  // u64 → field bytes
    hash_pair(id_commitment, &rate_bytes)
}
```

This is the Waku/RLN "rate commitment" pattern. Equivalent host code at `logos-lez-rln/lez-rln/lez-rln-ffi/src/lib.rs:479`: `let rate_commitment_fr = rln::hashers::poseidon_hash(&[id_commitment_fr, rate_limit_fr]);`.

### Membership address derivation

```rust
// logos-lez-rln/lez-rln/methods/guest/src/registration.rs:246-260
/// The seed is hash(tree_id || id_commitment) to create a unique 32-byte seed.
pub fn derive_membership_seed(tree_id: &[u8; 24], id_commitment: &[u8; 32]) -> PdaSeed {
    let seed = membership_seed_bytes(tree_id, id_commitment);
    // ...
}

pub fn membership_seed_bytes(tree_id: &[u8; 24], id_commitment: &[u8; 32]) -> [u8; 32] {
    validate_field_element(id_commitment);
    let tree_id_padded = ...;  // 24 bytes → 32 bytes (zero-padded)
    hash_pair(&tree_id_padded, id_commitment)
}
```

### How a presenter proves knowledge (`Slash` flow)

To slash a member, the caller submits the `identity_secret`:

```rust
// logos-lez-rln/lez-rln/methods/guest/src/bin/rln_registration.rs:514-523
validate_field_element(&identity_secret);

let id_commitment = hash_single(&identity_secret);
let config = RegistrationConfig::from_data(config_account.account.data.as_ref());

let membership_bytes = membership_account.account.data.as_ref();
assert!(!membership_bytes.is_empty(), "Membership account is empty - member doesn't exist or already slashed");

let membership = MembershipData::from_data(membership_bytes);
assert!(membership.id_commitment == id_commitment, "id_commitment mismatch - provided identity_secret doesn't match membership");
```

The on-chain program just re-hashes `identity_secret` and compares to the stored `id_commitment`. The "proof of knowledge" is by-construction: revealing `identity_secret` *is* the proof. For RLN this is fine because revealing it slashes the member. **For LP-0005 we cannot reveal the secret** — we'd instead include a knowledge-of-discrete-log-style statement inside our Risc0 circuit: "I know `identity_secret` such that `Poseidon(identity_secret) == public_id_commitment`, and `public_id_commitment` is the identity binding for this attestation."

### Pattern we'll adapt

1. Presenter holds `identity_secret` (BN254 field element).
2. Public `id_commitment = Poseidon(identity_secret)` is bound into the proof's journal.
3. The Risc0 circuit witnesses `identity_secret`, recomputes `id_commitment` inside the guest, and commits it to the journal — proving the presenter knows the secret without revealing it.
4. The verifier (on-chain program or off-chain recipient) checks that the journal's `id_commitment` matches the one the presenter publicly advertised (e.g. registered to a chat group's allowlist beforehand).

This addresses the prize's "proof forwarding" open problem (`LP-0005.md:74-76`).

### Tree structure (analogue for LP-0005, NOT what we'll use)

RLN uses a **fixed-depth-20 sparse tree** split into 10+10 (`logos-lez-rln/lez-rln/rln-layouts/src/lib.rs:281-290`):

```rust
pub const TREE_DEPTH: usize = 20;
pub const TOP_DEPTH: usize = 10;
pub const BOTTOM_DEPTH: usize = 10;
pub const SUBTREE_LEAVES: usize = 1024;
```

This is **separate** from the LEZ private-account Merkle tree (which is dynamic SHA-256 — section 3). LP-0005 must use the LEZ private-account tree, not this one.

---

## 9. Risc0 baseline (from lssa-zkvm-testing + lez)

### Version pin

```
risc0-zkvm = { version = "3.0.5", default-features = false, features = ['std'] }
risc0-build = "3.0.5"
```
— `lez/Cargo.toml:89-90`. Also `lez-programs/Cargo.toml:39`.

### Machine + accelerators

Per `lez/docs/benchmarks/cycle_bench.md:6-15`:

| Field | Value |
|---|---|
| Chip | Apple M2 Pro (8P+4E) |
| RAM | 16 GB |
| OS | macOS 15.5 |
| Rust | 1.94.0 |
| Risc0 zkVM | 3.0.5 |
| Profile | release |
| GPU acceleration | **none** |

### Proving times observed

Standalone real-proving (`cycle_bench.md:34-49`):

| Program | Instruction | total_cycles (po2) | prove_s |
|---|---|---:|---:|
| authenticated_transfer | Transfer | 131,072 | 13.7 |
| token | Transfer | 262,144 | 27.2 |
| amm | AddLiquidity | 1,048,576 | 111.7 |
| amm | SwapExactInput | 1,048,576 | 126.4 |

Linear fit: ≈ 100 µs per total cycle (≈ 10k cycles/s) on this CPU. Cost is bucketed by next power of two of `user_cycles`.

### PPE composition tax (`cycle_bench.md:51-64`)

| Case | prove_s | proof_bytes (S_agg) |
|---|---:|---:|
| auth_transfer Transfer standalone | 13.7 | n/a |
| auth_transfer Transfer in PPE | 61.5 | 223,551 |
| chain_caller depth=1 | 122.6 | 223,551 |
| chain_caller depth=9 | 544.3 | 223,551 |

≈ 48 s composition tax for the first program in a PPE; ≈ 53 s per additional chained call. Proof bytes are **constant ≈ 224 KB** regardless of depth.

### Verifier cost

`Receipt::verify(PRIVACY_PRESERVING_CIRCUIT_ID)` on the outer PPE receipt: **12.2 ms ± 0.25 ms** (criterion, n=100), `cycle_bench.md:72-75`. Not on the latency critical path.

### Integration end-to-end (`integration_bench.md:57-66`)

Real-proving `private_chained_flow`: each PPE step ≈ 127 s on submit (wallet pays the prove cost), inclusion ≈ 1 ms. So a single user proof generation will be on the order of 60-130 s of wall time today.

### Verdict on Risc0 vs other zkVMs

`lssa-zkvm-testing/README.md` enumerates zkWASM, zkMIPS, Valida, SP1, Nexus, RISC0 as candidates that the Nescience team benchmarked. **There is no consolidated verdict file in this repo** — only per-zkVM `README.md` setup scripts. No `RESULTS.md` or comparison table. The fact that LEZ shipped on Risc0 is itself the verdict.

The Risc0 sub-folder contents (`lssa-zkvm-testing/risc0/scripts_and_tools/`) are bench scripts (`risc0_bench_arithmetic.sh`, `risc0_bench_memory.sh`) and a setup script. Not directly useful for LP-0005, but confirms version + reproducibility approach.

---

## 10. λPrize submission expectations (from lambda-prize repo)

### Is LP-0005 spec checked in?

Yes: `lambda-prize/prizes/LP-0005.md` (124 lines). Status is **OPEN** as of the README table (`lambda-prize/README.md:32`).

### Verbatim key bits

Prize size: **$1,200**, "Effort: Large" (`LP-0005.md:87-88`). Note: the prize file says `$1,200` but doesn't specify currency; the global README (`lambda-prize/README.md:89`) says prizes are paid in **USDT** on Ethereum, not USDC. The user-supplied task description says "USDC" — flag.

Submission requirements (`LP-0005.md:96-100`):

> - Public repository with all circuit code, LEZ verifier program, off-chain verifier library, and client-side tooling under MIT or Apache-2.0.
> - Verifier program deployed on LEZ testnet with a verified program ID.
> - End-to-end demo video in which the builder narrates what they built and why, walks through the architecture and key implementation decisions, and demonstrates both verification paths. [...] A silent screencast is not sufficient (see demo requirements).
> - Write-up covering: circuit design, commitment format targeting, context-binding approach, both verification paths, privacy guarantees (including what is and is not hidden), security assumptions, known limitations, and integration instructions.
> - Proof generation time and on-chain verification gas cost benchmarks.

Evaluation process (`LP-0005.md:102-111`):

> Submissions are evaluated first-come-first-served against the success criteria. The first submission that satisfies all criteria wins. Evaluators will independently clone the repository and run the demo script from a clean environment; the script must succeed without modification.
> - **Submissions:** each builder (or team) is allowed a maximum of **3 submissions** per prize, with at most **one submission/review per week**.
> - **Feedback:** initial evaluation feedback is limited to a pass/fail indication against the success criteria.

### Submission format (`lambda-prize/README.md:55-63`)

1. Create `solutions/LP-0005.md`.
2. Fill in the solution template (describe approach, link repo, attach materials).
3. Open a PR titled `Solution: LP-0005 — <Short Description>`.
4. After merge, claim payment via the [Lambda Prize payment issue template](https://github.com/logos-co/lambda-prize/issues/new?template=lambda-prize-claim.yml). Provide full legal name + country (private) + Ethereum address (public).

There are existing solution files for LP-0009, LP-0010, LP-0012, LP-0014 — useful precedents. (Not opened here; do so before drafting.)

### Critical eligibility/policy bits

- All code must be MIT or Apache-2.0 (LP-0005 line 96 + global TERMS).
- "Original work" — teams must hold rights. Submissions become public + non-confidential.
- Three submissions max per prize; one per week.
- Demo must include narrated video, demonstrating *both* paths (on-chain + off-chain), with terminal output showing `RISC0_DEV_MODE=0` (`LP-0005.md:60`).
- At least **3 distinct applications** must integrate the primitive, **including one built by a party outside the submitting team** (`LP-0005.md:34`). This is the most demanding criterion and changes the project's social scope.

### Open issue: contradiction between prize text and code

`LP-0005.md:31` literally requires the circuit to target `SHA256(npk || program_owner || balance || nonce || SHA256(data))`. The real commitment includes a domain separator and binds to `account_id`, not `npk` (section 1). We need clarification — either the prize text will be updated, or the success criterion is interpreted loosely as "target the LEZ private account commitment as it actually is in the deployed code." Recommend opening a clarification issue early.

---

## 11. Open questions & gaps to resolve before coding

### A. How a SPEL program receives a Risc0 receipt as an instruction argument

**Decision needed: Option A (chained call) vs Option B (raw receipt bytes) — see section 4.**

Option A risks:
- The circuit code lives inside the LEZ "guest" world. We don't ship a "Risc0 circuit" in the sense the prize text means — we ship a LEZ program that *happens to be a Risc0 guest*, which the PPE outer circuit composes. This may be considered acceptable since the LEZ programs themselves are Risc0 circuits, but the prize text emphasises "transmitted over Logos Messaging and verified locally". A program-output journal alone isn't independently verifiable; the *PPE outer receipt* is — and binding to it adds a sequencer round-trip.

Option B risks:
- Verifying a Risc0 `Receipt` inside another Risc0 guest is recursive verification. Risc0 3.x supports this via succinct receipts (`ProverOpts::succinct()` is used in PPE, see `lez/nssa/src/privacy_preserving_transaction/circuit.rs:133`), but cycle cost of `Receipt::verify` inside a guest is unknown to me from this recon. Must verify against `risc0-zkvm-3.0.5` docs.
- Instruction-data size: 225 KB receipts double the on-wire tx size.

**Action:** prototype both. Option A is the fast path; Option B is the "real" path the prize asks for. May end up using Option A on-chain + Option B off-chain (over Logos Messaging — the proof there is independent of LEZ and *must* be Option B-shaped).

### B. Byte format of a Risc0 receipt for serialization through Logos Messaging

From `lez/nssa/src/privacy_preserving_transaction/circuit.rs:29-37` we know:
```rust
let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);
// ...
let inner: InnerReceipt = borsh::from_slice(&self.0).unwrap();
let receipt = Receipt::new(inner, circuit_output.to_bytes());
receipt.verify(PRIVACY_PRESERVING_CIRCUIT_ID).is_ok()
```

So the wire format is: `borsh(InnerReceipt) + separately-transported journal bytes (Risc0 serde u32 words cast to u8)`. For LP-0005 off-chain transport over Logos Messaging:
1. `borsh::to_vec(receipt.inner)` → ≈ 224 KB.
2. `journal_bytes = bytemuck::cast_slice(&risc0_zkvm::serde::to_vec(&our_output)).to_vec()` → small (a few hundred bytes).
3. Concat with a versioned header (1 byte version + content-topic-bound tag + base64-encode for the Logos delivery payload string).

Logos delivery's `maxMessageSize` default is `"150KiB"` (`logos-delivery-module/README.md:124`). **224 KB > 150 KB.** Action: increase `maxMessageSize` in `createNode` config, OR fragment the receipt over multiple messages, OR shrink via `ProverOpts::groth16()` (Risc0 ≈ 256-byte final wrap — verify exists in 3.0.5 and inclusion cost on chain).

### C. How to query the current Merkle root from a verifier (on-chain syscall? off-chain RPC?)

**There is no on-chain syscall.** Recap from section 3:

- The sequencer enforces "root is recent" automatically for any *PPE transaction* by checking each nullifier's bundled `CommitmentSetDigest` against `root_history` (`lez/nssa/src/state.rs:322-337`).
- User programs do NOT have a `Clock`-like "current_root" account they can read. There IS a clock program (`lez/programs/clock/`) but no commitment-tree-root program.

Solutions:
1. **Piggy-back on the PPE machinery (Option A):** if our verifier is a LEZ program invoked as part of a chained call that the wallet wraps in a `PrivacyPreservingTransaction`, the wallet emits a nullifier with the root attached, and the sequencer validates the root for free. We just have to wire the `InputAccountIdentity::PrivateAuthorizedUpdate { membership_proof, ... }` for the user's holding account (`lez/nssa/core/src/circuit_io.rs:42-46`). The downside: this nullifies the user's account, breaking the "doesn't link the proof to the account" property (because we burn the commitment and emit a fresh one).
2. **Have the user pass the root as an instruction argument + introduce a "root attestor" program** that the sequencer-team must run (off-chain oracle): they sign the latest root into a public account. Our verifier checks signature + freshness window. This bypasses the lack of syscall but adds a trusted third party.
3. **Have the verifier program declare the root as `pre_state` data** in an account that the wallet pre-fetches from the sequencer's `getProofForCommitment` result (root reconstructable from the proof itself!). Then we use `compute_digest_for_path` inside the guest to recompute the root from `(commitment, proof)` and check that it matches a stated `public_root`. Independent of the chain knowing the root — but verification then relies on the *off-chain* assertion "this root really existed at some point", which... is precisely what (1) gives for free.

**Recommendation:** Option A + (1). The "doesn't nullify the account" privacy requirement isn't actually a hard requirement in the prize text — the requirements (`LP-0005.md:28`) say "without revealing the account's nullifier public key, exact balance, or account identity", not "without modifying the account". We can emit a new commitment with identical balance (i.e. a no-op transfer to self), satisfying privacy while leveraging the existing PPE root check. **Validate with prize maintainers whether this is acceptable.**

### D. Sub-derivation of `AccountId::for_regular_private_account` not fully audited

We have the PDA form (`lez/nssa/core/src/program.rs:152-176`) but not the regular form definition. Need to:
- Open `lez/nssa/core/src/account.rs` or wherever `AccountId::for_regular_private_account` is implemented (referenced from `program.rs:182-184` and used in tests at `lez/nssa/src/privacy_preserving_transaction/circuit.rs:225` and elsewhere), quote exact bytes, and pin a test vector.

### E. Currency mismatch: USDC vs USDT

Task description says "$1,200 USDC". Prize file says "$1,200" with no currency. λPrize README says payment is in **USDT on Ethereum**. Clarify with the user / prize maintainers — irrelevant to the build but matters for the payment claim.

### F. Off-chain verifier library: language + transport

The prize requires that "the proof can be transmitted over Logos Messaging and verified locally by a recipient" (`LP-0005.md:33`). The recipient is presumably a Basecamp app (C++/Qt + QML). Verification of a Risc0 `Receipt` from C++ requires:
- Either calling into a Rust FFI library we ship as a `.so`, mirroring `lez-multisig-ffi`. This is the path of least surprise.
- Or using Risc0's planned native verifier (does 3.0.5 have one? unclear; check).

Likely path: ship a `lp0005-ffi` crate that exports `verify_attestation(receipt_bytes, journal_bytes, context_id, presenter_id_commitment) -> bool` and bundle it into the Basecamp app.

### G. The "3 distinct integrations, one by an outside party" criterion

`LP-0005.md:34` requires *3 integrations* and *one from outside the submitting team*. This is the most logistically demanding criterion and is independent of the technical work. Plan how to recruit an outside integrator early (Discord builder-hub channel, per the prize text). Without this, the submission fails.

### H. CU / gas cost benchmarks

`LP-0005.md:51`: "Document the compute unit (CU) cost of each on-chain operation on LEZ devnet/testnet. Note: LEZ's per-transaction compute budget may change during testnet."

LEZ's CU model is exposed via the cycle_bench (`G_executor`, `G_prove`, `G_verify`, `S_agg` — `cycle_bench.md:3`). Plug our circuit's user_cycles into the same model. The actual on-chain "gas" comes from the PPE outer receipt's verify (≈ 12 ms constant + S_agg storage). If we go Option A we contribute one additional `env::verify` assumption + our program's prove segment to the chain.

### I. `RISC0_DEV_MODE=0` for the demo video

`LP-0005.md:60`: the recording must show terminal output (including proof generation) to confirm `RISC0_DEV_MODE=0` was active. Plan demo around the ≈ 60-130 s prove time so the video doesn't feel padded.

### J. Sequencer health / port discovery on devnet

The `getProgramIds()` RPC (`lez/sequencer/service/src/service.rs:161-175`) advertises program IDs by string name. After deploying our verifier, it would need to be registered there — but that endpoint hardcodes only the built-ins. Verify the wallet's program-discovery path works for user-deployed programs (likely via `wallet deploy-program` returning an ID we then store locally).

---

*Recon complete. Total cited code excerpts: ~25 from 16 distinct source files across 7 repos. All factual claims have file:line refs. Where the prize text disagrees with the code, the code is canonical and flagged here.*
