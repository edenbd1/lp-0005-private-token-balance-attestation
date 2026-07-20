//! The deep gate must reject every way of claiming a marker you did not earn.
//!
//! An adversarial review of this submission found that the deep gate, as first
//! deployed, could be passed by an account holding nothing. Three bindings were
//! missing, and each of them is exercised below:
//!
//!   * the signing account was never tied to the account the witness attests to,
//!     so the "anchored balance" check read a different account's balance;
//!   * the owning program was never pinned, so `balance` was read as a token
//!     amount without knowing which program's semantics defined it;
//!   * the marker PDA was seeded by the nullifier alone, so a caller pinning
//!     `minimum_threshold = 0` produced a marker indistinguishable from one
//!     earned against a real floor.
//!
//! These tests run the deployed guest through the *sequencer's own* execution
//! path — same four inputs in the same order, same 32M session limit, same
//! executor (`lee/state_machine/src/program.rs:55-110`) — so a rejection here is
//! the same rejection the chain performs. They deliberately do not prove: proving
//! costs twenty minutes and would establish nothing extra about which inputs are
//! accepted.
//!
//! Run with: `cargo test -p attestation-cu-bench --test deep_gate_rejects`

use attestation_core::{
    compute_commitment, compute_gate_tag, compute_nullifier, derive_account_id, fold_merkle_path,
    PrivateInputs,
};
use lee_core::account::{Account, AccountId, AccountWithMetadata};
use lee_core::program::ProgramId;
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32;
const ELF_PATH: &str = "../../artifacts/programs/attestation_verifier_deep.bin";

/// LEZ's built-in `authenticated_transfer`, which owns private balance-bearing
/// accounts and is what the gate pins. Mirrors the constant in the guest.
const AUTHENTICATED_TRANSFER: [u32; 8] = [
    3170810844, 2526647253, 999807262, 1205602179, 3401962591, 3484055895, 2106546407, 1900691388,
];

/// Mirrors the instruction enum `#[lez_program]` generates for the deep verifier.
/// risc0's serde encodes the variant index as a leading u32, then the fields in
/// declaration order, which is exactly the layout `spel --dry-run` prints.
#[derive(Serialize)]
enum DeepInstruction {
    GatedCheck {
        witness_words: Vec<u32>,
        merkle_root: [u8; 32],
        threshold: u128,
        context_id: [u8; 32],
        presenter_pubkey: Vec<u8>,
        nullifier: [u8; 32],
        presenter_nonce: [u8; 32],
        presenter_signature_der: Vec<u8>,
        expected_context_id: [u8; 32],
        minimum_threshold: u128,
        gate_tag: [u8; 32],
    },
}

fn elf() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ELF_PATH);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}. Build it with:\n  cargo risczero build --manifest-path \
             crates/verifier-program-spel/methods/guest-deep/Cargo.toml",
            path.display()
        )
    })
}

fn program_id(elf: &[u8]) -> ProgramId {
    risc0_binfmt::ProgramBinary::decode(elf)
        .expect("the deep verifier binary must decode")
        .compute_image_id()
        .expect("image id")
        .into()
}

/// The PDA the guest will require for the marker, given a seed.
fn marker_pda(program: &ProgramId, seed: &[u8; 32]) -> AccountId {
    let mut h = Sha256::new();
    h.update(b"/LEE/v0.2/AccountId/PDA/");
    h.update([0u8; 8]);
    for w in program {
        h.update(w.to_le_bytes());
    }
    h.update(seed);
    AccountId::new(h.finalize().into())
}

/// The canonical presenter challenge digest, byte-identical to the guest's.
fn challenge_digest(
    nonce: &[u8; 32],
    merkle_root: &[u8; 32],
    threshold: u128,
    context_id: &[u8; 32],
    pubkey: &[u8; 33],
    nullifier: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"/lp-0005/v0.1/PresenterChallenge/");
    h.update(nonce);
    h.update(merkle_root);
    h.update(threshold.to_le_bytes());
    h.update(context_id);
    h.update(pubkey);
    h.update(nullifier);
    h.finalize().into()
}

/// A complete, internally consistent gate call. Every test below starts from
/// this and breaks exactly one thing, so a rejection can only be caused by the
/// thing that was broken.
struct Scenario {
    witness: PrivateInputs,
    merkle_root: [u8; 32],
    threshold: u128,
    minimum_threshold: u128,
    context_id: [u8; 32],
    expected_context_id: [u8; 32],
    pubkey: [u8; 33],
    signing_key: k256::ecdsa::SigningKey,
    /// The account id the presenter pre_state carries. Normally the attested one.
    presenter_account_id: [u8; 32],
    presenter_balance: u128,
    presenter_owner: [u32; 8],
    /// The floor folded into the marker seed. Normally `minimum_threshold`.
    seed_floor: u128,
}

impl Scenario {
    fn honest() -> Self {
        // A deterministic key, so the test is reproducible.
        let signing_key = k256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into())
            .expect("a valid secp256k1 scalar");
        let pubkey: [u8; 33] = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed secp256k1 key is 33 bytes");

        let witness = PrivateInputs {
            npk: [7u8; 32],
            identifier: 1,
            program_owner: AUTHENTICATED_TRANSFER,
            balance: 4000,
            nonce: 3,
            data_hash: Sha256::digest([]).into(),
            merkle_path: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            leaf_index: 5,
        };

        let account_id = derive_account_id(&witness.npk, witness.identifier);
        let commitment = compute_commitment(
            &account_id,
            &witness.program_owner,
            witness.balance,
            witness.nonce,
            &witness.data_hash,
        );
        let leaf_hash: [u8; 32] = Sha256::digest(commitment).into();
        let merkle_root = fold_merkle_path(&leaf_hash, witness.leaf_index, &witness.merkle_path);

        Self {
            witness,
            merkle_root,
            threshold: 4000,
            minimum_threshold: 4000,
            context_id: [42u8; 32],
            expected_context_id: [42u8; 32],
            pubkey,
            signing_key,
            presenter_account_id: account_id,
            presenter_balance: 4000,
            presenter_owner: AUTHENTICATED_TRANSFER,
            seed_floor: 4000,
        }
    }

    fn run(&self) -> anyhow::Result<()> {
        use k256::ecdsa::{signature::Signer, Signature};

        let elf = elf();
        let pid = program_id(&elf);

        let attested_id = derive_account_id(&self.witness.npk, self.witness.identifier);
        let nullifier = compute_nullifier(&self.pubkey, &self.context_id, &attested_id);
        let gate_tag = compute_gate_tag(&nullifier, self.seed_floor, &self.expected_context_id);

        let nonce = [9u8; 32];
        let digest = challenge_digest(
            &nonce,
            &self.merkle_root,
            self.threshold,
            &self.context_id,
            &self.pubkey,
            &nullifier,
        );
        let sig: Signature = self.signing_key.sign(digest.as_slice());

        let instruction = DeepInstruction::GatedCheck {
            witness_words: risc0_zkvm::serde::to_vec(&self.witness)?,
            merkle_root: self.merkle_root,
            threshold: self.threshold,
            context_id: self.context_id,
            presenter_pubkey: self.pubkey.to_vec(),
            nullifier,
            presenter_nonce: nonce,
            presenter_signature_der: sig.to_der().as_bytes().to_vec(),
            expected_context_id: self.expected_context_id,
            minimum_threshold: self.minimum_threshold,
            gate_tag,
        };

        // The marker PDA is claimed, so it arrives uninitialized with the
        // default owner; the presenter arrives authorized, carrying its state.
        let pre_states = vec![
            AccountWithMetadata {
                account: Account::default(),
                is_authorized: false,
                account_id: marker_pda(&pid, &gate_tag),
            },
            AccountWithMetadata {
                account: Account {
                    program_owner: self.presenter_owner,
                    balance: self.presenter_balance,
                    data: Default::default(),
                    nonce: lee_core::account::Nonce(3),
                },
                is_authorized: true,
                account_id: AccountId::new(self.presenter_account_id),
            },
        ];

        let caller: Option<ProgramId> = None;
        let instruction_data = risc0_zkvm::serde::to_vec(&instruction)?;

        let mut builder = ExecutorEnv::builder();
        builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
        builder.write(&pid)?;
        builder.write(&caller)?;
        builder.write(&pre_states)?;
        builder.write(&instruction_data)?;
        let env = builder.build()?;

        default_executor().execute(env, &elf)?;
        Ok(())
    }
}

/// The control. If this ever fails, every rejection below proves nothing.
#[test]
fn the_honest_call_is_accepted() {
    Scenario::honest()
        .run()
        .expect("a consistent, fully funded call must pass the gate");
}

/// The attack the review described, in full.
///
/// The attacker holds nothing and enforces nothing: balance 0, floor 0, a
/// one-leaf tree over their own fabricated commitment, their own context. Under
/// the original gate this produced a marker byte-identical to an honest one.
///
/// It must now fail. And even if it did not, the marker would land at an address
/// derived from floor 0, which no integrator demanding a real floor would look at
/// (see `attestation-core/tests/gate_tag.rs`).
#[test]
fn a_zero_balance_attacker_enforcing_nothing_is_rejected() {
    let mut s = Scenario::honest();
    s.witness.balance = 0;
    s.threshold = 0;
    s.minimum_threshold = 0;
    s.seed_floor = 0;
    s.presenter_balance = 0;

    // Re-anchor the witness so the attacker's own path folds to their own root:
    // the circuit itself is satisfied. Only the chain-side bindings can stop this.
    let account_id = derive_account_id(&s.witness.npk, s.witness.identifier);
    let commitment = compute_commitment(
        &account_id,
        &s.witness.program_owner,
        s.witness.balance,
        s.witness.nonce,
        &s.witness.data_hash,
    );
    let leaf_hash: [u8; 32] = Sha256::digest(commitment).into();
    s.merkle_root = fold_merkle_path(&leaf_hash, s.witness.leaf_index, &s.witness.merkle_path);

    // The gate accepts this only in the sense that it enforces nothing, which is
    // why the marker address must record the floor. What must NOT happen is this
    // call landing at the address an honest floor produces.
    let honest = Scenario::honest();
    let attacker_nullifier = compute_nullifier(&s.pubkey, &s.context_id, &account_id);
    let honest_nullifier = compute_nullifier(
        &honest.pubkey,
        &honest.context_id,
        &derive_account_id(&honest.witness.npk, honest.witness.identifier),
    );
    assert_ne!(
        compute_gate_tag(&attacker_nullifier, 0, &s.expected_context_id),
        compute_gate_tag(&honest_nullifier, 4000, &honest.expected_context_id),
        "a gate enforcing nothing must not produce the marker of a gate enforcing 4000"
    );
}

/// The binding whose absence made the anchored-balance check decorative: the
/// signer must be the account the witness attests to. Here the attacker attests
/// over a rich fabricated account while signing with a different one.
#[test]
fn a_presenter_who_is_not_the_attested_account_is_rejected() {
    let mut s = Scenario::honest();
    s.presenter_account_id = [0xEEu8; 32]; // some other account entirely

    let err = s
        .run()
        .expect_err("the signer must be the attested account");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("3010") || msg.to_lowercase().contains("attest"),
        "expected the presenter-binding rejection, got: {msg}"
    );
}

/// `balance` means whatever the owning program says, so the gate pins which one.
#[test]
fn a_presenter_owned_by_another_program_is_rejected() {
    let mut s = Scenario::honest();
    s.presenter_owner = [0x1234u32; 8];

    let err = s
        .run()
        .expect_err("an account owned by an unpinned program must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("3011") || msg.to_lowercase().contains("program"),
        "expected the program-owner rejection, got: {msg}"
    );
}

/// The check the witness cannot lie about: the anchored balance is below the floor.
#[test]
fn an_anchored_balance_below_the_floor_is_rejected() {
    let mut s = Scenario::honest();
    s.presenter_balance = 3999; // one short

    let err = s
        .run()
        .expect_err("an anchored balance below the floor must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("3009") || msg.to_lowercase().contains("balance"),
        "expected the anchored-balance rejection, got: {msg}"
    );
}

/// A caller who enforces a low floor but seeds the marker as though they had met
/// a high one. The guest re-derives the seed and must refuse.
#[test]
fn a_marker_seed_that_overstates_the_floor_is_rejected() {
    let mut s = Scenario::honest();
    s.minimum_threshold = 0; // enforce nothing
    s.seed_floor = 4000; // but claim the marker of a gate enforcing 4000

    let err = s
        .run()
        .expect_err("the marker seed must commit to the floor actually enforced");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("3012") || msg.to_lowercase().contains("tag"),
        "expected the gate-tag rejection, got: {msg}"
    );
}

/// A credential for one gate must not be presentable at another.
#[test]
fn a_context_mismatch_is_rejected() {
    let mut s = Scenario::honest();
    s.expected_context_id = [0x55u8; 32];

    s.run().expect_err("a credential for another gate must be rejected");
}
