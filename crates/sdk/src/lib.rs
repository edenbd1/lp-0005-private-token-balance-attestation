//! Client SDK for generating LP-0005 attestation credentials.
//!
//! Typical flow:
//!
//! ```ignore
//! let presenter = PresenterKey::generate();
//! let proof = AttestationProver::new()
//!     .with_account(account_inputs)            // npk, identifier, balance, ...
//!     .with_merkle_proof(path, leaf_index, root)
//!     .with_context(context_id)
//!     .with_threshold(N)
//!     .with_presenter_pubkey(presenter.public())
//!     .prove()?;                                // produces a Risc0 receipt
//!
//! // Later, when presenting:
//! let signature = presenter.sign(verifier_nonce, proof.journal());
//! transmit(proof, signature);
//! ```

use anyhow::Result;
use attestation_core::{
    compute_commitment, compute_nullifier, derive_account_id, fold_merkle_path, PrivateInputs,
    PublicJournal,
};
use attestation_methods::{ATTESTATION_ELF, ATTESTATION_ID};
use attestation_verifier_offchain::presenter_challenge_digest;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

pub use attestation_core::{PrivateInputs as Inputs, PublicJournal as Journal};

/// Long-lived presenter identity. The public key goes into the proof journal;
/// the secret key signs verifier-supplied challenges.
pub struct PresenterKey(SigningKey);

impl PresenterKey {
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut rand::thread_rng()))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self(SigningKey::from_bytes(bytes.into())?))
    }

    /// SEC1 compressed-point encoding (33 bytes).
    pub fn public(&self) -> [u8; 33] {
        let vk = self.0.verifying_key();
        let pt = vk.to_encoded_point(true);
        let bytes = pt.as_bytes();
        assert_eq!(bytes.len(), 33, "compressed secp256k1 pubkey is 33 bytes");
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    /// Sign a verifier-supplied challenge bound to the journal.
    pub fn sign(&self, nonce: &[u8; 32], journal: &PublicJournal) -> Vec<u8> {
        let digest = presenter_challenge_digest(nonce, journal);
        self.sign_digest(&digest)
    }

    /// Sign an already-computed challenge digest.
    ///
    /// The privacy-preserving on-chain path has no pre-generated credential to
    /// derive a journal from: the attestation is proved inline by the LEZ program,
    /// so the digest is built from the witness and statement directly. The bytes
    /// signed are identical either way, so a signature made here verifies in the
    /// off-chain verifier and in the on-chain guest without modification.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        let sig: Signature = self.0.sign(digest);
        sig.to_der().as_bytes().to_vec()
    }
}

/// A complete attestation: the Risc0 receipt and the decoded journal.
#[derive(Debug)]
pub struct AttestationProof {
    pub receipt: Receipt,
    pub journal: PublicJournal,
}

/// Inputs for generating a credential.
pub struct ProveRequest {
    pub npk: [u8; 32],
    pub identifier: u128,
    pub program_owner: [u32; 8],
    pub balance: u128,
    pub nonce: u128,
    pub data_hash: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
    pub leaf_index: u64,
    pub merkle_root: [u8; 32],
    pub threshold: u128,
    pub context_id: [u8; 32],
    pub presenter_pubkey: [u8; 33],
}

/// Receipt kind to produce.
///
/// `Composite` is the default — a multi-segment receipt that's fast to
/// generate but ~300 KB on disk. `Groth16` wraps the inner STARK in a
/// succinct Groth16 SNARK (~256 bytes); credentials fit any payload limit,
/// at the cost of a heavier prove step. The Groth16 prover runs in a
/// docker sidecar (`risczero/risc0-groth16-prover`) that requires the
/// BN254 CRS; the prover image is amd64 so macOS arm64 users need
/// Rosetta. Bonsai endpoints work without local docker.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReceiptKind {
    #[default]
    Composite,
    Groth16,
}

/// Generate a fresh attestation credential with the default (composite) receipt.
pub fn prove(req: ProveRequest) -> Result<AttestationProof> {
    prove_with_kind(req, ReceiptKind::Composite)
}

/// Generate a fresh attestation credential wrapped in a succinct Groth16
/// receipt (~256 bytes). Use this when the credential will be transmitted
/// over a bandwidth-constrained channel (e.g. Logos Delivery's per-message
/// size limit). Requires the local prover to have access to the BN254 CRS
/// or to delegate to Bonsai.
pub fn prove_groth16(req: ProveRequest) -> Result<AttestationProof> {
    prove_with_kind(req, ReceiptKind::Groth16)
}

/// Why an attestation could not be produced.
///
/// Proving fails for a small number of genuinely distinct reasons, and a bare
/// risc0 error tells the user almost nothing about which. Each variant here
/// names the cause and what to do about it.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    /// The witness does not satisfy the statement. The guest asserted and
    /// aborted, so no proof exists — by design.
    #[error("the attestation is not true for these inputs: {reason}\n\
             This is not a bug: the circuit refuses to prove a false statement.")]
    StatementFalse { reason: String },

    /// The Risc0 toolchain is missing or the wrong version.
    #[error("the Risc0 prover is unavailable: {0}\n\
             Install it with:  curl -L https://risczero.com/install | bash && rzup install r0vm 3.0.5")]
    ProverUnavailable(String),

    /// Groth16 wrapping needs the BN254 CRS, which ships in a Docker sidecar.
    #[error("Groth16 wrapping failed: {0}\n\
             It needs Docker running for the BN254 prover sidecar. Either start Docker, \
             or use the default composite receipt, which needs no sidecar but is ~300 KB \
             instead of ~1.5 KB.")]
    Groth16Unavailable(String),

    /// The guest ran past the cycle limit.
    #[error("proving exceeded the zkVM session limit: {0}\n\
             The most common cause is an over-deep Merkle path; check merkle_path.len().")]
    SessionLimit(String),

    /// Anything else, passed through with its context intact.
    #[error("proof generation failed: {0}")]
    Other(String),
}

impl ProveError {
    /// Classify a raw prover error into something actionable.
    ///
    /// Risc0 surfaces failures as opaque strings, so this inspects them. The
    /// ordering matters: a guest panic mentions its assert message, which is the
    /// most informative case and must be matched before the generic ones.
    fn classify(e: &anyhow::Error) -> Self {
        let msg = format!("{e:#}");
        let low = msg.to_lowercase();

        // Guest asserts carry their own message; surface it verbatim.
        for marker in [
            "balance is below the attested threshold",
            "merkle path does not anchor to the claimed root",
        ] {
            if msg.contains(marker) {
                return Self::StatementFalse {
                    reason: marker.to_owned(),
                };
            }
        }
        if low.contains("guest panicked") {
            let reason = msg
                .split("Guest panicked:")
                .nth(1)
                .unwrap_or(&msg)
                .trim()
                .to_owned();
            return Self::StatementFalse { reason };
        }
        if low.contains("session limit") || low.contains("cycle limit") {
            return Self::SessionLimit(msg);
        }
        if low.contains("groth16") || low.contains("stark2snark") || low.contains("docker") {
            return Self::Groth16Unavailable(msg);
        }
        if low.contains("r0vm") || low.contains("no such file") || low.contains("not found") {
            return Self::ProverUnavailable(msg);
        }
        Self::Other(msg)
    }
}

/// Same as [`prove`], but with failures classified into [`ProveError`].
///
/// Prefer this at any user-facing boundary: it is the difference between
/// "proof generation failed: exit status 101" and a message naming the cause.
pub fn prove_checked(req: ProveRequest) -> std::result::Result<AttestationProof, ProveError> {
    prove(req).map_err(|e| ProveError::classify(&e))
}

/// Groth16 counterpart of [`prove_checked`].
pub fn prove_groth16_checked(
    req: ProveRequest,
) -> std::result::Result<AttestationProof, ProveError> {
    prove_groth16(req).map_err(|e| ProveError::classify(&e))
}

fn prove_with_kind(req: ProveRequest, kind: ReceiptKind) -> Result<AttestationProof> {
    let account_id = derive_account_id(&req.npk, req.identifier);
    let nullifier = compute_nullifier(&req.presenter_pubkey, &req.context_id, &account_id);

    let priv_in = PrivateInputs {
        npk: req.npk,
        identifier: req.identifier,
        program_owner: req.program_owner,
        balance: req.balance,
        nonce: req.nonce,
        data_hash: req.data_hash,
        merkle_path: req.merkle_path,
        leaf_index: req.leaf_index,
    };
    let journal_stub = PublicJournal {
        merkle_root: req.merkle_root,
        threshold: req.threshold,
        context_id: req.context_id,
        presenter_pubkey: req.presenter_pubkey,
        nullifier,
    };

    let env = ExecutorEnv::builder()
        .write(&priv_in)?
        .write(&journal_stub)?
        .build()?;

    let opts = match kind {
        ReceiptKind::Composite => ProverOpts::default(),
        ReceiptKind::Groth16 => ProverOpts::groth16(),
    };
    let prover = default_prover();
    let prove_info = prover.prove_with_opts(env, ATTESTATION_ELF, &opts)?;

    // Emit cycle / segment metrics for the CU-cost criterion. The host process
    // already prints wall-clock; these are the in-zkVM compute units that the
    // LEZ PPE pipeline charges for. Stats are stable across prover backends
    // because they're a property of the guest binary, not the host hardware.
    let stats = &prove_info.stats;
    eprintln!(
        "[prove-metrics] total_cycles={} segments={} user_cycles={} paging_cycles={} reserved_cycles={}",
        stats.total_cycles,
        stats.segments,
        stats.user_cycles,
        stats.paging_cycles,
        stats.reserved_cycles,
    );

    let receipt = prove_info.receipt;
    let journal: PublicJournal = receipt.journal.decode()?;
    Ok(AttestationProof { receipt, journal })
}

/// Re-export so SDK users get a single dependency.
pub use attestation_verifier_offchain::{
    verify_credential, VerifyError, ATTESTATION_ID as PROGRAM_ID,
};

/// Convenience helper: rebuild the host-side commitment + Merkle leaf hash from raw inputs.
pub fn precompute_leaf(req: &ProveRequest) -> ([u8; 32], [u8; 32]) {
    let account_id = derive_account_id(&req.npk, req.identifier);
    let commit = compute_commitment(
        &account_id,
        &req.program_owner,
        req.balance,
        req.nonce,
        &req.data_hash,
    );
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(commit);
    let leaf_hash: [u8; 32] = h.finalize().into();
    (commit, leaf_hash)
}

/// Convenience helper: synthesize a Merkle path of the given depth from a leaf hash,
/// suitable for tests/demos that do not have a sequencer-provided proof yet.
pub fn synthetic_merkle_path(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    depth: usize,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut path = Vec::with_capacity(depth);
    for i in 0..depth {
        let mut h = Sha256::new();
        h.update([i as u8; 32]);
        path.push(h.finalize().into());
    }
    let root = fold_merkle_path(leaf_hash, leaf_index, &path);
    (path, root)
}

/// Identifier exported so CLI/integrations can reference the same program by name.
pub const ATTESTATION_PROGRAM_ID_WORDS: [u32; 8] = ATTESTATION_ID;

/// Helper for integrations that don't yet have a sequencer-backed Merkle proof:
/// builds a complete `ProveRequest` against a synthesized account + path of the given depth.
pub struct DemoFixture {
    pub npk: [u8; 32],
    pub identifier: u128,
    pub program_owner: [u32; 8],
    pub balance: u128,
    pub nonce: u128,
    pub data_seed: &'static [u8],
    pub leaf_index: u64,
    pub tree_depth: usize,
    pub threshold: u128,
    pub context_id: [u8; 32],
    pub presenter_pubkey: [u8; 33],
}

impl DemoFixture {
    pub fn into_request(self) -> ProveRequest {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.data_seed);
        let data_hash: [u8; 32] = h.finalize().into();

        let mut req = ProveRequest {
            npk: self.npk,
            identifier: self.identifier,
            program_owner: self.program_owner,
            balance: self.balance,
            nonce: self.nonce,
            data_hash,
            merkle_path: vec![],
            leaf_index: self.leaf_index,
            merkle_root: [0u8; 32],
            threshold: self.threshold,
            context_id: self.context_id,
            presenter_pubkey: self.presenter_pubkey,
        };
        let (_commit, leaf_hash) = precompute_leaf(&req);
        let (path, root) = synthetic_merkle_path(&leaf_hash, req.leaf_index, self.tree_depth);
        req.merkle_path = path;
        req.merkle_root = root;
        req
    }
}

#[cfg(test)]
mod sdk_tests {
    use super::*;

    fn synthetic_request(presenter_pubkey: [u8; 33]) -> ProveRequest {
        ProveRequest {
            npk: [0x33u8; 32],
            identifier: 42,
            program_owner: [0x11_22_33_44u32; 8],
            balance: 1_000_000,
            nonce: 7,
            data_hash: [0u8; 32],
            merkle_path: vec![],
            leaf_index: 3,
            merkle_root: [0u8; 32],
            threshold: 100_000,
            context_id: [0xaau8; 32],
            presenter_pubkey,
        }
    }

    #[test]
    fn presenter_key_from_bytes_roundtrip() {
        let bytes = [0x42u8; 32];
        let k1 = PresenterKey::from_bytes(&bytes).unwrap();
        let k2 = PresenterKey::from_bytes(&bytes).unwrap();
        assert_eq!(k1.public(), k2.public());
    }

    #[test]
    fn presenter_key_public_is_33_bytes() {
        let k = PresenterKey::generate();
        assert_eq!(k.public().len(), 33);
    }

    #[test]
    fn precompute_leaf_is_deterministic() {
        let pk = PresenterKey::generate();
        let r1 = synthetic_request(pk.public());
        let r2 = synthetic_request(pk.public());
        let (commit_a, leaf_a) = precompute_leaf(&r1);
        let (commit_b, leaf_b) = precompute_leaf(&r2);
        assert_eq!(commit_a, commit_b);
        assert_eq!(leaf_a, leaf_b);
    }

    #[test]
    fn precompute_leaf_changes_with_balance() {
        let pk = PresenterKey::generate();
        let mut r1 = synthetic_request(pk.public());
        let (commit_a, _) = precompute_leaf(&r1);
        r1.balance += 1;
        let (commit_b, _) = precompute_leaf(&r1);
        assert_ne!(commit_a, commit_b);
    }

    #[test]
    fn precompute_leaf_changes_with_npk() {
        let pk = PresenterKey::generate();
        let mut r1 = synthetic_request(pk.public());
        let (commit_a, _) = precompute_leaf(&r1);
        r1.npk[0] ^= 0xff;
        let (commit_b, _) = precompute_leaf(&r1);
        assert_ne!(commit_a, commit_b);
    }

    #[test]
    fn synthetic_merkle_path_yields_consistent_root() {
        let leaf = [0xaau8; 32];
        let (path1, root1) = synthetic_merkle_path(&leaf, 0, 10);
        let (path2, root2) = synthetic_merkle_path(&leaf, 0, 10);
        assert_eq!(path1, path2);
        assert_eq!(root1, root2);
        assert_eq!(path1.len(), 10);
    }

    #[test]
    fn synthetic_merkle_path_changes_with_leaf_index() {
        let leaf = [0xaau8; 32];
        let (_, root_at_0) = synthetic_merkle_path(&leaf, 0, 10);
        let (_, root_at_5) = synthetic_merkle_path(&leaf, 5, 10);
        assert_ne!(root_at_0, root_at_5);
    }

    #[test]
    fn presenter_key_sign_is_signature_aware_of_journal() {
        let pk = PresenterKey::generate();
        let nonce = [0u8; 32];
        let journal_a = PublicJournal {
            merkle_root: [0u8; 32],
            threshold: 100,
            context_id: [0u8; 32],
            presenter_pubkey: pk.public(),
            nullifier: [0u8; 32],
        };
        let mut journal_b = journal_a.clone();
        journal_b.threshold = 200;
        let sig_a = pk.sign(&nonce, &journal_a);
        let sig_b = pk.sign(&nonce, &journal_b);
        // ECDSA signatures are randomised by default but the digest is different,
        // so signatures will diverge — and the verifier checks digest equality.
        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn receipt_kind_default_is_composite() {
        assert_eq!(ReceiptKind::default(), ReceiptKind::Composite);
    }
}
