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
    compute_commitment, compute_nullifier, derive_account_id, fold_merkle_path,
    PrivateInputs, PublicJournal,
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
        let sig: Signature = self.0.sign(&digest);
        sig.to_der().as_bytes().to_vec()
    }
}

/// A complete attestation: the Risc0 receipt and the decoded journal.
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

/// Generate a fresh attestation credential.
pub fn prove(req: ProveRequest) -> Result<AttestationProof> {
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

    let prover = default_prover();
    let prove_info = prover.prove_with_opts(env, ATTESTATION_ELF, &ProverOpts::default())?;
    let receipt = prove_info.receipt;
    let journal: PublicJournal = receipt.journal.decode()?;
    Ok(AttestationProof { receipt, journal })
}

/// Re-export so SDK users get a single dependency.
pub use attestation_verifier_offchain::{verify_credential, VerifyError, ATTESTATION_ID as PROGRAM_ID};

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
pub fn synthetic_merkle_path(leaf_hash: &[u8; 32], leaf_index: u64, depth: usize) -> (Vec<[u8; 32]>, [u8; 32]) {
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
