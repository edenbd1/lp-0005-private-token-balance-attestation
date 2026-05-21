//! `attest` CLI for LP-0005.
//!
//!   attest keygen --out presenter.key
//!   attest prove  --presenter presenter.key --balance 1000000 --threshold 100000 \
//!                 --context "gov-v1" --out credential.bin
//!   attest verify --credential credential.bin --presenter presenter.key --context "gov-v1" --threshold 100000

use anyhow::{Context, Result};
use attestation_sdk::{prove, precompute_leaf, synthetic_merkle_path, PresenterKey, ProveRequest};
use attestation_verifier_offchain::verify_credential;
use clap::{Parser, Subcommand};
use risc0_zkvm::Receipt;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Instant;

const TREE_DEPTH: usize = 5;

#[derive(Parser)]
#[command(name = "attest", about = "LP-0005 private balance attestation CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a presenter key (secp256k1).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Decode and pretty-print the journal embedded in a credential.
    Journal {
        #[arg(long)]
        credential: PathBuf,
    },
    /// Verifier-side: generate a fresh challenge nonce (32 bytes hex).
    Challenge,
    /// Generate an attestation credential.
    /// Uses synthesized account state — for demos. Real flow consumes a sequencer
    /// `get_proof_for_commitment` response and a wallet-held private account.
    Prove {
        #[arg(long)]
        presenter: PathBuf,
        #[arg(long)]
        balance: u128,
        #[arg(long)]
        threshold: u128,
        #[arg(long)]
        context: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a credential locally (Risc0 + presenter signature).
    Verify {
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        presenter: PathBuf,
        #[arg(long)]
        context: String,
        #[arg(long)]
        threshold: u128,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Challenge => {
            let mut nonce = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
            println!("{}", hex::encode(nonce));
        }
        Cmd::Keygen { out } => {
            // Generate a fresh seed and derive the signing key from it so we can persist
            // a 32-byte secret. A production CLI would AEAD-encrypt under a passphrase.
            let mut bytes = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
            let key = PresenterKey::from_bytes(&bytes)?;
            let payload = serde_json::json!({
                "secret_hex": hex::encode(bytes),
                "public_hex": hex::encode(key.public()),
            });
            std::fs::write(&out, serde_json::to_string_pretty(&payload)?)?;
            println!("wrote presenter key to {}", out.display());
            println!("public:  0x{}", hex::encode(key.public()));
        }
        Cmd::Prove {
            presenter,
            balance,
            threshold,
            context,
            out,
        } => {
            let pk = load_presenter(&presenter)?;
            let context_id = context_id_from(&context);

            // Synthesize an account + Merkle path for the demo.
            let npk = [0x33u8; 32];
            let identifier: u128 = 42;
            let program_owner = [0x11_22_33_44u32; 8];
            let nonce: u128 = 7;
            let data_hash = sha256(b"demo-account-data");

            let mut req = ProveRequest {
                npk,
                identifier,
                program_owner,
                balance,
                nonce,
                data_hash,
                merkle_path: vec![],
                leaf_index: 3,
                merkle_root: [0u8; 32],
                threshold,
                context_id,
                presenter_pubkey: pk.public(),
            };
            let (_commit, leaf_hash) = precompute_leaf(&req);
            let (path, root) = synthetic_merkle_path(&leaf_hash, req.leaf_index, TREE_DEPTH);
            req.merkle_path = path;
            req.merkle_root = root;

            println!("proving...");
            let t = Instant::now();
            let proof = prove(req)?;
            println!("proved in {:?}", t.elapsed());

            let bytes = bincode::serde::encode_to_vec(&proof.receipt, bincode::config::standard())?;
            std::fs::write(&out, &bytes)?;
            println!("wrote credential ({} bytes) to {}", bytes.len(), out.display());
            println!("nullifier: 0x{}", hex::encode(proof.journal.nullifier));
        }
        Cmd::Journal { credential } => {
            let bytes = std::fs::read(&credential)?;
            let (receipt, _): (Receipt, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
            let journal = attestation_verifier_offchain::verify_receipt(&receipt)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "merkle_root":      hex::encode(journal.merkle_root),
                "threshold":        journal.threshold,
                "context_id":       hex::encode(journal.context_id),
                "presenter_pubkey": hex::encode(journal.presenter_pubkey),
                "nullifier":        hex::encode(journal.nullifier),
            }))?);
        }
        Cmd::Verify {
            credential,
            presenter,
            context,
            threshold,
        } => {
            let pk = load_presenter(&presenter)?;
            let bytes = std::fs::read(&credential)?;
            let (receipt, _): (Receipt, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;

            // Simulate the verifier challenge: a fresh nonce per session.
            let mut nonce = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);

            let journal = attestation_verifier_offchain::verify_receipt(&receipt)?;
            let signature = pk.sign(&nonce, &journal);

            let expected_context = context_id_from(&context);
            let journal = verify_credential(&receipt, &nonce, &signature, &expected_context, threshold)?;
            println!("verified.");
            println!("threshold attested: {}", journal.threshold);
            println!("context_id:         0x{}", hex::encode(journal.context_id));
            println!("nullifier:          0x{}", hex::encode(journal.nullifier));
        }
    }
    Ok(())
}

fn load_presenter(path: &PathBuf) -> Result<PresenterKey> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let hex_sk = v["secret_hex"].as_str().context("missing secret_hex")?;
    let bytes = hex::decode(hex_sk)?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("bad sk length"))?;
    PresenterKey::from_bytes(&bytes)
}

fn context_id_from(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"/lp-0005/v0.1/context/");
    h.update(s.as_bytes());
    h.finalize().into()
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}
