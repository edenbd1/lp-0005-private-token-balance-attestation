//! `attest` CLI for LP-0005.
//!
//!   attest keygen --out presenter.key
//!   attest prove  --presenter presenter.key --balance 1000000 --threshold 100000 \
//!                 --context "gov-v1" --out credential.bin
//!   attest verify --credential credential.bin --presenter presenter.key --context "gov-v1" --threshold 100000

use anyhow::{Context, Result};
use attestation_sdk::{precompute_leaf, prove, synthetic_merkle_path, PresenterKey, ProveRequest};
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
    /// Prover-side: sign a verifier-supplied challenge with the presenter key.
    /// Outputs the DER-encoded signature as hex on stdout.
    SignChallenge {
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        presenter: PathBuf,
        /// Hex-encoded 32-byte nonce produced by the verifier.
        #[arg(long)]
        nonce: String,
    },
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
    ///
    /// In a real challenge-response, `--nonce` and `--signature` come from the
    /// presenter after the verifier publishes its challenge. For self-contained
    /// demos (and CI), omit them and the CLI loads the presenter key locally to
    /// simulate the round-trip.
    Verify {
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        context: String,
        #[arg(long)]
        threshold: u128,
        /// Optional verifier-drawn nonce (hex). If omitted, a fresh one is drawn.
        #[arg(long)]
        nonce: Option<String>,
        /// Hex DER signature returned by the presenter for `--nonce`.
        #[arg(long)]
        signature: Option<String>,
        /// Self-contained mode: load the presenter key and sign in-process.
        /// Ignored if both `--nonce` and `--signature` are supplied.
        #[arg(long)]
        presenter: Option<PathBuf>,
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
            println!(
                "wrote credential ({} bytes) to {}",
                bytes.len(),
                out.display()
            );
            println!("nullifier: 0x{}", hex::encode(proof.journal.nullifier));
        }
        Cmd::Journal { credential } => {
            let bytes = std::fs::read(&credential)?;
            let (receipt, _): (Receipt, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
            let journal = attestation_verifier_offchain::verify_receipt(&receipt)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "merkle_root":      hex::encode(journal.merkle_root),
                    "threshold":        journal.threshold,
                    "context_id":       hex::encode(journal.context_id),
                    "presenter_pubkey": hex::encode(journal.presenter_pubkey),
                    "nullifier":        hex::encode(journal.nullifier),
                }))?
            );
        }
        Cmd::SignChallenge {
            credential,
            presenter,
            nonce,
        } => {
            let pk = load_presenter(&presenter)?;
            let bytes = std::fs::read(&credential)?;
            let (receipt, _): (Receipt, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
            // Prover decodes their own journal without re-verifying the receipt:
            // re-verifying in this process would refuse DEV_MODE receipts that the prover
            // just generated, and would duplicate work that the verifier will do anyway.
            let journal: attestation_core::PublicJournal = receipt
                .journal
                .decode()
                .context("could not decode journal from credential")?;
            let nonce_bytes = parse_nonce(&nonce)?;
            let signature = pk.sign(&nonce_bytes, &journal);
            println!("{}", hex::encode(signature));
        }
        Cmd::Verify {
            credential,
            context,
            threshold,
            nonce,
            signature,
            presenter,
        } => {
            let bytes = std::fs::read(&credential)?;
            let (receipt, _): (Receipt, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;

            // Resolve (nonce, signature):
            //   external mode: --nonce + --signature passed in by the caller
            //   self-contained mode: load --presenter, draw a fresh nonce, sign locally
            let (nonce_bytes, sig_bytes) = match (nonce, signature, presenter) {
                (Some(n_hex), Some(s_hex), _) => {
                    let n = parse_nonce(&n_hex)?;
                    let s = hex::decode(s_hex.trim()).context("--signature is not valid hex")?;
                    (n, s)
                }
                (None, None, Some(presenter_path)) => {
                    let pk = load_presenter(&presenter_path)?;
                    let mut n = [0u8; 32];
                    rand::Rng::fill(&mut rand::thread_rng(), &mut n);
                    let journal = attestation_verifier_offchain::verify_receipt(&receipt)?;
                    let s = pk.sign(&n, &journal);
                    (n, s)
                }
                _ => anyhow::bail!(
                    "supply either (--nonce + --signature) for external challenge-response, \
                     or --presenter for the self-contained demo mode"
                ),
            };

            let expected_context = context_id_from(&context);
            let journal = verify_credential(
                &receipt,
                &nonce_bytes,
                &sig_bytes,
                &expected_context,
                threshold,
            )?;
            println!("verified.");
            println!("threshold attested: {}", journal.threshold);
            println!("context_id:         0x{}", hex::encode(journal.context_id));
            println!("nullifier:          0x{}", hex::encode(journal.nullifier));
        }
    }
    Ok(())
}

fn load_presenter(path: &PathBuf) -> Result<PresenterKey> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let hex_sk = v["secret_hex"].as_str().context("missing secret_hex")?;
    let bytes = hex::decode(hex_sk)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad sk length"))?;
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

fn parse_nonce(hex_in: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_in.trim()).context("nonce is not valid hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be exactly 32 bytes"))
}
