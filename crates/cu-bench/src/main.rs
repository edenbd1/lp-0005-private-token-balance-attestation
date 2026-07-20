//! Measures the **on-chain** compute-unit cost of an LP-0005 instruction.
//!
//! The prize asks for "the compute unit (CU) cost of each on-chain operation on
//! LEZ devnet/testnet". The LEZ sequencer exposes no per-transaction cycle
//! telemetry (there is no such field on `getTransaction`, and neither the
//! sequencer nor the indexer RPC surfaces one), so the cost cannot simply be
//! read back off the chain.
//!
//! What this tool does instead is replay the sequencer's own execution, byte for
//! byte. `lee::state_machine::Program::execute` (LEZ `v0.2.0`,
//! `lee/state_machine/src/program.rs:55-86`) does exactly this:
//!
//! ```text
//! let mut env_builder = ExecutorEnv::builder();
//! env_builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION)); // 32M
//! Program::write_inputs(id, caller_program_id, pre_states, instruction_data, &mut env_builder);
//! let executor = default_executor();
//! let session_info = executor.execute(env, self.elf())?;
//! ```
//!
//! We reproduce that with the same ELF, the same four inputs in the same order,
//! the same session limit and the same executor, then report the cycle counts
//! the run actually consumed. The account pre-state is fetched live from the
//! sequencer so the inputs match what the chain really held.
//!
//! The result is therefore a measurement of the real on-chain work, not an
//! estimate: it is the identical computation the sequencer performs when it
//! includes the transaction in a block.

use anyhow::{bail, Context, Result};
use clap::Parser;
use lee_core::account::{Account, AccountId, AccountWithMetadata, Nonce};
use lee_core::program::ProgramId;
use risc0_zkvm::{default_executor, ExecutorEnv};
use serde::Deserialize;

/// Matches `MAX_NUM_CYCLES_PUBLIC_EXECUTION` in `lee/state_machine/src/program.rs:15`.
const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32;

#[derive(Parser)]
#[command(about = "Replay the LEZ sequencer's execution of a program and report its cycle cost")]
struct Args {
    /// Program binary, as deployed (the same file passed to `wallet deploy-program`).
    #[arg(long)]
    elf: String,

    /// `spel --dry-run=json` output for the instruction to measure.
    #[arg(long)]
    tx: String,

    /// Sequencer JSON-RPC endpoint used to fetch the account pre-states.
    #[arg(long, default_value = "https://testnet.lez.logos.co")]
    sequencer: String,

    /// Emit machine-readable JSON instead of a table.
    #[arg(long)]
    json: bool,
}

/// The subset of `spel --dry-run=json` we consume.
#[derive(Deserialize)]
struct DryRun {
    instruction: String,
    instruction_data: String,
    accounts: Vec<DryRunAccount>,
}

#[derive(Deserialize)]
struct DryRunAccount {
    id: String,
    #[serde(default)]
    flags: Vec<String>,
}

/// `getAccount` result shape.
#[derive(Deserialize)]
struct RpcAccount {
    program_owner: [u32; 8],
    balance: u128,
    #[serde(default)]
    data: Vec<u8>,
    nonce: u128,
}

/// `instruction_data` arrives as a flat hex string of little-endian u32 words.
fn decode_instruction_data(hex_str: &str) -> Result<Vec<u32>> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .context("instruction_data is not valid hex")?;
    if bytes.len() % 4 != 0 {
        bail!(
            "instruction_data length {} is not a multiple of 4 bytes",
            bytes.len()
        );
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// A dry-run account id is `0x`-prefixed hex over the raw 32-byte account id.
fn parse_account_id(raw: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(raw.trim_start_matches("0x")).context("account id is not valid hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("account id is {} bytes, expected 32", bytes.len()))?;
    Ok(arr)
}

fn fetch_account(sequencer: &str, account_id: &[u8; 32]) -> Result<RpcAccount> {
    let id_b58 = bs58_encode(account_id);
    let body = ureq::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccount",
        "params": [id_b58],
    });
    let resp: serde_json::Value = ureq::post(sequencer)
        .send_json(body)
        .context("getAccount request failed")?
        .into_json()
        .context("getAccount response was not JSON")?;

    let result = resp
        .get("result")
        .filter(|v| !v.is_null())
        .with_context(|| format!("account {id_b58} not found on {sequencer}"))?;
    serde_json::from_value(result.clone()).context("unexpected getAccount result shape")
}

/// Minimal base58 (Bitcoin alphabet), matching the encoding LEZ uses for account ids.
fn bs58_encode(input: &[u8; 32]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::with_capacity(45);
    for &byte in input {
        let mut carry = byte as usize;
        for digit in digits.iter_mut() {
            carry += (*digit as usize) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat_n('1', leading_zeros));
    out.extend(digits.iter().rev().map(|&d| ALPHABET[d as usize] as char));
    out
}

fn main() -> Result<()> {
    let args = Args::parse();

    let elf = std::fs::read(&args.elf).with_context(|| format!("cannot read ELF {}", args.elf))?;
    let dry_run: DryRun = serde_json::from_str(
        &std::fs::read_to_string(&args.tx).with_context(|| format!("cannot read {}", args.tx))?,
    )
    .context("dry-run file is not the JSON emitted by `spel --dry-run=json`")?;

    // Derive the ProgramId the way the sequencer does: `Program::new` decodes the
    // deployed binary and takes its image id (lee/state_machine/src/program.rs:24-32).
    let program_id: ProgramId = risc0_binfmt::ProgramBinary::decode(&elf)
        .context("deployed binary is not a valid risc0 ProgramBinary")?
        .compute_image_id()
        .context("cannot compute image id")?
        .into();

    let instruction_data = decode_instruction_data(&dry_run.instruction_data)?;

    // Rebuild the pre-states from live chain state so the inputs match what the
    // sequencer actually had in front of it.
    let mut pre_states = Vec::with_capacity(dry_run.accounts.len());
    for acc in &dry_run.accounts {
        let raw_id = parse_account_id(&acc.id)?;
        let fetched = fetch_account(&args.sequencer, &raw_id)?;
        let account = Account {
            program_owner: fetched.program_owner,
            balance: fetched.balance,
            data: fetched
                .data
                .try_into()
                .map_err(|e| anyhow::anyhow!("account data rejected by LEZ: {e}"))?,
            nonce: Nonce(fetched.nonce),
        };
        let is_authorized = acc.flags.iter().any(|f| f == "signer");
        pre_states.push(AccountWithMetadata::new(
            account,
            is_authorized,
            AccountId::new(raw_id),
        ));
    }

    // Exactly `Program::write_inputs`: program_id, caller_program_id, pre_states,
    // instruction_data, in that order (lee/state_machine/src/program.rs:89-110).
    // A top-level instruction has no caller.
    let caller_program_id: Option<ProgramId> = None;

    let mut env_builder = ExecutorEnv::builder();
    env_builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
    env_builder.write(&program_id)?;
    env_builder.write(&caller_program_id)?;
    env_builder.write(&pre_states)?;
    env_builder.write(&instruction_data)?;
    let env = env_builder.build()?;

    let session = default_executor()
        .execute(env, &elf)
        .context("execution failed, the sequencer would have rejected this transaction")?;

    let user_cycles: u64 = session.segments.iter().map(|s| u64::from(s.cycles)).sum();
    let proving_cycles: u64 = session.segments.iter().map(|s| 1u64 << s.po2).sum();
    let budget_pct = (proving_cycles as f64 / MAX_NUM_CYCLES_PUBLIC_EXECUTION as f64) * 100.0;

    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "instruction": dry_run.instruction,
                "program_id_hex": hex::encode(
                    program_id.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>()
                ),
                "user_cycles": user_cycles,
                "proving_cycles": proving_cycles,
                "segments": session.segments.len(),
                "instruction_data_words": instruction_data.len(),
                "pre_states": pre_states.len(),
                "public_execution_limit": MAX_NUM_CYCLES_PUBLIC_EXECUTION,
                "budget_used_pct": (budget_pct * 1000.0).round() / 1000.0,
            })
        );
    } else {
        println!("instruction            {}", dry_run.instruction);
        println!("pre-state accounts     {}", pre_states.len());
        println!("instruction data       {} u32 words", instruction_data.len());
        println!("segments               {}", session.segments.len());
        println!("user cycles            {user_cycles}");
        println!("proving cycles (po2)   {proving_cycles}");
        println!(
            "public budget          {MAX_NUM_CYCLES_PUBLIC_EXECUTION} cycles ({budget_pct:.3}% used)"
        );
    }

    Ok(())
}
