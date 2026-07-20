#!/usr/bin/env bash
# LP-0005 end-to-end test against a REAL LOCAL LEZ sequencer in standalone mode.
#
# This is the test the prize asks for twice over:
#   "End-to-end integration tests run against a LEZ sequencer (standalone mode)
#    and are included in CI."
#   "A reproducible end-to-end demo script is provided and works against a real
#    local sequencer with RISC0_DEV_MODE=0."
#
# Unlike scripts/demo.sh, which checks already-deployed transactions on the
# public testnet, this script exercises the pipeline from an empty chain:
#
#   1. boot a standalone sequencer on a throwaway data dir
#   2. initialise the genesis signer account
#   3. deploy three programs and wait for each to land
#   4. generate a REAL Risc0 attestation proof (RISC0_DEV_MODE=0)
#   5. draw a challenge, sign it, verify off-chain
#   6. submit gated_check on chain and require it to CONFIRM
#
# Every step must succeed or the script exits non-zero.
#
# SCOPE — READ THIS BEFORE CITING THE SCRIPT AS EVIDENCE.
#
# The gated_check submitted at step 6 is against the SHALLOW gate, on a public
# transaction. The shallow gate verifies no zero-knowledge proof, and no program
# on the public path could: a LEZ public transaction re-executes host-side rather
# than proving (lee/state_machine/src/program.rs:73-77). So this script proves
# that deployment, proving, signing, submission and confirmation all work against
# a real sequencer. It does NOT exercise the deep gate, and it is not evidence
# that the proof is verified on chain.
#
# The deep gate is covered in two other places, deliberately not here, because a
# privacy-preserving submission needs twenty-plus minutes of proving:
#
#   * crates/cu-bench/tests/deep_gate_rejects.rs runs the DEPLOYED deep binary
#     through the sequencer's own execution path and requires each of
#     3009/3010/3011/3012 to fire on the corresponding forged input, with the
#     honest call accepted as the control. This runs in CI on every push.
#   * scripts/verify-onchain-proof.sh checks the real privacy-preserving
#     gated_check on the public testnet from public data alone.
#
# Required in PATH or via env:
#   SEQUENCER_BIN  sequencer_service built with --features standalone
#   SEQUENCER_CFG  path to sequencer_config.json (its "genesis" funds the signer)
#   WALLET_BIN     wallet binary from the same LEZ tag
#   SPEL_BIN       spel >= 0.6.0
#
# Build them with:
#   git clone https://github.com/logos-blockchain/logos-execution-zone && cd logos-execution-zone
#   git checkout v0.2.0
#   cargo build --release --features standalone -p sequencer_service
#   cargo build --release -p wallet
#   cargo install --git https://github.com/logos-co/spel --tag v0.6.0

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${RISC0_DEV_MODE:=0}"
export RISC0_DEV_MODE

: "${SEQUENCER_BIN:?set SEQUENCER_BIN to the standalone sequencer_service binary}"
: "${SEQUENCER_CFG:?set SEQUENCER_CFG to the sequencer config json}"
: "${WALLET_BIN:?set WALLET_BIN to the wallet binary}"
: "${SPEL_BIN:=spel}"

# Genesis signer from the LEZ debug config. This key is a public test key
# committed in the LEZ repo's Justfile; it is not a secret.
SIGNER=CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r
SIGNER_KEY=7f273098f25b71e6c005a9519f2678da8d1c7f01f6a27778e2d9948abdf901fb

RPC=http://127.0.0.1:3040
CTX=lp-0005-e2e-local
BALANCE=1000000
THRESHOLD=100000

WORK="$(mktemp -d)"
export LEE_WALLET_HOME_DIR="$WORK/wallet"
mkdir -p "$LEE_WALLET_HOME_DIR" "$WORK/chain"
ART="$ROOT/artifacts/e2e-local"
mkdir -p "$ART"

SEQ_PID=""
cleanup() {
  if [[ -n "$SEQ_PID" ]] && kill -0 "$SEQ_PID" 2>/dev/null; then
    kill "$SEQ_PID" 2>/dev/null || true
    wait "$SEQ_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

rpc() {
  curl -s -m 20 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# tx_hash of a program deployment is SHA256(borsh(bytecode)), i.e. the u32-LE
# length prefix followed by the bytes. Content addressed, so it can be computed
# offline and does not depend on who submitted it.
deploy_tx_hash() {
  python3 -c "
import hashlib,struct,sys
b=open(sys.argv[1],'rb').read()
print(hashlib.sha256(struct.pack('<I',len(b))+b).hexdigest())" "$1"
}

wait_for_tx() {
  local hash="$1" name="$2" tries=40
  for _ in $(seq 1 $tries); do
    if [[ "$(rpc getTransaction "[\"$hash\"]" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("result") is not None)')" == "True" ]]; then
      echo "  ✅ $name landed  ($hash)"
      return 0
    fi
    sleep 5
  done
  echo "  ❌ $name never landed after $((tries * 5))s  ($hash)" >&2
  return 1
}

echo "==========================================================="
echo "▶ LP-0005 end-to-end against a LOCAL standalone sequencer"
echo "▶ RISC0_DEV_MODE = $RISC0_DEV_MODE"
echo "==========================================================="
echo

echo "[1/7] boot the standalone sequencer"
( cd "$WORK/chain" && RUST_LOG=warn "$SEQUENCER_BIN" "$SEQUENCER_CFG" > "$WORK/sequencer.log" 2>&1 ) &
SEQ_PID=$!
for i in $(seq 1 60); do
  if rpc getLastBlockId '[]' 2>/dev/null | grep -q '"result"'; then
    echo "  sequencer up after ${i}s, height $(rpc getLastBlockId '[]' | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"])')"
    break
  fi
  if ! kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "  ❌ sequencer died on startup:" >&2; tail -30 "$WORK/sequencer.log" >&2; exit 1
  fi
  sleep 1
  [[ $i -eq 60 ]] && { echo "  ❌ sequencer did not answer within 60s" >&2; tail -30 "$WORK/sequencer.log" >&2; exit 1; }
done
echo

echo "[2/7] initialise the genesis signer account"
"$WALLET_BIN" config set sequencer_addr "$RPC" >/dev/null 2>&1
"$WALLET_BIN" account import public --private-key "$SIGNER_KEY" >/dev/null 2>&1
"$WALLET_BIN" check-health
"$WALLET_BIN" auth-transfer init --account-id "Public/$SIGNER" >/dev/null 2>&1
echo "  signer Public/$SIGNER initialised"
echo

echo "[3/7] deploy the three programs"
# Prefer the committed binaries under artifacts/programs/. They are the exact
# bytes deployed on the public testnet, so a clean clone can run this script
# without a Docker risc0 rebuild. Fall back to a local build tree if present.
pick_bin() {
  local committed="$1" built="$2"
  if [[ -f "$committed" ]]; then echo "$committed"; else echo "$built"; fi
}
ATT_BIN=$(pick_bin artifacts/programs/attestation.bin \
  target/riscv-guest/attestation-methods/attestation-guest/riscv32im-risc0-zkvm-elf/release/attestation.bin)
V2_BIN=$(pick_bin artifacts/programs/attestation_verifier.bin \
  crates/verifier-program-spel/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier.bin)
V3_BIN=$(pick_bin artifacts/programs/attestation_verifier_shallow.bin \
  crates/verifier-program-spel/methods/guest-shallow/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier_shallow.bin)
for b in "$ATT_BIN" "$V2_BIN" "$V3_BIN"; do
  [[ -f "$b" ]] || { echo "  ❌ missing program binary $b" >&2; exit 1; }
  "$WALLET_BIN" deploy-program "$b" >/dev/null 2>&1
done
wait_for_tx "$(deploy_tx_hash "$ATT_BIN")" "attestation circuit"
wait_for_tx "$(deploy_tx_hash "$V2_BIN")"  "verifier v2 (superseded, not the deep gate)"
wait_for_tx "$(deploy_tx_hash "$V3_BIN")"  "verifier v3 (shallow gate)"
echo

echo "[4/7] build the attestation CLI"
cargo build --release -p attestation-cli --bin attest >/dev/null 2>&1
ATTEST="$ROOT/target/release/attest"
echo "  attest at $ATTEST"
echo

echo "[5/7] generate a REAL Risc0 proof ($BALANCE >= $THRESHOLD)"
"$ATTEST" keygen --out "$ART/presenter.json" >/dev/null
"$ATTEST" prove \
  --presenter "$ART/presenter.json" --balance "$BALANCE" --threshold "$THRESHOLD" \
  --context "$CTX" --out "$ART/credential.bin" 2>&1 | grep -E "proved|wrote" | sed 's/^/  /'
echo

echo "[6/7] challenge, sign, verify off-chain"
NONCE=$("$ATTEST" challenge)
SIG=$("$ATTEST" sign-challenge --credential "$ART/credential.bin" --presenter "$ART/presenter.json" --nonce "$NONCE")
"$ATTEST" verify --credential "$ART/credential.bin" --context "$CTX" \
  --threshold "$THRESHOLD" --nonce "$NONCE" --signature "$SIG" 2>&1 | sed 's/^/  /'
echo

echo "[7/7] submit gated_check on chain and require confirmation"
"$ATTEST" gated-check-args --credential "$ART/credential.bin" --presenter "$ART/presenter.json" \
  --context "$CTX" --threshold "$THRESHOLD" --nonce "$NONCE" > "$ART/gated-check.args"
ARGS=$(tr '\n' ' ' < "$ART/gated-check.args")

# Capture the resolved instruction before submitting it. crates/cu-bench replays
# this against the same binary to report the real on-chain cycle cost.
eval "$SPEL_BIN" --dry-run=json --idl idl/attestation_verifier_shallow.idl.json \
  --program "$V3_BIN" \
  -- gated_check --presenter "Public/$SIGNER" $ARGS > "$ART/dryrun.json" 2>/dev/null || true

OUT="$ART/gated-check.out"
set +e
eval "$SPEL_BIN" --idl idl/attestation_verifier_shallow.idl.json \
  --program "$V3_BIN" \
  -- gated_check --presenter "Public/$SIGNER" $ARGS > "$OUT" 2>&1
SPEL_RC=$?
set -e
grep -v "^    \[" "$OUT" | tail -6 | sed 's/^/  /'
if [[ $SPEL_RC -ne 0 ]] || ! grep -q "Transaction confirmed" "$OUT"; then
  echo "  ❌ gated_check did not confirm on the local sequencer" >&2
  exit 1
fi
GATED_TX=$(grep -o 'tx_hash: [0-9a-f]\{64\}' "$OUT" | head -1 | cut -d' ' -f2)
wait_for_tx "$GATED_TX" "gated_check"
echo

# Measure the CU cost while this chain is still up. The bench fetches the
# account pre-states over RPC, so it has to run against the same sequencer the
# dry-run was captured from; doing it after teardown, or against a different
# chain, would mix state from two chains and report a meaningless number.
echo "[8/8] measure the on-chain CU cost of that gated_check"
if cargo run --release -q -p attestation-cu-bench -- \
     --elf "$V3_BIN" --tx "$ART/dryrun.json" --sequencer "$RPC" --json \
     > "$ART/cu.json" 2>"$ART/cu.err"; then
  python3 -c "
import json
d = json.load(open('$ART/cu.json'))
print(f\"  user cycles          {d['user_cycles']:,}\")
print(f\"  proving cycles       {d['proving_cycles']:,}\")
print(f\"  budget consumed      {d['budget_used_pct']}%\")"
else
  echo "  ❌ CU measurement failed" >&2
  cat "$ART/cu.err" >&2
  exit 1
fi
echo

echo "==========================================================="
echo "✅ End-to-end PASSED against a local standalone LEZ sequencer"
echo "   real Risc0 proof (RISC0_DEV_MODE=$RISC0_DEV_MODE), three programs"
echo "   deployed from an empty chain, gated_check confirmed on chain."
echo "==========================================================="
