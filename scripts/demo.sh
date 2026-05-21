#!/usr/bin/env bash
# End-to-end LP-0005 demo: keygen → prove → verify.
#
# Runs entirely off-chain (no LEZ sequencer required for this script).
# RISC0_DEV_MODE defaults to 0 (real STARK). Set =1 for fast iteration without a proof.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${RISC0_DEV_MODE:=0}"
export RISC0_DEV_MODE

ARTIFACTS="$ROOT/artifacts/demo"
mkdir -p "$ARTIFACTS"

CTX="lp-0005-demo-context-2026"

echo "=== LP-0005 end-to-end demo (RISC0_DEV_MODE=$RISC0_DEV_MODE) ==="
echo

echo "[1/4] building..."
cargo build --release -p attestation-cli --bin attest 1>/dev/null

ATTEST="$ROOT/target/release/attest"

echo "[2/4] keygen..."
"$ATTEST" keygen --out "$ARTIFACTS/presenter.json"

echo
echo "[3/4] prove: balance=1000000, threshold=100000, context='$CTX'..."
"$ATTEST" prove \
  --presenter "$ARTIFACTS/presenter.json" \
  --balance   1000000 \
  --threshold 100000 \
  --context   "$CTX" \
  --out       "$ARTIFACTS/credential.bin"

echo
echo "[4/4] verify..."
"$ATTEST" verify \
  --credential "$ARTIFACTS/credential.bin" \
  --presenter  "$ARTIFACTS/presenter.json" \
  --context    "$CTX" \
  --threshold  100000

echo
echo "=== Demo complete. Artifacts in $ARTIFACTS ==="
