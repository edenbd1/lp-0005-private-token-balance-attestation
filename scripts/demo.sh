#!/usr/bin/env bash
# End-to-end LP-0005 demo: keygen → prove → verify.
#
# Modes:
#   SEQUENCER_URL unset (default) — uses synthesized account state, suitable for
#     evaluators who do not have a Logos workspace yet. Exercises the same prove
#     / verify code paths as the real flow.
#   SEQUENCER_URL=http://127.0.0.1:3040 — drives the SDK against a real local
#     sequencer (requires the sequencer-client transport to be wired, tracked in
#     docs/sequencer-client-plan.md). Will produce a credential against an actual
#     Merkle root the sequencer attested to.
#
# RISC0_DEV_MODE defaults to 0 (real STARK proving). Set =1 to skip proof
# generation for fast iteration.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${RISC0_DEV_MODE:=0}"
: "${SEQUENCER_URL:=}"
export RISC0_DEV_MODE

ARTIFACTS="$ROOT/artifacts/demo"
mkdir -p "$ARTIFACTS"

CTX="lp-0005-demo-context-2026"

echo "=== LP-0005 end-to-end demo ==="
echo "RISC0_DEV_MODE=$RISC0_DEV_MODE"
if [[ -n "$SEQUENCER_URL" ]]; then
    echo "Mode: against local sequencer at $SEQUENCER_URL"
    echo "NOTE: sequencer-backed mode is still wiring up (see"
    echo "      docs/sequencer-client-plan.md). Falling back to synthesized mode."
else
    echo "Mode: synthesized account state (no sequencer)"
fi
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
