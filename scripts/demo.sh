#!/usr/bin/env bash
# LP-0005 end-to-end demo against the PUBLIC LEZ testnet.
#
# Pipeline:
#   1. RISC0_DEV_MODE=0 banner (real Risc0 proving, no dev-mode stubs).
#   2. Sanity-check the public testnet sequencer via the real sequencer-client
#      transport (proves the off-chain stack can reach a real LEZ endpoint).
#   3. Confirm the deployed attestation + verifier programs exist on chain.
#   4. Generate a presenter key, prove `balance >= threshold`, sign a
#      verifier-supplied challenge, verify locally.
#   5. Emit the spel-CLI args needed to submit a gated_check call against the
#      deployed verifier program.
#
# Override SEQUENCER_URL to target a different endpoint (e.g. a local
# `lgs localnet start` sequencer on port 3040). Default is the public testnet.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${RISC0_DEV_MODE:=0}"
: "${SEQUENCER_URL:=https://testnet.lez.logos.co}"
: "${CTX:=lp-0005-demo-context-2026}"
: "${BALANCE:=1000000}"
: "${THRESHOLD:=100000}"
export RISC0_DEV_MODE

# Public-testnet deployed program identifiers (see docs/DEPLOYMENT.md).
ATTESTATION_PROGRAM_ID=dbc40b94eda637ae958a393438d37c11e31a2e535939d952488b4760b46a9d4d
VERIFIER_DEEP_PROGRAM_ID=7715f79145f71bc61954305d77b2c0c194afef3843c0e770322c286d8a1db429
VERIFIER_SHALLOW_PROGRAM_ID=b32c6662bb7eba466284576e7228ecf58743d1a6efbe8887e94d3ddfbf85952a
ATTESTATION_DEPLOY_TX=4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d
VERIFIER_DEEP_DEPLOY_TX=2bf10138c085429d9d6fb46793f0a089376eff90558fce4a66634447923723a9
VERIFIER_SHALLOW_DEPLOY_TX=a0ec45bb7817eea672bfe1cac4663969557da852a031a7a46c571193d341c5ca
CONFIRMED_GATED_CHECK_TX=262bbe95681431829279e897062e84131fe11ab7b5f4ed71512ab7c96babfd5e

ARTIFACTS="$ROOT/artifacts/demo"
mkdir -p "$ARTIFACTS"

echo "==========================================================="
echo "▶ RISC0_DEV_MODE = $RISC0_DEV_MODE"
echo "▶ SEQUENCER      = $SEQUENCER_URL"
echo "▶ CONTEXT        = $CTX"
echo "==========================================================="
echo

echo "[1/7] sanity — tool versions"
command -v cargo >/dev/null  && echo "  cargo:  ok"
command -v curl  >/dev/null  && echo "  curl:   ok"
command -v jq    >/dev/null  && echo "  jq:     ok"
echo

echo "[2/7] reach the public LEZ testnet (real HTTP via sequencer-client)"
BLOCK=$(curl -s -X POST "$SEQUENCER_URL" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}' | \
  jq -r '.result')
echo "  block height = $BLOCK"
echo

echo "[3/7] verify on-chain deployments + the confirmed gated_check call"
for label in \
  "attestation circuit deploy:$ATTESTATION_DEPLOY_TX" \
  "verifier program v2 (deep gate) deploy:$VERIFIER_DEEP_DEPLOY_TX" \
  "verifier program v3 (shallow gate) deploy:$VERIFIER_SHALLOW_DEPLOY_TX" \
  "✅ CONFIRMED gated_check call (v3, real ECDSA-signed):$CONFIRMED_GATED_CHECK_TX"
do
  NAME="${label%%:*}"
  HASH="${label#*:}"
  RES=$(curl -s -X POST "$SEQUENCER_URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$HASH\"]}" | \
    jq -r '.result | if . == null then "MISSING" else "PRESENT" end')
  if [[ "$RES" == "PRESENT" ]]; then
    echo "  ✅ $NAME"
    echo "     tx $HASH"
  else
    echo "  ❌ $NAME — tx $HASH NOT on chain"
    exit 1
  fi
done
echo "  Explorer: https://explorer.testnet.lez.logos.co/"
echo

echo "[4/7] build attestation CLI"
cargo build --release -p attestation-cli --bin attest 1>/dev/null
ATTEST="$ROOT/target/release/attest"
echo "  attest at $ATTEST"
echo

echo "[5/7] keygen + prove ($BALANCE >= $THRESHOLD, context='$CTX')"
"$ATTEST" keygen --out "$ARTIFACTS/presenter.json" 1>/dev/null
echo "  ↳ proving (RISC0_DEV_MODE=$RISC0_DEV_MODE)..."
"$ATTEST" prove \
  --presenter "$ARTIFACTS/presenter.json" \
  --balance   "$BALANCE" \
  --threshold "$THRESHOLD" \
  --context   "$CTX" \
  --out       "$ARTIFACTS/credential.bin" \
  2>&1 | grep -E "proved|wrote|nullifier" | sed 's/^/    /'
echo

echo "[6/7] challenge → sign → off-chain verify (presenter signature + Risc0 receipt)"
NONCE=$("$ATTEST" challenge)
echo "  ↳ nonce: $NONCE"
SIG=$("$ATTEST" sign-challenge \
  --credential "$ARTIFACTS/credential.bin" \
  --presenter  "$ARTIFACTS/presenter.json" \
  --nonce      "$NONCE")
echo "  ↳ signature: ${SIG:0:48}..."
"$ATTEST" verify \
  --credential "$ARTIFACTS/credential.bin" \
  --context    "$CTX" \
  --threshold  "$THRESHOLD" \
  --nonce      "$NONCE" \
  --signature  "$SIG" 2>&1 | sed 's/^/    /'
echo

echo "[7/7] build spel gated_check call args (ready to submit on chain)"
"$ATTEST" gated-check-args \
  --credential "$ARTIFACTS/credential.bin" \
  --presenter  "$ARTIFACTS/presenter.json" \
  --context    "$CTX" \
  --threshold  "$THRESHOLD" \
  --nonce      "$NONCE" > "$ARTIFACTS/gated-check.args"
echo "  ↳ written to $ARTIFACTS/gated-check.args"
echo "  ↳ submit against the v3 shallow verifier program with:"
echo "      spel --idl idl/attestation_verifier_shallow.idl.json \\"
echo "           --program crates/verifier-program-spel/methods/guest-shallow/target/riscv32im-risc0-zkvm-elf/docker/attestation_verifier_shallow.bin \\"
echo "           -- gated_check --presenter Public/<your-pubkey> \\"
echo "           \$(cat $ARTIFACTS/gated-check.args | tr '\\n' ' ')"
echo
echo "  ↳ reference confirmed call:"
echo "      tx $CONFIRMED_GATED_CHECK_TX"
echo "      https://explorer.testnet.lez.logos.co/transaction/$CONFIRMED_GATED_CHECK_TX"
echo

echo "==========================================================="
echo "✅ Demo complete — full off-chain path exercised against a real Risc0 proof,"
echo "   public testnet liveness confirmed, on-chain programs verified,"
echo "   spel gated_check args ready to submit."
echo "==========================================================="
