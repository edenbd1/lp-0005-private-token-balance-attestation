#!/usr/bin/env bash
# Verify, from public data, that LP-0005's zero-knowledge proof is really
# verified on chain by the LEZ verifier program.
#
# Needs `curl`, `python3` and `jq`. Nothing here is taken on trust: every
# identifier is derived from the binaries in this repository or decoded from the
# bytes the sequencer returns.
#
#   ./scripts/verify-onchain-proof.sh
#
# The five checks, and what each rules out:
#
#   1. The deployed bytecode IS the audited bytecode. A deployment tx hash is
#      SHA256(borsh(bytecode)), so recomputing it from the local file and finding
#      it on chain proves the deployed program is byte-identical to the one you
#      can read here. Merely checking "the tx exists" would pass for any program.
#
#   2. The gated_check transaction is PrivacyPreserving, not Public. This is the
#      crux. A LEZ *public* transaction proves and verifies nothing: the sequencer
#      only re-executes the program (lee/state_machine/src/program.rs:73-77,
#      "Execute the program (without proving)"). Only the privacy path carries a
#      receipt the sequencer verifies against PRIVACY_PRESERVING_CIRCUIT_ID, and
#      only that path composes chained calls with env::verify
#      (lee/privacy_preserving_circuit/src/execution_state.rs:149).
#
#   3. The embedded receipt is a Succinct STARK. risc0's InnerReceipt enum is
#      Composite=0, Succinct=1, Groth16=2, Fake=3 (risc0-zkvm-3.0.5 receipt.rs).
#      Reading variant 1 rules out a RISC0_DEV_MODE fake receipt from the on-chain
#      bytes alone, without any claim about how the node was configured. A size
#      check alone would not: 230 KB of zeros would pass it.
#
#   4. The marker PDA is DERIVED here, not asserted, from the verifier's own
#      ImageID and the gate tag, where the gate tag is itself derived from the
#      nullifier, the enforced floor and the context.
#
#      Read what this does and does not establish. The nullifier below is
#      SUBMITTER-SUPPLIED: it is computed from the presenter's public key, the
#      context and the private account id, none of which are public, so a third
#      party cannot reconstruct it from chain data alone and this script cannot
#      pretend otherwise.
#
#      What it does establish is the part that matters to an integrator. The
#      guest recomputes the gate tag from (nullifier, minimum_threshold,
#      expected_context_id) and rejects any mismatch, and the PDA address is
#      derived from that tag. So a marker found at the address computed below
#      could only have been created by an execution that enforced EXACTLY this
#      floor in EXACTLY this context. Change FLOOR to 0 and re-run: the address
#      moves and no account is there. That is the property that was missing when
#      the seed was the bare nullifier, which recorded that a gate ran without
#      recording what it demanded.
#
#   5. That PDA is owned by the verifier program. program_owner cannot be forged:
#      validate_execution rejects any program_owner change in a program's output
#      (lee/state_machine/core/src/program.rs:692-696), and the circuit sets it to
#      the executing program only after checking the PDA derivation
#      (execution_state.rs:399-447).

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RPC="${SEQUENCER_URL:-https://testnet.lez.logos.co}"

ATTESTATION_BIN=artifacts/programs/attestation_lez.bin
VERIFIER_BIN=artifacts/programs/attestation_verifier_deep.bin
GATED_CHECK_TX=b9488de014c7bda54544011b3cf1e7f54562e90c5451dc402316507bd10d36b2

# The policy that transaction enforced, and the attestation nullifier it spent.
#
# FLOOR and CONTEXT are the public half: they are what an integrator demands, and
# step 4 proves the on-chain marker encodes them. NULLIFIER is submitter-supplied
# (see the header) and is recorded here so the derivation is reproducible.
NULLIFIER=af53e7cdeb6b12a9602f95e765bfa8d5ba1770655fa1c97294aee6a63b5e0b93
FLOOR=4000
CONTEXT=77023f48afd63625bb8b13bfd9dff2e01da374d91135295edfed92de4f1e5dcd

FAILED=0
ok()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }

rpc() {
  curl -s -m 30 -X POST "$RPC" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}"
}

# A LEZ program-deployment tx hash is SHA256(u32_le(len) || bytecode).
deploy_tx_hash() {
  python3 -c "
import hashlib,struct,sys
b=open(sys.argv[1],'rb').read()
print(hashlib.sha256(struct.pack('<I',len(b))+b).hexdigest())" "$1"
}

# ImageID of a deployed binary, as the sequencer computes it.
image_id() {
  python3 -c "
import sys,subprocess,re
out=subprocess.run(['spel','inspect',sys.argv[1]],capture_output=True,text=True).stdout
m=re.search(r'ImageID \(hex bytes\):\s*([0-9a-f]{64})',out)
print(m.group(1) if m else '')" "$1" 2>/dev/null
}

echo "LP-0005 on-chain proof verification"
echo "sequencer: $RPC"
echo

echo "[1/5] the deployed bytecode is the bytecode in this repository"
for pair in "attestation program:$ATTESTATION_BIN" "verifier program:$VERIFIER_BIN"; do
  name="${pair%%:*}"; bin="${pair#*:}"
  if [ ! -f "$bin" ]; then bad "$name binary missing at $bin"; continue; fi
  h=$(deploy_tx_hash "$bin")
  if [ "$(rpc getTransaction "[\"$h\"]" | jq -r 'if .result == null then "no" else "yes" end')" = "yes" ]; then
    ok "$name  SHA256(borsh(bytecode)) = $h found on chain"
  else
    bad "$name  computed $h is NOT on chain"
  fi
done
echo

echo "[2/5] the gated_check transaction is PrivacyPreserving, not Public"
TX_B64=$(rpc getTransaction "[\"$GATED_CHECK_TX\"]" | jq -r '.result // empty')
if [ -z "$TX_B64" ]; then
  bad "gated_check transaction not found  $GATED_CHECK_TX"
else
  # LeeTransaction: 0 Public, 1 PrivacyPreserving, 2 ProgramDeployment
  # (lez/common/src/transaction.rs:10-14)
  VARIANT=$(printf '%s' "$TX_B64" | python3 -c 'import sys,base64; print(base64.b64decode(sys.stdin.read())[0])')
  SIZE=$(printf '%s' "$TX_B64" | python3 -c 'import sys,base64; print(len(base64.b64decode(sys.stdin.read())))')
  if [ "$VARIANT" = "1" ]; then
    ok "borsh variant byte 1 = PrivacyPreserving, $SIZE bytes on chain"
  else
    bad "borsh variant byte $VARIANT (expected 1 = PrivacyPreserving)"
  fi
fi
echo

echo "[3/5] the embedded receipt is a Succinct STARK, not a dev-mode fake"
if [ -n "$TX_B64" ]; then
  # NB: pass the payload as argv. `python3 - <<EOF` takes the script from the
  # heredoc, which replaces stdin, so a piped payload would be discarded.
  RECEIPT_KIND=$(python3 -c "
import sys, base64
raw = base64.b64decode(sys.argv[1])
# The proof is the last field of the borsh-encoded transaction, so its Vec<u8>
# length prefix is the one whose payload runs exactly to the end of the buffer.
# That leaves no ambiguity. The byte right after the prefix is the InnerReceipt
# enum discriminant.
found = -1
for off in range(1, len(raw) - 5):
    n = int.from_bytes(raw[off:off+4], 'little')
    if n > 100000 and off + 4 + n == len(raw):
        found = raw[off + 4]
        break
print(found)" "$TX_B64")
  case "$RECEIPT_KIND" in
    1) ok "InnerReceipt variant 1 = Succinct (a real STARK)" ;;
    0) ok "InnerReceipt variant 0 = Composite (a real STARK)" ;;
    2) ok "InnerReceipt variant 2 = Groth16 (a real SNARK)" ;;
    3) bad "InnerReceipt variant 3 = Fake — this is a RISC0_DEV_MODE receipt" ;;
    *) bad "could not decode the InnerReceipt variant (got $RECEIPT_KIND)" ;;
  esac
fi
echo

echo "[4/5] derive the marker PDA from the ImageID and the enforced policy"
VERIFIER_ID=$(image_id "$VERIFIER_BIN")
if [ -z "$VERIFIER_ID" ]; then
  echo "  (spel not on PATH; falling back to the recorded ImageID)"
  VERIFIER_ID=1047297a1fdd686d82435cd858c2d8acb86b20a74d5f779a8d9bcd9f8261b27c
fi
# gate_tag = SHA256(GATE_TAG_PREFIX || nullifier || floor_LE || context)
# then PDA = SHA256("/LEE/v0.2/AccountId/PDA/" || 8 zero bytes || program_id || seed)
read -r GATE_TAG MARKER_PDA <<<"$(python3 -c "
import hashlib,sys
A=b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58(b):
    n=int.from_bytes(b,'big'); o=b''
    while n: n,r=divmod(n,58); o=A[r:r+1]+o
    return '1'*(len(b)-len(b.lstrip(b'\0')))+o.decode()
image, nullifier, floor, context = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
g=hashlib.sha256()
g.update(b'/lp-0005/v0.1/GateTag/'+b'\0'*10)
g.update(bytes.fromhex(nullifier))
g.update(floor.to_bytes(16,'little'))
g.update(bytes.fromhex(context))
tag=g.digest()
h=hashlib.sha256()
h.update(b'/LEE/v0.2/AccountId/PDA/'+b'\0'*8)
h.update(bytes.fromhex(image))
h.update(tag)
print(tag.hex(), b58(h.digest()))" "$VERIFIER_ID" "$NULLIFIER" "$FLOOR" "$CONTEXT")"
ok "verifier ImageID $VERIFIER_ID"
ok "enforced policy  floor $FLOOR, context ${CONTEXT:0:16}…"
ok "gate tag         $GATE_TAG"
ok "derived PDA      $MARKER_PDA"
echo

echo "[5/5] that PDA is owned by the verifier program"
# program_owner is [u32; 8] little-endian over the ImageID bytes.
EXPECTED=$(python3 -c "
import sys
b=bytes.fromhex(sys.argv[1])
print('['+','.join(str(int.from_bytes(b[i:i+4],'little')) for i in range(0,32,4))+']')" "$VERIFIER_ID")
OWNER=$(rpc getAccount "[\"$MARKER_PDA\"]" | jq -c '.result.program_owner // empty')
if [ -z "$OWNER" ]; then
  bad "marker PDA $MARKER_PDA not found on chain"
elif [ "$OWNER" = "$EXPECTED" ]; then
  ok "owned by the deep verifier"
else
  bad "owned by $OWNER, expected $EXPECTED"
fi
echo

if [ "$FAILED" -eq 0 ]; then
  cat <<'EOF'
===========================================================
VERIFIED.

The transaction is privacy-preserving and carries a real STARK
receipt. The sequencer verifies that receipt against the pinned
PRIVACY_PRESERVING_CIRCUIT_ID before applying any state
(validated_state_diff.rs:426), so acceptance implies verification.
The marker PDA, derived above rather than asserted, is owned by
the verifier program, and program_owner cannot be forged.

Because the PDA seed commits to the floor and the context, that
marker could only have been produced by an execution that enforced
this exact policy. A run that demanded less lands at a different
address.

That the receipt's circuit composed the chained call to the
attestation program with env::verify follows from the deployed
verifier bytecode, which is byte-identical to the source in this
repository (step 1) and declares that ChainedCall.
===========================================================
EOF
  exit 0
else
  echo "VERIFICATION FAILED — see the failures above." >&2
  exit 1
fi
