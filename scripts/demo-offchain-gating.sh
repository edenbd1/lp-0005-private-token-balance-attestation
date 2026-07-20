#!/usr/bin/env bash
# LP-0005 off-chain path: token-gated chat admission over real Logos Messaging.
#
# Satisfies: "the proof can be transmitted over Logos Messaging and verified
# locally by a recipient, demonstrated by a token-gated access flow (e.g.
# admission to a chat group)."
#
# Logos Delivery is a Waku node. `_external/logos-delivery-module/src/delivery_module_plugin.h:47-54`
# documents its `createNode` as taking a `WakuNodeConf` straight from
# `tools/confutils/cli_args.nim`, and its README describes joining "twn", the
# RLN-protected Waku Network. This script therefore starts two real Waku nodes,
# peers them, and moves a credential from one to the other over the relay
# network, using the same LIP-23 content-topic scheme and the same
# `{contentTopic, payload(base64), ephemeral}` envelope Logos Delivery's send()
# builds.
#
# Needs Docker and cargo. Everything else is set up here.
#
#   ./scripts/demo-offchain-gating.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

: "${RISC0_DEV_MODE:=0}"
export RISC0_DEV_MODE

NODE_A=nwaku-lp0005-a
NODE_B=nwaku-lp0005-b
IMAGE=wakuorg/nwaku:v0.38.0
PORT_A=8645
PORT_B=8646
KEEP_NODES="${KEEP_NODES:-0}"

cleanup() {
  if [[ "$KEEP_NODES" != "1" ]]; then
    docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
  else
    echo "KEEP_NODES=1, leaving $NODE_A and $NODE_B running"
  fi
}
trap cleanup EXIT

wait_rest() {
  local port="$1" name="$2"
  for _ in $(seq 1 60); do
    if curl -s -m 5 "http://127.0.0.1:$port/debug/v1/info" >/dev/null 2>&1; then
      return 0
    fi
    if ! docker ps --filter "name=$name" --format '{{.Status}}' | grep -q Up; then
      echo "  ❌ $name died on startup:" >&2
      docker logs "$name" 2>&1 | tail -15 >&2
      return 1
    fi
    sleep 2
  done
  echo "  ❌ $name did not answer on port $port within 120s" >&2
  return 1
}

echo "==========================================================="
echo "▶ LP-0005 off-chain gating over Logos Messaging (Waku)"
echo "▶ RISC0_DEV_MODE = $RISC0_DEV_MODE"
echo "==========================================================="
echo

echo "[1/4] start two Waku nodes"
docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
# --nat=extip is required: without it the node fails to update its ENR
# multiaddress and exits. --discv5-discovery=false keeps the demo off the
# public network so it is deterministic and offline-friendly.
docker run -d --name "$NODE_A" --platform linux/amd64 -p "$PORT_A":8645 "$IMAGE" \
  --relay=true --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-allow-origin="*" \
  --nodekey="$(openssl rand -hex 32)" --cluster-id=16 --num-shards-in-network=1 \
  --discv5-discovery=false --nat=extip:127.0.0.1 >/dev/null
wait_rest "$PORT_A" "$NODE_A"
PEER_A=$(curl -s -m 10 "http://127.0.0.1:$PORT_A/debug/v1/info" | python3 -c 'import sys,json; print(json.load(sys.stdin)["listenAddresses"][0])')
echo "  sender   $PEER_A"

# Peering matters: a lone node answers NoPeersToPublish, because relay has no
# mesh to gossip into. Two peered nodes make the hop real.
docker run -d --name "$NODE_B" --platform linux/amd64 -p "$PORT_B":8645 "$IMAGE" \
  --relay=true --rest=true --rest-address=0.0.0.0 --rest-port=8645 --rest-allow-origin="*" \
  --nodekey="$(openssl rand -hex 32)" --cluster-id=16 --num-shards-in-network=1 \
  --discv5-discovery=false --nat=extip:127.0.0.1 --staticnode="$PEER_A" >/dev/null
wait_rest "$PORT_B" "$NODE_B"
PEER_B=$(curl -s -m 10 "http://127.0.0.1:$PORT_B/debug/v1/info" | python3 -c 'import sys,json; print(json.load(sys.stdin)["listenAddresses"][0])')
echo "  receiver $PEER_B"
echo

echo "[2/4] let the relay mesh form"
sleep 12
echo "  ok"
echo

echo "[3/4] build the gating demo"
cargo build --release -q -p chat-gate --example waku_token_gate
echo "  built"
echo

echo "[4/4] run it"
echo
WAKU_SENDER="http://127.0.0.1:$PORT_A" \
WAKU_RECEIVER="http://127.0.0.1:$PORT_B" \
  cargo run --release -q -p chat-gate --example waku_token_gate
