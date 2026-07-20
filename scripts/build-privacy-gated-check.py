#!/usr/bin/env python3
"""Build the `spel gated_check` arguments for the privacy-preserving on-chain path.

Takes a witness captured from a live LEZ sequencer (see capture below) plus a
presenter keypair, and emits the flags for the deep verifier's `gated_check`.

The witness is real: `npk` and `identifier` come from the wallet's private
account, `balance`/`nonce`/`program_owner` from the account's on-chain state, and
`merkle_path`/`leaf_index` from the sequencer's own `getProofForCommitment`. No
synthetic Merkle path is involved.

Usage:
  python3 scripts/build-privacy-gated-check.py \
      --witness /tmp/real_witness.json \
      --presenter /tmp/pres.json \
      --context lp-0005-onchain \
      --threshold 1000 \
      --out /tmp/gated-check-privacy.args
"""

import argparse
import hashlib
import json
import subprocess
import sys

NULLIFIER_PREFIX = b"/lp-0005/v0.1/Nullifier/" + b"\0" * 8
PRIVATE_ACCOUNT_ID_PREFIX = b"/LEE/v0.3/AccountId/Private/" + b"\0" * 4
CHALLENGE_TAG = b"/lp-0005/v0.1/PresenterChallenge/"
GATE_TAG_PREFIX = b"/lp-0005/v0.1/GateTag/" + b"\0" * 10


def derive_account_id(npk: bytes, identifier: int) -> bytes:
    h = hashlib.sha256()
    h.update(PRIVATE_ACCOUNT_ID_PREFIX)
    h.update(npk)
    h.update(identifier.to_bytes(16, "little"))
    return h.digest()


def context_id_from(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def compute_nullifier(pubkey: bytes, context_id: bytes, account_id: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(NULLIFIER_PREFIX)
    h.update(pubkey)
    h.update(context_id)
    h.update(account_id)
    return h.digest()


def compute_gate_tag(nullifier: bytes, minimum_threshold: int, expected_context_id: bytes) -> bytes:
    """The marker PDA seed, mirroring `attestation_core::compute_gate_tag`.

    Folding the floor and the context into the seed is what makes the marker's
    address encode the policy that was enforced, rather than merely recording
    that some gate ran. The guest re-derives this and rejects a mismatch, so a
    caller cannot land a marker at an address that overstates what it met.
    """
    h = hashlib.sha256()
    h.update(GATE_TAG_PREFIX)
    h.update(nullifier)
    h.update(minimum_threshold.to_bytes(16, "little"))
    h.update(expected_context_id)
    return h.digest()


def challenge_digest(nonce, merkle_root, threshold, context_id, pubkey, nullifier) -> bytes:
    h = hashlib.sha256()
    h.update(CHALLENGE_TAG)
    h.update(nonce)
    h.update(merkle_root)
    h.update(threshold.to_bytes(16, "little"))
    h.update(context_id)
    h.update(pubkey)
    h.update(nullifier)
    return h.digest()


def risc0_words(witness: dict) -> list:
    """Serialise PrivateInputs the way risc0's serde does, as u32 words.

    Layout, matching `risc0_zkvm::serde`:
      * [u8; N] -> N words, one byte per word
      * u128    -> 4 words, little-endian limbs
      * u64     -> 2 words
      * Vec<T>  -> length word, then the elements
    """
    words = []

    def push_bytes(bs):
        words.extend(int(b) for b in bs)

    def push_u128(v):
        words.extend([(v >> (32 * i)) & 0xFFFFFFFF for i in range(4)])

    def push_u64(v):
        words.extend([v & 0xFFFFFFFF, (v >> 32) & 0xFFFFFFFF])

    push_bytes(witness["npk"])                       # npk: [u8; 32]
    push_u128(witness["identifier"])                 # identifier: u128
    words.extend(int(w) for w in witness["program_owner"])  # [u32; 8]
    push_u128(witness["balance"])                    # balance: u128
    push_u128(witness["nonce"])                      # nonce: u128
    push_bytes(witness["data_hash"])                 # data_hash: [u8; 32]
    words.append(len(witness["merkle_path"]))        # Vec length
    for sib in witness["merkle_path"]:
        push_bytes(sib)
    push_u64(witness["leaf_index"])                  # leaf_index: u64
    return words


def sign(secret_hex: str, digest: bytes) -> str:
    """DER secp256k1 signature over `digest`, via the attest CLI's own signer."""
    out = subprocess.run(
        ["./target/release/attest", "sign-digest",
         "--secret", secret_hex, "--digest", digest.hex()],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print("attest sign-digest failed:\n" + out.stderr, file=sys.stderr)
        sys.exit(1)
    return out.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--witness", required=True)
    ap.add_argument("--presenter", required=True)
    ap.add_argument("--context", required=True)
    ap.add_argument("--threshold", type=int, required=True)
    ap.add_argument(
        "--minimum-threshold",
        type=int,
        default=None,
        help="the floor the gate enforces; defaults to --threshold. Set it lower "
             "than --threshold to exercise the gate's own policy check.",
    )
    ap.add_argument("--nonce", default=None, help="hex challenge nonce; random if omitted")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    w = json.load(open(args.witness))
    pres = json.load(open(args.presenter))
    pubkey = bytes.fromhex(pres["public_hex"])

    account_id = derive_account_id(bytes(w["npk"]), w["identifier"])
    context_id = context_id_from(args.context)
    nullifier = compute_nullifier(pubkey, context_id, account_id)
    minimum_threshold = (
        args.threshold if args.minimum_threshold is None else args.minimum_threshold
    )
    gate_tag = compute_gate_tag(nullifier, minimum_threshold, context_id)

    nonce = bytes.fromhex(args.nonce) if args.nonce else hashlib.sha256(
        b"lp-0005-challenge" + nullifier
    ).digest()

    merkle_root = bytes(w["merkle_root"])
    digest = challenge_digest(nonce, merkle_root, args.threshold, context_id, pubkey, nullifier)
    sig_der = sign(pres["secret_hex"], digest)

    words = risc0_words(w)

    def hexarg(b):
        return "'" + b.hex() + "'"

    lines = [
        f"--witness-words '{','.join(str(x) for x in words)}'",
        f"--merkle-root {hexarg(merkle_root)}",
        f"--threshold {args.threshold}",
        f"--context-id {hexarg(context_id)}",
        f"--presenter-pubkey '{','.join(str(b) for b in pubkey)}'",
        f"--nullifier {hexarg(nullifier)}",
        f"--presenter-nonce {hexarg(nonce)}",
        # Vec<u8> args take comma-separated decimal bytes, not hex.
        f"--presenter-signature-der '{','.join(str(b) for b in bytes.fromhex(sig_der))}'",
        f"--expected-context-id {hexarg(context_id)}",
        f"--minimum-threshold {minimum_threshold}",
        f"--gate-tag {hexarg(gate_tag)}",
    ]
    open(args.out, "w").write("\n".join(lines) + "\n")

    print(f"account_id  {account_id.hex()}")
    print(f"context_id  {context_id.hex()}")
    print(f"nullifier   {nullifier.hex()}")
    print(f"gate_tag    {gate_tag.hex()}   (the gate_marker PDA seed)")
    print(f"floor       {minimum_threshold}   (attested threshold {args.threshold})")
    print(f"witness     {len(words)} u32 words")
    print(f"wrote       {args.out}")


if __name__ == "__main__":
    main()
