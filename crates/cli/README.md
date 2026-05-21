# attestation-cli (`attest`)

CLI for LP-0005 attestation credentials.

```bash
cargo build --release -p attestation-cli --bin attest

# Generate a presenter key (secp256k1).
./target/release/attest keygen --out presenter.json

# Generate an attestation. (Uses synthesized account state — see the SDK for
# wiring against a real sequencer's get_proof_for_commitment.)
./target/release/attest prove \
  --presenter presenter.json \
  --balance   1000000 \
  --threshold 100000 \
  --context   "my-app-v1" \
  --out       credential.bin

# Verify locally (Risc0 verify + ECDSA signature).
./target/release/attest verify \
  --credential credential.bin \
  --presenter  presenter.json \
  --context    "my-app-v1" \
  --threshold  100000
```

`scripts/demo.sh` runs the three steps end-to-end with `RISC0_DEV_MODE=0`.
