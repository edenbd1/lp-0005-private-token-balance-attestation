# Glossary

| Term | Meaning |
|---|---|
| **LEZ** | Logos Execution Zone — the Logos blockchain we target (`_external/lez`). |
| **PPE** | Privacy-Preserving Execution — the LEZ outer Risc0 circuit that composes program proofs and enforces tree freshness. |
| **SPEL** | Anchor-for-Logos: macro-driven framework for writing LEZ programs (`_external/spel`). |
| **Basecamp** | The Logos Core app host. Hosts our future GUI deliverable. |
| **Logos Delivery** | The Logos peer-to-peer messaging layer; the "Logos Messaging" referenced in the prize text. |
| **`npk`** | Nullifier public key — private, identifies a Logos account holder. |
| **`identifier`** | Per-account index (`u128`). Combined with `npk` to derive `account_id`. |
| **`account_id`** | 32-byte derived id of a private account (`SHA256(PRIVATE_ACCOUNT_ID_PREFIX ‖ npk ‖ identifier_LE)`). |
| **Commitment** | A leaf in the LEZ commitment Merkle tree representing a private account's state. Format: `SHA256(COMMITMENT_PREFIX ‖ account_id ‖ program_owner ‖ balance ‖ nonce ‖ data_hash)`. |
| **`context_id`** | 32-byte application-defined identifier in our proof's journal. Pinned to prevent cross-gate replay. |
| **`presenter_pubkey`** | secp256k1 compressed pubkey (33 bytes) committed in the proof's journal. The matching secret key must sign a challenge to present the proof. |
| **`nullifier`** | LP-0005's per-credential marker (`SHA256(NULLIFIER_PREFIX ‖ presenter_pubkey ‖ context_id ‖ account_id)`). Integrations track it to enforce one-shot semantics. |
| **Receipt** | Risc0's STARK proof object. ~300 KB uncompressed for our circuit. |
| **Groth16 wrap** | Risc0's compression of a STARK receipt into a constant-size SNARK proof (~256 bytes), used for transport over Logos Delivery. |
| **Chained call** | A LEZ program's declaration that another program's proof must be composed in (verified by `env::verify` inside the PPE outer circuit). |
| **PDA** | Program-Derived Address — an account whose id is deterministically derived from `(program_id, seed, ...)`. |
| **`r0vm`** | The Risc0 zkVM runtime used to execute and prove the guest circuit. |
| **`rzup`** | Risc0's toolchain manager. Installs `cargo-risczero`, `r0vm`, and the guest Rust toolchain. |
