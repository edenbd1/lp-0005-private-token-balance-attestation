//! Async HTTP client for the LEZ sequencer JSON-RPC API.
//!
//! Wraps the JSON-RPC methods LP-0005's host code drives:
//!
//! - [`SequencerClient::get_proof_for_commitment`] — fetch the Merkle path for
//!   a private-account commitment from the sequencer's index. Used by the SDK
//!   to replace the synthesized in-process Merkle path with a real one.
//! - [`SequencerClient::get_last_block_id`] — sanity check + sequencer
//!   liveness. Used by the demo script.
//! - [`SequencerClient::get_transaction`] — fetch a confirmed transaction by
//!   hash. Used to verify deployments programmatically.
//! - [`SequencerClient::get_account`] — fetch an account by id (base58 or
//!   typed prefix). Lets integrations read program PDAs.
//! - [`SequencerClient::send_transaction`] — submit a signed transaction. The
//!   raw blob is constructed by the `wallet` binary today; this method exists
//!   so callers can drive an end-to-end submission without shelling out.
//!
//! The client targets the public Logos LEZ testnet at
//! `https://testnet.lez.logos.co` by default; pass any other endpoint to
//! [`SequencerClient::new`] (e.g. a local sequencer on port 3040).

use serde::{Deserialize, Serialize};

/// Default endpoint used by examples / demos / docs. The same URL the LP-0017
/// submission uses for its public testnet deployment.
pub const DEFAULT_TESTNET_URL: &str = "https://testnet.lez.logos.co";

/// Membership proof for one commitment, as returned by the sequencer.
/// Mirrors `(usize, Vec<[u8; 32]>)` from `_external/lez/nssa/core/src/commitment.rs:83`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipProof {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; 32]>,
}

/// JSON-RPC request envelope. Public so callers can pre-compose requests if
/// they need to drive a different HTTP client than the one we ship.
#[derive(Debug, Serialize)]
pub struct Request<P> {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: P,
}

impl<P> Request<P> {
    pub const fn new(id: u64, method: &'static str, params: P) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope<R> {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<R>,
    error: Option<JsonRpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorBody {
    code: i64,
    message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON decode error: {0}")]
    Decode(#[from] serde_json::Error),

    #[error("server returned a JSON-RPC error (code {code}): {message}")]
    Rpc { code: i64, message: String },

    #[error("server returned neither result nor error — malformed JSON-RPC envelope")]
    EmptyResponse,
}

/// HTTP JSON-RPC client targeting a LEZ sequencer.
#[derive(Debug, Clone)]
pub struct SequencerClient {
    endpoint: String,
    http: reqwest::Client,
}

impl SequencerClient {
    /// Build a client against `endpoint` (e.g. `https://testnet.lez.logos.co`).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest builder"),
        }
    }

    /// Build a client targeting the public LEZ testnet
    /// (`https://testnet.lez.logos.co`).
    pub fn public_testnet() -> Self {
        Self::new(DEFAULT_TESTNET_URL)
    }

    /// Raw JSON-RPC call. Most callers should prefer the typed methods below;
    /// this is exposed for advanced uses (custom methods, batch calls).
    pub async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, ClientError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        // JSON-RPC `result: null` deserializes `Option<R>` to None for any R,
        // which loses information for callers that explicitly want Value::Null.
        // So we first parse into a raw envelope (result is a Value), then
        // deserialize the value into R — this way a null result reaches R as
        // Value::Null.
        let envelope: JsonRpcEnvelope<serde_json::Value> = resp.json().await?;
        if let Some(err) = envelope.error {
            return Err(ClientError::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        let raw = envelope.result.unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(raw)?)
    }

    /// `getLastBlockId() -> u64` — returns the current chain head height.
    pub async fn get_last_block_id(&self) -> Result<u64, ClientError> {
        self.call("getLastBlockId", serde_json::json!([])).await
    }

    /// `getTransaction(hash: String) -> Option<String>` — returns the
    /// base64-encoded transaction blob, or `None` if the hash is unknown.
    /// The blob is opaque (LEZ transaction envelope); callers typically just
    /// check presence as proof a deploy / submit landed on chain.
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<Option<String>, ClientError> {
        let v: serde_json::Value = self
            .call("getTransaction", serde_json::json!([tx_hash]))
            .await?;
        Ok(v.as_str().map(str::to_owned))
    }

    /// `getAccount(account_id: String) -> Option<AccountSnapshot>` — fetch an
    /// account by typed-prefixed id (e.g. `"Public/<base58>"`).
    pub async fn get_account(
        &self,
        account_id: &str,
    ) -> Result<Option<AccountSnapshot>, ClientError> {
        let v: Option<serde_json::Value> = self
            .call("getAccount", serde_json::json!([account_id]))
            .await?;
        match v {
            None => Ok(None),
            Some(v) => Ok(Some(serde_json::from_value(v)?)),
        }
    }

    /// `getProofForCommitment(commitment: hex) -> Option<MembershipProof>`.
    /// Returns the membership proof anchoring the given commitment under the
    /// sequencer's current Merkle root, or `None` if the commitment is unknown.
    /// The current commitment-set root, derived from a commitment known to be on chain.
    ///
    /// LEZ exposes no dedicated "current root" RPC. The root is the digest of the
    /// commitment set, and folding any valid membership proof yields it, which is
    /// exactly what `lee_core::compute_digest_for_path` does
    /// (`lee/state_machine/core/src/commitment.rs:89`). So: fetch a proof for a
    /// commitment you know is included, fold it, and you have the root the
    /// sequencer currently holds.
    ///
    /// **Why you need this.** An attestation's `merkle_root` is chosen by the
    /// prover. Nothing in the circuit, and nothing in the sequencer, ties it to
    /// real chain state: a prover can invent a one-leaf tree containing an account
    /// with any balance. Until a verifier compares `journal.merkle_root` against a
    /// root it fetched itself, the proof establishes possession of a key over a
    /// self-declared account, not a balance. See `docs/limitations.md`.
    ///
    /// Returns `None` if the commitment is not in the set, in which case you
    /// cannot derive the root from it.
    pub async fn commitment_set_root(
        &self,
        known_commitment: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, ClientError> {
        let Some(proof) = self.get_proof_for_commitment(known_commitment).await? else {
            return Ok(None);
        };
        Ok(Some(fold_membership_proof(known_commitment, &proof)))
    }

    /// Whether `merkle_root` is the root the sequencer currently holds.
    ///
    /// The honest check a gate should run before honouring an attestation.
    /// `known_commitment` is any commitment the caller knows is on chain; its own
    /// account's commitment is the natural choice.
    pub async fn is_root_current(
        &self,
        merkle_root: &[u8; 32],
        known_commitment: &[u8; 32],
    ) -> Result<bool, ClientError> {
        Ok(self.commitment_set_root(known_commitment).await? == Some(*merkle_root))
    }

    pub async fn get_proof_for_commitment(
        &self,
        commitment: &[u8; 32],
    ) -> Result<Option<MembershipProof>, ClientError> {
        // The sequencer expects the commitment as a JSON array of bytes, not a hex
        // string: `Commitment` deserialises from `[u8; 32]`. Sending hex returns
        // `-32602 Invalid params`, which is what this method did until 2026-07-20.
        let bytes: Vec<u8> = commitment.to_vec();
        let v: Option<serde_json::Value> = self
            .call("getProofForCommitment", serde_json::json!([bytes]))
            .await?;
        match v {
            None => Ok(None),
            Some(v) => Ok(Some(decode_proof_tuple(&v)?)),
        }
    }

    /// `sendTransaction(blob_base64: String) -> tx_hash: String` — submit a
    /// fully-signed transaction and return its hash.
    pub async fn send_transaction(&self, tx_blob_base64: &str) -> Result<String, ClientError> {
        self.call("sendTransaction", serde_json::json!([tx_blob_base64]))
            .await
    }

    /// Endpoint URL this client is bound to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Subset of an LEZ account snapshot relevant to LP-0005 use cases. The full
/// LEZ `Account` enum is larger; we extract `nonce` + `data` which are the
/// fields integrations care about.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AccountSnapshot {
    /// Public account variant — has `nonce` and `data` (raw bytes).
    Public {
        #[serde(default)]
        nonce: u64,
        #[serde(default)]
        data: Vec<u8>,
    },
    /// Anything else (program PDA, private account) — keep the raw JSON so
    /// callers can downcast as needed.
    Raw(serde_json::Value),
}

fn decode_proof_tuple(v: &serde_json::Value) -> Result<MembershipProof, ClientError> {
    // Tolerate two shapes:
    //   1. `[leaf_index, ["<hex>", ...]]`
    //   2. `{"leaf_index": ..., "siblings": [...]}` (forward-compat)
    if let Some(obj) = v.as_object() {
        let leaf_index = obj
            .get("leaf_index")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| ClientError::Rpc {
                code: -1,
                message: "missing leaf_index in MembershipProof object".to_string(),
            })?;
        let siblings_arr = obj
            .get("siblings")
            .and_then(|x| x.as_array())
            .ok_or_else(|| ClientError::Rpc {
                code: -1,
                message: "missing siblings in MembershipProof object".to_string(),
            })?;
        let siblings = decode_hash_array(siblings_arr.as_slice())?;
        return Ok(MembershipProof {
            leaf_index,
            siblings,
        });
    }
    if let Some(arr) = v.as_array() {
        if arr.len() != 2 {
            return Err(ClientError::Rpc {
                code: -1,
                message: format!(
                    "MembershipProof tuple has {} elements (expected 2)",
                    arr.len()
                ),
            });
        }
        let leaf_index = arr[0].as_u64().ok_or_else(|| ClientError::Rpc {
            code: -1,
            message: "leaf_index is not a u64".to_string(),
        })?;
        let siblings_arr = arr[1].as_array().ok_or_else(|| ClientError::Rpc {
            code: -1,
            message: "siblings is not an array".to_string(),
        })?;
        let siblings = decode_hash_array(siblings_arr.as_slice())?;
        return Ok(MembershipProof {
            leaf_index,
            siblings,
        });
    }
    Err(ClientError::Rpc {
        code: -1,
        message: "MembershipProof is neither object nor tuple".to_string(),
    })
}

/// Decode a list of 32-byte hashes.
///
/// The sequencer returns each sibling as a JSON array of byte values, which is
/// how `[u8; 32]` serialises. Hex strings are also accepted, both because an
/// earlier revision of this client assumed that shape and because it is the more
/// natural thing for a hand-written client to send.
fn decode_hash_array(values: &[serde_json::Value]) -> Result<Vec<[u8; 32]>, ClientError> {
    let mut out = Vec::with_capacity(values.len());
    for (i, v) in values.iter().enumerate() {
        let bytes: Vec<u8> = if let Some(arr) = v.as_array() {
            arr.iter()
                .map(|b| {
                    b.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(|| ClientError::Rpc {
                            code: -1,
                            message: format!("sibling[{i}] contains a non-byte value"),
                        })
                })
                .collect::<Result<_, _>>()?
        } else if let Some(hex_str) = v.as_str() {
            hex::decode(hex_str).map_err(|e| ClientError::Rpc {
                code: -1,
                message: format!("sibling[{i}] hex decode: {e}"),
            })?
        } else {
            return Err(ClientError::Rpc {
                code: -1,
                message: format!("sibling[{i}] is neither a byte array nor a hex string"),
            });
        };
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| ClientError::Rpc {
            code: -1,
            message: format!("sibling[{i}] length {} != 32", bytes.len()),
        })?;
        out.push(arr);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_last_block_id_decodes_u64_result() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"getLastBlockId"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0","id":1,"result":42_u64
            })))
            .mount(&server)
            .await;
        let client = SequencerClient::new(server.uri());
        assert_eq!(client.get_last_block_id().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn get_transaction_decodes_string_result() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"getTransaction"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0","id":1,"result":"AAEC"
            })))
            .mount(&server)
            .await;
        let client = SequencerClient::new(server.uri());
        assert_eq!(
            client.get_transaction("abc").await.unwrap(),
            Some("AAEC".to_string())
        );
    }

    #[tokio::test]
    async fn get_transaction_decodes_null_as_none() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method":"getTransaction"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0","id":1,"result":null
            })))
            .mount(&server)
            .await;
        let client = SequencerClient::new(server.uri());
        assert_eq!(client.get_transaction("abc").await.unwrap(), None);
    }

    #[tokio::test]
    async fn rpc_error_surfaces_as_client_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc":"2.0","id":1,"error":{"code": -32601, "message":"unknown method"}
            })))
            .mount(&server)
            .await;
        let client = SequencerClient::new(server.uri());
        let err = client
            .get_last_block_id()
            .await
            .expect_err("should surface RPC error");
        match err {
            ClientError::Rpc { code, message } => {
                assert_eq!(code, -32601);
                assert!(message.contains("unknown"));
            }
            _ => panic!("expected Rpc variant"),
        }
    }

    #[test]
    fn decode_proof_tuple_supports_array_shape() {
        let v = serde_json::json!([3, ["aa".repeat(32), "bb".repeat(32)]]);
        let proof = decode_proof_tuple(&v).unwrap();
        assert_eq!(proof.leaf_index, 3);
        assert_eq!(proof.siblings.len(), 2);
        assert_eq!(proof.siblings[0], [0xaa; 32]);
        assert_eq!(proof.siblings[1], [0xbb; 32]);
    }

    #[test]
    fn decode_proof_tuple_supports_object_shape() {
        let v = serde_json::json!({
            "leaf_index": 7,
            "siblings": ["00".repeat(32)]
        });
        let proof = decode_proof_tuple(&v).unwrap();
        assert_eq!(proof.leaf_index, 7);
        assert_eq!(proof.siblings.len(), 1);
        assert_eq!(proof.siblings[0], [0u8; 32]);
    }
}

/// Fold a membership proof to the root it attests, matching LEZ's own
/// `compute_digest_for_path`: the leaf is hashed once before folding, and a
/// sibling goes on the right when the index bit is 0.
#[must_use]
pub fn fold_membership_proof(commitment: &[u8; 32], proof: &MembershipProof) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut node: [u8; 32] = Sha256::digest(commitment).into();
    let mut idx = proof.leaf_index;
    for sib in &proof.siblings {
        let mut h = Sha256::new();
        if idx & 1 == 0 {
            h.update(node);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(node);
        }
        node = h.finalize().into();
        idx >>= 1;
    }
    node
}
