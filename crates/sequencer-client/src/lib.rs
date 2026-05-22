//! LEZ sequencer JSON-RPC client (stub).
//!
//! Concrete HTTP transport is deliberately deferred to ship alongside the SPEL
//! wrapper and the wallet integration. See [`docs/sequencer-client-plan.md`](../../docs/sequencer-client-plan.md).
//!
//! What's pinned now: the wire shapes (request, response, Merkle proof) so callers
//! can write against this API while the transport is being built.

use serde::{Deserialize, Serialize};

/// Membership proof for one commitment, as returned by the sequencer.
/// Mirrors `(usize, Vec<[u8; 32]>)` from `_external/lez/nssa/core/src/commitment.rs:83`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    pub leaf_index: u64,
    pub siblings: Vec<[u8; 32]>,
}

/// JSON-RPC request envelope. Kept here so callers can pre-compose requests if they
/// need to drive a different HTTP client than the one we ship.
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

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("not yet implemented: sequencer transport ships with the SPEL wrapper")]
    NotImplemented,
}

/// Placeholder for the future async client. Calls return `NotImplemented` until
/// the transport lands; the type exists so dependent crates can compile against it.
pub struct SequencerClient {
    pub endpoint: String,
}

impl SequencerClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    pub fn get_proof_for_commitment(
        &self,
        _commitment: &[u8; 32],
    ) -> Result<Option<MembershipProof>, ClientError> {
        Err(ClientError::NotImplemented)
    }
}
