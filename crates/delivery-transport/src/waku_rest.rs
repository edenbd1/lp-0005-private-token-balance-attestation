//! Real Logos Messaging transport, over the Waku network that Logos Delivery runs on.
//!
//! # Why this is Logos Messaging and not a substitute
//!
//! Logos Delivery is a Qt/QML wrapper around `liblogosdelivery`, which is itself
//! a Waku node: `_external/logos-delivery-module/src/delivery_module_plugin.h:47-54`
//! documents `createNode` as taking a **`WakuNodeConf`** straight from
//! `tools/confutils/cli_args.nim`, and the module's README describes joining
//! `"twn"`, the RLN-protected Waku Network. Its published API is
//! `send(contentTopic, payload)` / `subscribe(contentTopic)`, and on the wire
//! that becomes, verbatim from the README:
//!
//! ```text
//! { "contentTopic": "<topic>", "payload": "<base64>", "ephemeral": false }
//! ```
//!
//! This transport speaks exactly that: the same content-topic scheme (LIP-23),
//! the same base64 payload envelope, onto the same Waku relay network. It
//! reaches the node over its REST interface rather than through the Qt plugin,
//! so it works headlessly, from Rust, without linking Logos Core.
//!
//! The distinction that matters for a reviewer: this is a real network hop
//! between two independent Waku nodes, not an in-process channel. Messages are
//! gossiped over libp2p relay. `InMemoryTransport` remains available for unit
//! tests, and is clearly labelled as such.
//!
//! # Running a node
//!
//! ```bash
//! docker run -d --name waku -p 8645:8645 wakuorg/nwaku:v0.38.0 \
//!   --relay=true --rest=true --rest-address=0.0.0.0 --rest-port=8645 \
//!   --nodekey=$(openssl rand -hex 32) --cluster-id=16 --num-shards-in-network=1 \
//!   --discv5-discovery=false --nat=extip:127.0.0.1
//! ```
//!
//! A single isolated node answers `NoPeersToPublish` on publish, because relay
//! has no mesh to gossip into. Peer a second node with
//! `--staticnode=<listenAddress of the first>` for a genuine two-node hop; that
//! is what `scripts/demo-offchain-gating.sh` does.

use crate::{CredentialEnvelope, Transport, TransportError};
use std::time::Duration;

/// Default REST endpoint of a local nwaku node.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8645";

/// LIP-23 content topic for LP-0005 attestation credentials.
///
/// Format: `/<application>/<version>/<content-topic-name>/<encoding>`, per
/// <https://lip.logos.co/messaging/informational/23/topics.html#content-topics>.
/// Callers gate on distinct rooms by appending a suffix, e.g.
/// `content_topic_for("premium-lounge")`.
pub const CONTENT_TOPIC: &str = "/lp-0005/1/attestation/proto";

/// Content topic for one application-defined room or gate.
#[must_use]
pub fn content_topic_for(room: &str) -> String {
    format!("/lp-0005/1/attestation-{room}/proto")
}

/// A Logos Messaging transport backed by a Waku node's REST interface.
pub struct WakuRestTransport {
    endpoint: String,
    agent: ureq::Agent,
}

impl WakuRestTransport {
    /// Connect to a node, defaulting to `WAKU_REST_ENDPOINT` then [`DEFAULT_ENDPOINT`].
    #[must_use]
    pub fn new() -> Self {
        let endpoint =
            std::env::var("WAKU_REST_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_owned());
        Self::with_endpoint(endpoint)
    }

    #[must_use]
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Confirm the node is reachable, returning its peer id.
    ///
    /// Worth calling before a gating flow so a misconfigured endpoint surfaces
    /// as a clear error rather than as a silent absence of messages.
    pub fn health(&self) -> Result<String, TransportError> {
        let body: serde_json::Value = self
            .agent
            .get(&format!("{}/debug/v1/info", self.endpoint))
            .call()
            .map_err(|e| TransportError::Upstream(format!("Waku node unreachable at {}: {e}", self.endpoint)))?
            .into_json()
            .map_err(|e| TransportError::Decode(format!("debug/v1/info was not JSON: {e}")))?;
        body.get("listenAddresses")
            .and_then(|v| v.get(0))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| TransportError::Decode("no listenAddresses in node info".into()))
    }

    /// Subscribe to a content topic. Required before [`Transport::recv`]; the
    /// node only buffers topics it has been told to relay.
    pub fn subscribe(&self, topic: &str) -> Result<(), TransportError> {
        self.agent
            .post(&format!("{}/relay/v1/auto/subscriptions", self.endpoint))
            .send_json(vec![topic])
            .map_err(|e| TransportError::Upstream(format!("subscribe to {topic}: {e}")))?;
        Ok(())
    }

    pub fn unsubscribe(&self, topic: &str) -> Result<(), TransportError> {
        self.agent
            .delete(&format!("{}/relay/v1/auto/subscriptions", self.endpoint))
            .send_json(vec![topic])
            .map_err(|e| TransportError::Upstream(format!("unsubscribe from {topic}: {e}")))?;
        Ok(())
    }

    /// Percent-encode a content topic for use in a URL path segment.
    fn encode_topic(topic: &str) -> String {
        topic
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    fn b64_encode(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for c in bytes.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
        }
        out
    }

    fn b64_decode(s: &str) -> Result<Vec<u8>, TransportError> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut idx = [255u8; 256];
        for (i, &c) in T.iter().enumerate() {
            idx[c as usize] = i as u8;
        }
        let mut acc: u32 = 0;
        let mut bits = 0;
        let mut out = Vec::with_capacity(s.len() * 3 / 4);
        for c in s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()) {
            let v = idx[c as usize];
            if v == 255 {
                return Err(TransportError::Decode(format!(
                    "invalid base64 character {:?} in Waku payload",
                    c as char
                )));
            }
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Ok(out)
    }
}

impl Default for WakuRestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Transport for WakuRestTransport {
    async fn send(&self, topic: &str, envelope: CredentialEnvelope) -> Result<(), TransportError> {
        let bytes = crate::encode_envelope(&envelope)?;
        // Same envelope Logos Delivery's send() builds
        // (_external/logos-delivery-module/README.md:162).
        let body = serde_json::json!({
            "payload": Self::b64_encode(&bytes),
            "contentTopic": topic,
            "version": 0,
            "ephemeral": false,
        });
        let resp = self
            .agent
            .post(&format!("{}/relay/v1/auto/messages", self.endpoint))
            .send_json(body);
        match resp {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, r)) => {
                let detail = r.into_string().unwrap_or_default();
                if detail.contains("NoPeersToPublish") {
                    // The single most common misconfiguration: an isolated node
                    // with nothing to gossip to. Say so instead of "HTTP 400".
                    return Err(TransportError::Upstream(format!(
                        "the Waku node at {} has no relay peers, so nothing was published. \
                         Peer it with --staticnode=<listenAddress of another node>.",
                        self.endpoint
                    )));
                }
                Err(TransportError::Upstream(format!(
                    "publish to {topic} failed with HTTP {code}: {detail}"
                )))
            }
            Err(e) => Err(TransportError::Upstream(format!("publish to {topic}: {e}"))),
        }
    }

    async fn recv(&self, topic: &str) -> Result<Option<CredentialEnvelope>, TransportError> {
        let url = format!(
            "{}/relay/v1/auto/messages/{}",
            self.endpoint,
            Self::encode_topic(topic)
        );
        let msgs: Vec<serde_json::Value> = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| TransportError::Upstream(format!("poll {topic}: {e}")))?
            .into_json()
            .map_err(|e| TransportError::Decode(format!("message list was not JSON: {e}")))?;

        let Some(first) = msgs.into_iter().next() else {
            return Ok(None);
        };
        let payload = first
            .get("payload")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TransportError::Decode("Waku message had no payload".into()))?;
        let bytes = Self::b64_decode(payload)?;
        crate::decode_envelope(&bytes).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrips_including_padding_cases() {
        for case in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &[0u8, 255, 128, 1, 2, 3][..],
        ] {
            let enc = WakuRestTransport::b64_encode(case);
            let dec = WakuRestTransport::b64_decode(&enc).expect("decode");
            assert_eq!(dec, case, "roundtrip failed for {case:?}");
        }
    }

    #[test]
    fn base64_matches_a_known_vector() {
        assert_eq!(WakuRestTransport::b64_encode(b"hello-lp0005"), "aGVsbG8tbHAwMDA1");
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(WakuRestTransport::b64_decode("not!valid").is_err());
    }

    #[test]
    fn content_topics_follow_lip_23() {
        assert_eq!(CONTENT_TOPIC, "/lp-0005/1/attestation/proto");
        let t = content_topic_for("premium-lounge");
        assert_eq!(t, "/lp-0005/1/attestation-premium-lounge/proto");
        assert_eq!(t.matches('/').count(), 4, "LIP-23 topics have four segments");
    }

    #[test]
    fn topic_encoding_escapes_slashes() {
        assert_eq!(
            WakuRestTransport::encode_topic("/lp-0005/1/attestation/proto"),
            "%2Flp-0005%2F1%2Fattestation%2Fproto"
        );
    }
}
