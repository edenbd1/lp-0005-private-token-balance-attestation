//! In-memory transport, useful for tests and the off-chain demo loop.

use crate::{CredentialEnvelope, Transport, TransportError};
use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

type Sender = mpsc::Sender<CredentialEnvelope>;
type Receiver = Arc<Mutex<mpsc::Receiver<CredentialEnvelope>>>;
type Channel = (Sender, Receiver);

#[derive(Default, Clone)]
pub struct InMemoryTransport {
    inner: Arc<Mutex<HashMap<String, Channel>>>,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    fn channel_for(&self, topic: &str) -> Channel {
        let mut map = self.inner.lock().unwrap();
        map.entry(topic.to_owned())
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel();
                (tx, Arc::new(Mutex::new(rx)))
            })
            .clone()
    }
}

#[async_trait::async_trait]
impl Transport for InMemoryTransport {
    async fn send(&self, topic: &str, envelope: CredentialEnvelope) -> Result<(), TransportError> {
        let (tx, _) = self.channel_for(topic);
        tx.send(envelope)
            .map_err(|e| TransportError::Upstream(e.to_string()))?;
        Ok(())
    }

    async fn recv(&self, topic: &str) -> Result<Option<CredentialEnvelope>, TransportError> {
        let (_, rx) = self.channel_for(topic);
        let guard = rx.lock().unwrap();
        match guard.recv() {
            Ok(env) => Ok(Some(env)),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_receipt() -> risc0_zkvm::Receipt {
        // Build the smallest plausible Receipt for fingerprint/encode tests.
        // We can't fabricate a verifiable receipt without an actual prover;
        // use a default-constructed one and only exercise non-verifying
        // round-trip surfaces.
        bincode::serde::decode_from_slice::<risc0_zkvm::Receipt, _>(
            &include_bytes!("../../verifier-offchain/tests/fixtures/dev-mode-receipt.bin")[..],
            bincode::config::standard(),
        )
        .ok()
        .map(|(r, _)| r)
        .unwrap_or_else(|| panic!("dev-mode receipt fixture missing; regenerate or fall back"))
    }

    fn envelope() -> CredentialEnvelope {
        CredentialEnvelope {
            receipt: dummy_receipt(),
            challenge_nonce: [0xaa; 32],
            presenter_signature_der: vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            app_meta: b"test".to_vec(),
        }
    }

    #[tokio::test]
    async fn inmem_roundtrip_single_message() {
        let t = InMemoryTransport::new();
        let env = envelope();
        t.send("topic-a", env.clone()).await.unwrap();
        let got = t.recv("topic-a").await.unwrap().unwrap();
        assert_eq!(got.challenge_nonce, env.challenge_nonce);
        assert_eq!(got.app_meta, env.app_meta);
    }

    #[tokio::test]
    async fn inmem_topics_are_isolated() {
        let t = InMemoryTransport::new();
        let mut env_a = envelope();
        env_a.app_meta = b"alpha".to_vec();
        let mut env_b = envelope();
        env_b.app_meta = b"beta".to_vec();
        t.send("topic-a", env_a).await.unwrap();
        t.send("topic-b", env_b).await.unwrap();
        let from_a = t.recv("topic-a").await.unwrap().unwrap();
        let from_b = t.recv("topic-b").await.unwrap().unwrap();
        assert_eq!(from_a.app_meta, b"alpha");
        assert_eq!(from_b.app_meta, b"beta");
    }

    #[tokio::test]
    async fn inmem_fifo_within_topic() {
        let t = InMemoryTransport::new();
        let mut e1 = envelope();
        e1.app_meta = b"1".to_vec();
        let mut e2 = envelope();
        e2.app_meta = b"2".to_vec();
        let mut e3 = envelope();
        e3.app_meta = b"3".to_vec();
        t.send("t", e1).await.unwrap();
        t.send("t", e2).await.unwrap();
        t.send("t", e3).await.unwrap();
        assert_eq!(t.recv("t").await.unwrap().unwrap().app_meta, b"1");
        assert_eq!(t.recv("t").await.unwrap().unwrap().app_meta, b"2");
        assert_eq!(t.recv("t").await.unwrap().unwrap().app_meta, b"3");
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let e = envelope();
        assert_eq!(e.fingerprint(), e.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_nonce() {
        let e1 = envelope();
        let mut e2 = e1.clone();
        e2.challenge_nonce[0] ^= 0xff;
        assert_ne!(e1.fingerprint(), e2.fingerprint());
    }

    #[test]
    fn fingerprint_changes_with_app_meta() {
        let e1 = envelope();
        let mut e2 = e1.clone();
        e2.app_meta.push(0xee);
        assert_ne!(e1.fingerprint(), e2.fingerprint());
    }

    #[test]
    fn transport_error_display_short() {
        let errs = [
            TransportError::Upstream("x".into()),
            TransportError::Encode("y".into()),
            TransportError::Decode("z".into()),
        ];
        for e in &errs {
            let s = e.to_string();
            assert!(s.len() < 200);
            assert!(!s.contains('\n'));
        }
    }
}
