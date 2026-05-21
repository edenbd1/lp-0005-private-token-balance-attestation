//! In-memory transport, useful for tests and the off-chain demo loop.

use crate::{CredentialEnvelope, Transport, TransportError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;

#[derive(Default, Clone)]
pub struct InMemoryTransport {
    inner: Arc<Mutex<HashMap<String, (mpsc::Sender<CredentialEnvelope>, Arc<Mutex<mpsc::Receiver<CredentialEnvelope>>>)>>>,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    fn channel_for(&self, topic: &str) -> (mpsc::Sender<CredentialEnvelope>, Arc<Mutex<mpsc::Receiver<CredentialEnvelope>>>) {
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
        tx.send(envelope).map_err(|e| TransportError::Upstream(e.to_string()))?;
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
