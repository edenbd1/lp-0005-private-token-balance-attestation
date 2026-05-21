//! Logos Delivery transport that shells out to a small Qt helper process.
//!
//! Why this approach: `_external/logos-delivery-module` exposes the Logos
//! Delivery API only through Qt meta-objects (C++/QML). The Logos team has not
//! published a Rust binding. Rather than write a full FFI binding against the
//! shared library (which would couple us to Logos Core build flags), we drive
//! a small Qt helper as a child process and exchange newline-delimited JSON
//! over stdin/stdout.
//!
//! This file is a stub: it lays out the protocol and the supervisor; the Qt
//! helper itself ships separately as a Logos Core plugin.
//!
//! Status: not enabled (see task #16). Compiles with `--features qt-bridge`
//! once the helper exists.

#![cfg(feature = "qt-bridge")]

use crate::{CredentialEnvelope, Transport, TransportError};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

/// Path to the Qt helper binary, typically resolved from `LOGOS_DELIVERY_HELPER`.
pub fn helper_path() -> String {
    std::env::var("LOGOS_DELIVERY_HELPER").unwrap_or_else(|_| "logos-delivery-helper".to_owned())
}

pub struct QtBridgeTransport {
    child: Mutex<Child>,
}

impl QtBridgeTransport {
    pub fn spawn() -> Result<Self, TransportError> {
        let child = Command::new(helper_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| TransportError::Upstream(format!("spawn helper: {e}")))?;
        Ok(Self { child: Mutex::new(child) })
    }
}

#[async_trait::async_trait]
impl Transport for QtBridgeTransport {
    async fn send(&self, _topic: &str, _envelope: CredentialEnvelope) -> Result<(), TransportError> {
        // Writes `{"op": "send", "topic": ..., "envelope": <base64>}\n` to stdin.
        Err(TransportError::Upstream("qt-bridge not wired up yet (task #16)".to_owned()))
    }

    async fn recv(&self, _topic: &str) -> Result<Option<CredentialEnvelope>, TransportError> {
        // Reads `{"op": "recv", "topic": ..., "envelope": <base64>}\n` from stdout.
        Err(TransportError::Upstream("qt-bridge not wired up yet (task #16)".to_owned()))
    }
}
