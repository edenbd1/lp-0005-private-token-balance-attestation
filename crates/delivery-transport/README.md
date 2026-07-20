# attestation-delivery-transport

Transport abstraction for LP-0005 credentials over Logos Delivery (a.k.a. Logos Messaging).

## Why a trait

Logos Delivery ships as a Qt/C++ Logos Core module and exposes no Rust binding. Rather than write an FFI shim, `waku_rest.rs` reaches the Waku node underneath it: Delivery's `createNode` takes a `WakuNodeConf`, so Logos Delivery *is* a Waku node. The transport uses the same LIP-23 content topics and the same `{contentTopic, payload(base64), ephemeral}` envelope Delivery's `send()` builds, over the node's REST interface. `scripts/demo-offchain-gating.sh` runs it across two peered nodes. `inmem.rs` remains for unit tests and is not a Logos Messaging transport.

## Surface

```rust
pub struct CredentialEnvelope {
    pub receipt: Receipt,
    pub challenge_nonce: [u8; 32],
    pub presenter_signature_der: Vec<u8>,
    pub app_meta: Vec<u8>,
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, topic: &str, envelope: CredentialEnvelope) -> Result<(), TransportError>;
    async fn recv(&self, topic: &str) -> Result<Option<CredentialEnvelope>, TransportError>;
}
```

## Provided backends

- `inmem::InMemoryTransport` — in-process mpsc channels, for tests.

Planned backends:

- `qt_bridge::QtBridgeTransport` — shells out to a small Qt helper exposing Logos Delivery `send/subscribe` over IPC.
- `ffi::LiblogosdeliveryTransport` — Rust FFI binding on top of `liblogosdelivery`.
