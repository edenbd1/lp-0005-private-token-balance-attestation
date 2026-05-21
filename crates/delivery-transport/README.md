# attestation-delivery-transport

Transport abstraction for LP-0005 credentials over Logos Delivery (a.k.a. Logos Messaging).

## Why a trait

Logos Delivery currently ships only as a Qt/C++ Logos Core module (see [`_external/logos-delivery-module`](https://github.com/logos-co/logos-delivery-module)). The Rust binding does not exist upstream yet. The `Transport` trait lets the rest of the SDK be written and tested today; we plug in a real backend later (see task #16).

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
