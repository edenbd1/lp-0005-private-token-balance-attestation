# LP-0005 Basecamp app (skeleton)

A Logos Basecamp app surface for generating and presenting LP-0005 credentials. Skeleton only — the Qt plugin layer is documented and laid out, but actual proving is delegated to the `attest` CLI as a child process. This is enough to show reviewers the intended UX and gives a clear hand-off point for a production Qt build.

## Layout

```
app/
├── metadata.json                 # Logos Core / Basecamp manifest
├── qml/
│   ├── Main.qml                  # UI surface
│   └── qmldir
├── src/
│   ├── attestation_bridge.h      # QObject exposed to QML
│   ├── attestation_bridge.cpp    # Stub impl — shells out to ./attest in prod
│   └── plugin.cpp                # Plugin registration (TBD)
└── assets/                       # Icon, resources.qrc (TBD)
```

## Build path (when filled in)

1. Build the Rust artifacts: `cargo build --release -p attestation-cli --bin attest`.
2. Build the Qt plugin: standard `cmake -B build && cmake --build build`.
3. Bundle as a `.lgx` package: `nix bundle --bundler github:logos-co/nix-bundle-lgx github:edenbd1/lp-0005-private-token-balance-attestation#app`.
4. Drop the `.lgx` into Basecamp's modules directory, restart, and the app appears in the sidebar.

## Wiring strategy

The bridge (`AttestationBridge`) talks to two backends:

- **Proving / verification** — shells out to `./attest prove ... --out cred.bin` and `./attest verify ...`. No FFI required.
- **Logos Delivery transport** — uses the `logos-delivery-module` C++ API directly (we are inside a Logos Core process), with a small `qt_bridge` Rust shim if richer behavior is needed (`crates/delivery-transport/src/qt_bridge.rs`, task #16).

## Why a skeleton

The prize requires a Basecamp app GUI with local build instructions and a loadable package. Shipping a polished Qt plugin is out of scope for this submission round, but the manifest, QML surface, and bridge interface fix the intended shape so a Qt developer can fill in the rest.
