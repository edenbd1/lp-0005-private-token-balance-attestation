# LP-0005 Basecamp app

A Logos Basecamp app surface for generating and presenting LP-0005 credentials from inside Basecamp. Built as a Qt6/QML plugin (`AttestationPlugin` implements `IComponent` with `Q_PLUGIN_METADATA`) and packaged as a loadable `.lgx`.

## Layout

```
app/
├── CMakeLists.txt                # dual-path build (framework + standalone)
├── metadata.json                 # Logos Core / Basecamp manifest
├── lp-0005-attestation.lgx       # packaged plugin (2.1 MB, lgx verify ✅)
├── qml/
│   ├── Main.qml                  # UI surface (Rectangle root, embeddable)
│   └── qmldir
├── src/
│   ├── plugin.h                  # IComponent + Q_PLUGIN_METADATA entry point
│   ├── plugin.cpp                # Plugin registration, QQuickWidget host
│   ├── attestation_bridge.h      # QObject exposed to QML
│   └── attestation_bridge.cpp    # Shells out to ./attest CLI as a child process
└── assets/                       # Icons, resources.qrc
```

## Loading the published plugin

The published asset is `app/lp-0005-attestation.lgx` (2.1 MB, `lgx verify ✅`, SHA-256 `193a903a0823cdf4f8ef3a333bc28c81e240c1b2faf5b7f8fd93bc1094c89770`).

Drop the directory into Basecamp's user-plugins location and the `PluginLoader` picks it up on next start:

- macOS: `~/Library/Application Support/Logos/LogosBasecampDev/plugins/`
- Linux: `~/.local/share/Logos/LogosBasecampDev/plugins/`

## Build paths

The `CMakeLists.txt` supports two paths.

### Framework build (production `.lgx`)

When the `LOGOS_MODULE_BUILDER_ROOT` environment variable points at a `logos-module-builder` checkout (typically the Nix dev shell), the build includes `LogosModule.cmake` and the `logos_module()` macro wires Qt + the Logos SDK + LGX packaging:

```bash
LOGOS_MODULE_BUILDER_ROOT=/path/to/logos-module-builder cmake -B build
cmake --build build
lgx create lp-0005-attestation
lgx add lp-0005-attestation.lgx --variant darwin-arm64 --files build/ --main lp_0005_attestation.dylib --view qml/Main.qml --yes
```

### Standalone Qt build (development / IDE)

For QML iteration without spinning up the full Logos stack:

```bash
brew install qt              # macOS — provides Qt6 from Homebrew
cmake -DCMAKE_PREFIX_PATH=$(brew --prefix qt) -B build
cmake --build build
```

Produces `build/lp_0005_attestation.dylib` next to `metadata.json` + `module.json` — ready to load directly from Basecamp's plugin folder without the `.lgx` wrapper.

## Wiring strategy

The bridge (`AttestationBridge`) talks to two backends:

- **Proving / verification** — shells out to `./attest prove ... --out cred.bin` and `./attest verify ...`. The plugin DSO stays lean (130 KB) because the heavy Risc0 prover lives in the sidecar binary.
- **Logos Delivery transport** — feature-gated `qt_bridge` Rust shim (`crates/delivery-transport/src/qt_bridge.rs`) that bridges credential publish/subscribe over Qt remote objects when the plugin is hosted inside the full Logos Core runtime.
