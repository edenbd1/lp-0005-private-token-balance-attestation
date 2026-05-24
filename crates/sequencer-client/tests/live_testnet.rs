//! Live integration test — talks to the public LEZ testnet.
//!
//! Gated `#[ignore]` so `cargo test` doesn't hit the network by default.
//! Run with: `cargo test -p attestation-sequencer-client --release -- --ignored --nocapture`.

use attestation_sequencer_client::SequencerClient;

const DEPLOY_TX_ATTESTATION: &str =
    "4593060b507fef640b7f9c3d25b75432a83bc7097a439334436e532983db989d";
const DEPLOY_TX_VERIFIER: &str = "6369e70e9164edcef92dd7193cd4a5e88013e4cd0788e743ddacd7de07c51b6d";

#[tokio::test]
#[ignore]
async fn public_testnet_sanity() {
    let client = SequencerClient::public_testnet();

    let height = client
        .get_last_block_id()
        .await
        .expect("getLastBlockId against public testnet");
    println!("Block height: {height}");
    assert!(height > 21000, "testnet head should be > 21000 by now");
}

#[tokio::test]
#[ignore]
async fn public_testnet_resolves_deployed_attestation_tx() {
    let client = SequencerClient::public_testnet();
    let blob = client
        .get_transaction(DEPLOY_TX_ATTESTATION)
        .await
        .expect("getTransaction");
    let blob = blob.expect("attestation deploy tx should be on chain");
    println!("Attestation deploy tx blob: {} bytes (base64)", blob.len());
    assert!(
        blob.len() > 1000,
        "the deploy blob is hundreds of KB — got {} chars",
        blob.len()
    );
}

#[tokio::test]
#[ignore]
async fn public_testnet_resolves_deployed_verifier_tx() {
    let client = SequencerClient::public_testnet();
    let blob = client
        .get_transaction(DEPLOY_TX_VERIFIER)
        .await
        .expect("getTransaction");
    let blob = blob.expect("verifier deploy tx should be on chain");
    println!("Verifier deploy tx blob: {} bytes (base64)", blob.len());
    assert!(
        blob.len() > 1000,
        "the deploy blob is hundreds of KB — got {} chars",
        blob.len()
    );
}

#[tokio::test]
#[ignore]
async fn public_testnet_unknown_tx_returns_none() {
    let client = SequencerClient::public_testnet();
    let unknown = "ff".repeat(32); // 64 hex chars, all 0xff — vanishingly unlikely to exist
    let blob = client
        .get_transaction(&unknown)
        .await
        .expect("getTransaction shouldn't error on unknown hash");
    // The sequencer returns `null` for unknown hashes; our client maps to None.
    assert!(
        blob.is_none(),
        "all-ff hash should not be a real tx, got {blob:?}"
    );
}
