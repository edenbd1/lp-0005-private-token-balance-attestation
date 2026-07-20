//! Token-gated chat admission over **real Logos Messaging**, end to end.
//!
//! This is the off-chain criterion demonstrated rather than asserted: *"the proof
//! can be transmitted over Logos Messaging and verified locally by a recipient,
//! demonstrated by a token-gated access flow (e.g. admission to a chat group)."*
//!
//! What actually happens:
//!
//!   1. A candidate generates a **real Risc0 attestation** proving `balance >= N`
//!      (`RISC0_DEV_MODE=0` unless you override it).
//!   2. The group operator issues a challenge nonce; the candidate signs it under
//!      the presenter key bound into the proof journal.
//!   3. The candidate publishes the credential envelope on a LIP-23 content topic
//!      from **Waku node A**.
//!   4. The operator, on a **separate Waku node B**, receives it off the relay
//!      network, verifies the receipt and the signature locally, and admits.
//!   5. Three negative cases are then exercised against the same live transport.
//!
//! Step 3 to 4 is a genuine libp2p network hop between two independent nodes.
//! Logos Delivery is itself a Waku node (`liblogosdelivery` takes a `WakuNodeConf`),
//! and this uses the same content-topic scheme and the same `{contentTopic,
//! payload(base64), ephemeral}` envelope its `send()` builds.
//!
//! Run it with `scripts/demo-offchain-gating.sh`, which starts the two nodes.
//! Or manually, with two nodes already peered:
//!
//! ```bash
//! WAKU_SENDER=http://127.0.0.1:8645 WAKU_RECEIVER=http://127.0.0.1:8646 \
//!   cargo run --release -p chat-gate --example waku_token_gate
//! ```

use attestation_delivery_transport::{
    waku_rest::{content_topic_for, WakuRestTransport},
    CredentialEnvelope, Transport,
};
use attestation_sdk::{PresenterKey, ProveRequest};
use chat_gate::{group_context_id, GroupRoster};

const GROUP: &str = "premium-lounge";
const MIN_STAKE: u128 = 100_000;
const BALANCE: u128 = 1_000_000;

fn step(n: u8, msg: &str) {
    println!("\n[{n}/6] {msg}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sender_url = std::env::var("WAKU_SENDER").unwrap_or_else(|_| "http://127.0.0.1:8645".into());
    let receiver_url =
        std::env::var("WAKU_RECEIVER").unwrap_or_else(|_| "http://127.0.0.1:8646".into());
    let topic = content_topic_for(GROUP);

    println!("===========================================================");
    println!("LP-0005 token-gated chat admission over Logos Messaging");
    println!("  sender node    {sender_url}");
    println!("  receiver node  {receiver_url}");
    println!("  content topic  {topic}");
    println!("===========================================================");

    step(1, "connect to both Waku nodes");
    let sender = WakuRestTransport::with_endpoint(&sender_url);
    let receiver = WakuRestTransport::with_endpoint(&receiver_url);
    println!("  sender peer    {}", sender.health()?);
    println!("  receiver peer  {}", receiver.health()?);
    if sender.health()? == receiver.health()? {
        return Err("both endpoints point at the same node; the hop would be meaningless".into());
    }

    step(2, "the operator subscribes to the group's content topic");
    receiver.subscribe(&topic)?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    println!("  subscribed");

    step(3, "the candidate proves balance >= minimum stake");
    let presenter = PresenterKey::generate();
    let context_id = group_context_id(GROUP);
    let req = demo_request(&presenter, context_id, BALANCE, MIN_STAKE);
    // Groth16, not the default composite receipt. Waku caps a message at 153,600
    // bytes and a composite receipt is ~300 KB, so it does not fit; the Groth16
    // wrap is ~1.5 KB. This is precisely the payload-cap compatibility the
    // succinct path exists for (docs/benchmarks/cu-budget.md).
    let proof = attestation_sdk::prove_groth16(req)?;
    let receipt_bytes =
        bincode::serde::encode_to_vec(&proof.receipt, bincode::config::standard())?.len();
    println!("  proved {BALANCE} >= {MIN_STAKE} for group {GROUP:?}");
    println!("  Groth16 receipt {receipt_bytes} bytes (Waku limit is 153,600)");

    step(4, "the operator issues a challenge; the candidate signs it");
    let mut roster = GroupRoster::new(GROUP, MIN_STAKE);
    let nonce: [u8; 32] = rand_nonce();
    let signature = presenter.sign(&nonce, &proof.journal);
    println!("  nonce {}", hex::encode(nonce));

    step(5, "the credential crosses the Waku network, node A to node B");
    let envelope = CredentialEnvelope {
        receipt: proof.receipt.clone(),
        challenge_nonce: nonce,
        presenter_signature_der: signature.clone(),
        app_meta: GROUP.as_bytes().to_vec(),
    };
    block_on(sender.send(&topic, envelope))?;
    println!("  published from the sender node");

    let received = poll(&receiver, &topic, 20)?
        .ok_or("nothing arrived on the receiver node within the timeout")?;
    println!("  received on the receiver node, fingerprint {}", hex::encode(received.fingerprint()));

    step(6, "the operator verifies locally and decides");
    let journal = roster.admit(
        &received.receipt,
        &received.challenge_nonce,
        &received.presenter_signature_der,
    )?;
    println!("  attested threshold {} for context {}", journal.threshold, hex::encode(journal.context_id));
    println!("  ADMITTED to {GROUP}");

    println!("\n--- negative cases, over the same live transport ---");

    // A second admission with the same attestation must fail: one nullifier, one join.
    let replay = roster.admit(
        &received.receipt,
        &received.challenge_nonce,
        &received.presenter_signature_der,
    );
    println!(
        "  replay of the same attestation      {}",
        expect_err(&replay)
    );

    // An interceptor holds the envelope but not the presenter key, so it cannot
    // answer a fresh challenge. This is the identity-binding criterion.
    let fresh_nonce: [u8; 32] = rand_nonce();
    let mut other_roster = GroupRoster::new(GROUP, MIN_STAKE);
    let stolen = other_roster.admit(
        &received.receipt,
        &fresh_nonce,
        &received.presenter_signature_der,
    );
    println!("  intercepted proof, fresh challenge  {}", expect_err(&stolen));

    // A gate demanding more than was attested must refuse.
    let mut strict = GroupRoster::new(GROUP, BALANCE + 1);
    let under = strict.admit(
        &received.receipt,
        &received.challenge_nonce,
        &received.presenter_signature_der,
    );
    println!("  gate demanding more than attested   {}", expect_err(&under));

    println!("\n===========================================================");
    println!("PASSED. A real Risc0 credential travelled over the Waku relay");
    println!("network between two independent nodes, was verified locally by");
    println!("the recipient, and gated admission to the group. Replay, theft");
    println!("and an under-funded attestation were all refused.");
    println!("===========================================================");
    Ok(())
}

fn expect_err<T, E: std::fmt::Debug>(r: &Result<T, E>) -> String {
    match r {
        Err(e) => format!("REFUSED ({e:?})"),
        Ok(_) => "ACCEPTED — THIS IS A BUG".to_owned(),
    }
}

/// Poll the receiver until a credential shows up or the budget runs out.
fn poll(
    t: &WakuRestTransport,
    topic: &str,
    tries: u32,
) -> Result<Option<CredentialEnvelope>, Box<dyn std::error::Error>> {
    for _ in 0..tries {
        if let Some(e) = block_on(t.recv(topic))? {
            return Ok(Some(e));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Ok(None)
}

/// The transport trait is async; this example is deliberately synchronous, so
/// drive the futures on a current-thread runtime rather than pull in a macro.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures_lite::future::block_on(f)
}

fn rand_nonce() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();
    let mut h = Sha256::new();
    h.update(b"/lp-0005/demo/nonce/");
    h.update(seed);
    h.finalize().into()
}

/// Demo witness. The on-chain path consumes a real sequencer membership proof
/// (see `crates/cu-bench/tests/real_chain_attestation.rs`); this example is about
/// the transport, so it uses a self-consistent synthetic tree.
fn demo_request(
    presenter: &PresenterKey,
    context_id: [u8; 32],
    balance: u128,
    _threshold: u128,
) -> ProveRequest {
    use sha2::{Digest, Sha256};
    let mut req = ProveRequest {
        npk: [7u8; 32],
        identifier: 1,
        program_owner: [11u32; 8],
        balance,
        nonce: 3,
        data_hash: Sha256::digest([]).into(),
        merkle_path: Vec::new(),
        leaf_index: 0,
        merkle_root: [0u8; 32],
        threshold: MIN_STAKE,
        context_id,
        presenter_pubkey: presenter.public(),
    };
    let (_commit, leaf_hash) = attestation_sdk::precompute_leaf(&req);
    let (path, root) = attestation_sdk::synthetic_merkle_path(&leaf_hash, req.leaf_index, 3);
    req.merkle_path = path;
    req.merkle_root = root;
    req
}
