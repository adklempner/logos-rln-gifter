//! Synthetic chain (no signature): path A (`utxo.note.pk == K`) at the
//! `check_claim` layer, and `allow_direct_ownership = false`.

use pow_claim_core::{node::testing::FakeNode, ownership::Path, Payload};
use pow_claim_verifier::{check_claim, ticket::ClaimOp, Config};
use serde_json::{json, Value};

const BID: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
const TX: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
const SLOT: u64 = 500;

fn k() -> [u8; 32] {
    let mut k = [0u8; 32];
    k[0] = 37;
    k
}

/// A self-consistent claim block where the reward note pays `K` directly.
fn setup() -> (FakeNode, Payload) {
    let op = ClaimOp { epoch_nonce: [5; 32], block_hash: [7; 32], public_key: k() };
    let ticket = op.puzzle_ticket();
    let op_id: Vec<u8> = op.op_id().to_vec();
    let block = json!({
        "header": {"id": BID, "slot": SLOT},
        "transactions": [{"mantle_tx": {"hash": TX, "ops": [{"opcode": 64, "payload": {
            "epoch_nonce": hex::encode(op.epoch_nonce),
            "block_hash": op.block_hash.to_vec(),
            "public_key": hex::encode(op.public_key),
        }}]}}],
    });
    let ev = json!({"Tx": {"tx_hash": TX, "op_id": op_id, "payload": {"PoWRewardClaimed": {
        "pow_nullifier": hex::encode(ticket),
        "utxo": {"op_id": op_id, "output_index": 0, "note": {"value": 1000, "pk": hex::encode(k())}},
    }}}});
    let mut n = FakeNode { info: json!({"cryptarchia_info": {"lib_slot": SLOT + 10}}), ..Default::default() };
    n.add_block(block, vec![ev], true);
    let mut bid = [0u8; 32];
    hex::decode_to_slice(BID, &mut bid).unwrap();
    let p = Payload {
        version: 1,
        flags: 0,
        k: k(),
        claim_block_id: bid,
        pow_nullifier: ticket,
        rate_max: 100,
        spend: None,
        zksig: [0; 128],
    };
    (n, p)
}

fn cfg(extra: Value) -> Config {
    let mut c = json!({"node_url": "http://fake"});
    for (k, v) in extra.as_object().unwrap() {
        c[k] = v.clone();
    }
    Config::parse(Some(&c)).unwrap()
}

#[test]
fn path_a_direct_accepts() {
    let (n, p) = setup();
    let c = check_claim(&[&n], &p, &cfg(json!({}))).unwrap();
    assert_eq!(c.outcome, Ok(Path::Direct));
    assert_eq!(c.lib_slot, Some(SLOT + 10));
}

#[test]
fn direct_ownership_disabled_rejects() {
    let (n, p) = setup();
    let c = check_claim(&[&n], &p, &cfg(json!({"allow_direct_ownership": false}))).unwrap();
    let r = c.outcome.unwrap_err();
    assert!(r.contains("direct ownership is disabled"), "{r}");
}

#[test]
fn direct_min_payout_rejects() {
    let (n, p) = setup();
    let c = check_claim(&[&n], &p, &cfg(json!({"min_payout": 1001}))).unwrap();
    assert!(c.outcome.is_err());
    let c = check_claim(&[&n], &p, &cfg(json!({"min_payout": 1000}))).unwrap();
    assert_eq!(c.outcome, Ok(Path::Direct));
}

#[test]
fn other_k_rejects() {
    let (n, mut p) = setup();
    p.k[1] = 1;
    let c = check_claim(&[&n], &p, &cfg(json!({}))).unwrap();
    assert!(c.outcome.unwrap_err().contains("does not own"));
}

#[test]
fn node_count_checks() {
    let (n, p) = setup();
    assert!(check_claim(&[], &p, &cfg(json!({}))).is_err());
    assert!(check_claim(&[&n, &n], &p, &cfg(json!({}))).unwrap_err().contains("unsupported"));
}

#[test]
fn garbage_chain_json_never_panics() {
    let (mut n, p) = setup();
    let b = n.blocks.get_mut(BID).unwrap();
    b["transactions"] = json!([{"mantle_tx": {"hash": TX, "ops": [
        {"opcode": 64, "payload": {"epoch_nonce": 5, "block_hash": [1, 2], "public_key": null}},
        {"opcode": 0, "payload": {"inputs": [1, null], "outputs": "x"}},
        "junk"
    ]}}]);
    let c = check_claim(&[&n], &p, &cfg(json!({}))).unwrap();
    assert!(c.outcome.unwrap_err().contains("ticket"));
    n.events.insert(BID.into(), vec![json!(null), json!({"Tx": 3})]);
    let c = check_claim(&[&n], &p, &cfg(json!({}))).unwrap();
    assert!(c.outcome.is_err());
}
