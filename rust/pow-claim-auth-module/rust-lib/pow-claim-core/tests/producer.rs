//! Discovery + produce tests over `FakeNode` (synthetic fixtures and
//! in-memory scenarios).

use pow_claim_core::{
    challenge, discover, node::testing::FakeNode, produce, Path, Payload, ProduceArgs,
};
use serde_json::{json, Value};

const K: &str = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07";
const MINER: &str = "3333333333333333333333333333333333333333333333333333333333333303";
#[cfg_attr(not(feature = "strict-ownership"), allow(dead_code))]
const ATTACKER: &str = "4444444444444444444444444444444444444444444444444444444444444404";

fn h(b: u8) -> String {
    hex::encode([b; 32])
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/synthetic")
}

fn utxo(op: u8, pk: &str) -> Value {
    json!({"op_id": vec![op; 32], "output_index": 0, "note": {"value": 1000, "pk": pk}})
}

fn claim_event(tx_hash: &str, nullifier: &str, utxo: &Value) -> Value {
    json!({"Tx": {"tx_hash": tx_hash, "op_id": utxo["op_id"].clone(),
        "payload": {"PoWRewardClaimed": {"pow_nullifier": nullifier, "utxo": utxo}}}})
}

fn transfer(inputs: &[String], out_pk: &str) -> Value {
    json!({"opcode": 0, "payload": {"inputs": inputs, "outputs": [{"value": 1000, "pk": out_pk}]}})
}

fn block(id: &str, parent: &str, slot: u64, txs: Vec<(String, Vec<Value>)>) -> Value {
    let txs: Vec<Value> = txs
        .into_iter()
        .map(|(hash, mut ops)| {
            ops.insert(0, json!({"opcode": 64, "payload": {}}));
            json!({"mantle_tx": {"hash": hash, "ops": ops}, "ops_proofs": []})
        })
        .collect();
    json!({"header": {"id": id, "parent_block": parent, "slot": slot}, "uncle_headers": [], "transactions": txs})
}

fn node(lib_slot: u64, tip: &str) -> FakeNode {
    let mut n = FakeNode::from_dir(fixture_dir()).unwrap();
    n.blocks.clear();
    n.events.clear();
    n.immutable.clear();
    n.info = json!({"cryptarchia_info": {"lib": tip, "lib_slot": lib_slot, "tip": tip, "slot": lib_slot + 10, "height": 1, "state": "Online"}, "phase": "Online"});
    n
}

/// Block with a claim minted directly to `pk` (path A candidate).
fn direct_block(id: u8, slot: u64, nul: u8, pk: &str) -> (Value, Vec<Value>) {
    let tx = h(id ^ 0xf0);
    let u = utxo(id, pk);
    (block(&h(id), &h(id - 1), slot, vec![(tx.clone(), vec![])]), vec![claim_event(&tx, &h(nul), &u), json!({"Header": {}})])
}

#[test]
fn fixtures_full_produce() {
    let n = FakeNode::from_dir(fixture_dir()).unwrap();
    let mut args = ProduceArgs::parse(Some(&json!({"audience": "poc"}))).unwrap();
    args.rate_max = 100;
    let idc = h(0x01);
    let p = produce(&n, &idc, &args).unwrap();
    assert_eq!(p.payload.len(), 234);
    assert_eq!(p.k_hex, K);
    assert_eq!(p.claim_block_id, h(0xa1));
    assert_eq!(p.pow_nullifier, h(0x11));
    let want = challenge::digest("poc", &[1; 32], 100, &[0x11; 32]);
    assert_eq!(p.digest, want);

    let sign = n.last_sign().unwrap();
    assert_eq!(sign.tx_hash, hex::encode(want));
    assert_eq!(sign.pk, K);

    let d = Payload::decode(&p.payload).unwrap();
    assert_eq!(d.version, 1);
    assert_eq!(d.flags, 0);
    assert_eq!(hex::encode(d.k), K);
    assert_eq!(d.claim_block_id, [0xa1; 32]);
    assert_eq!(d.pow_nullifier, [0x11; 32]);
    assert_eq!(d.rate_max, 100);
    assert_eq!(d.spend, None);
    assert_eq!(&d.zksig[..32], &[0xaa; 32]);
    assert_eq!(&d.zksig[32..96], &[0xbb; 64]);
    assert_eq!(&d.zksig[96..], &[0xcc; 32]);
}

#[test]
fn produce_with_spend_locator_and_bad_idc() {
    let n = FakeNode::from_dir(fixture_dir()).unwrap();
    let args = ProduceArgs::parse(Some(&json!({"spend_block_id": h(0x55), "spend_tx_hash": h(0x66)}))).unwrap();
    let p = produce(&n, &h(1), &args).unwrap();
    assert_eq!(p.payload.len(), 298);
    let d = Payload::decode(&p.payload).unwrap();
    assert_eq!(d.flags, 1);
    assert_eq!(d.spend, Some(([0x55; 32], [0x66; 32])));

    let half = ProduceArgs::parse(Some(&json!({"spend_block_id": h(0x55)}))).unwrap();
    assert!(produce(&n, &h(1), &half).unwrap_err().contains("together"));
    let e = produce(&n, "1234", &ProduceArgs::default()).unwrap_err();
    assert!(e.starts_with("id_commitment_hex"), "{e}");
}

#[test]
fn produce_propagates_bad_sign_reply() {
    let mut n = FakeNode::from_dir(fixture_dir()).unwrap();
    n.sign_reply = json!({"sig": {"pi_a": "aa", "pi_b": "bb", "pi_c": "cc"}});
    let e = produce(&n, &h(1), &ProduceArgs::default()).unwrap_err();
    assert!(e.contains("pi_a"), "{e}");
}

#[test]
fn path_a_hit() {
    let mut n = node(1000, &h(0x20));
    let (b, ev) = direct_block(0x20, 990, 0x11, K);
    n.add_block(b, ev, true);
    let f = discover(&n, &ProduceArgs::default()).unwrap();
    assert_eq!(f.path, Path::Direct);
    assert_eq!(f.k, K);
    assert_eq!(f.slot, 990);
    assert_eq!(f.nullifier, h(0x11));
    assert_eq!(f.event["tx_hash"], json!(h(0x20 ^ 0xf0)));
}

#[test]
fn no_k_is_an_error() {
    let mut n = node(1000, &h(0x20));
    n.pow_status = json!({"is_mining": false, "auto_claim": {"targets": []}});
    let e = discover(&n, &ProduceArgs::default()).unwrap_err();
    assert!(e.contains("no claim address"), "{e}");
    // claim_address overrides /pow/status.
    let (b, ev) = direct_block(0x20, 990, 0x11, K);
    n.add_block(b, ev, true);
    let args = ProduceArgs::parse(Some(&json!({"claim_address": K}))).unwrap();
    assert_eq!(discover(&n, &args).unwrap().k, K);
}

#[test]
fn not_owned_is_not_found() {
    let mut n = node(1000, &h(0x20));
    let (b, ev) = direct_block(0x20, 990, 0x11, MINER);
    n.add_block(b, ev, true);
    let e = discover(&n, &ProduceArgs::default()).unwrap_err();
    assert!(e.contains("no redeemable PoW claim found"), "{e}");
}

#[test]
fn newest_first_and_excluded_skipped() {
    let mut n = node(1000, &h(0x30));
    // Old block in an earlier 100-slot chunk, newer ones in the latest chunk.
    for (id, slot, nul) in [(0x10u8, 850u64, 0x01u8), (0x20, 950, 0x02), (0x30, 990, 0x03)] {
        let (b, ev) = direct_block(id, slot, nul, K);
        n.add_block(b, ev, true);
    }
    let f = discover(&n, &ProduceArgs::default()).unwrap();
    assert_eq!(f.block_id, h(0x30));
    assert_eq!(n.ranges.borrow()[0], (901, 1000));

    let args = ProduceArgs::parse(Some(&json!({"exclude_nullifiers": [h(0x03), h(0x02)]}))).unwrap();
    let f = discover(&n, &args).unwrap();
    assert_eq!(f.block_id, h(0x10));
    assert_eq!(f.nullifier, h(0x01));

    let all = ProduceArgs::parse(Some(&json!({"exclude_nullifiers": [h(0x03), h(0x02), h(0x01)]}))).unwrap();
    assert!(discover(&n, &all).is_err());
}

#[test]
fn scan_window_bounds_the_scan() {
    let mut n = node(1000, &h(0x10));
    let (b, ev) = direct_block(0x10, 500, 0x01, K);
    n.add_block(b, ev, true);
    let narrow = ProduceArgs::parse(Some(&json!({"scan_window_slots": 400}))).unwrap();
    assert!(discover(&n, &narrow).is_err());
    assert_eq!(n.ranges.borrow().last().copied(), Some((600, 600)));
    assert_eq!(discover(&n, &ProduceArgs::default()).unwrap().slot, 500);
}

#[test]
fn allow_unfinal_walks_from_tip() {
    // tip 0x32 (slot 1005, unfinal) -> 0x31 (slot 1003, unfinal, has claim) -> 0x30 (final, nothing)
    let mut n = node(1000, &h(0x32));
    let (b30, _) = direct_block(0x30, 990, 0x09, MINER);
    n.add_block(b30, vec![], true);
    let (b31, ev31) = direct_block(0x31, 1003, 0x07, K);
    n.add_block(b31, ev31, false);
    n.add_block(block(&h(0x32), &h(0x31), 1005, vec![]), vec![], false);

    let e = discover(&n, &ProduceArgs::default()).unwrap_err();
    assert!(e.contains("no redeemable"), "{e}");
    let args = ProduceArgs::parse(Some(&json!({"allow_unfinal": true}))).unwrap();
    let f = discover(&n, &args).unwrap();
    assert_eq!(f.block_id, h(0x31));
    assert_eq!(f.slot, 1003);
    // Depth 1 only sees the tip.
    let shallow = ProduceArgs::parse(Some(&json!({"allow_unfinal": true, "scan_depth_blocks": 1}))).unwrap();
    assert!(discover(&n, &shallow).is_err());
}

#[test]
fn pinned_nullifier_mode() {
    let mut n = node(1000, &h(0x30));
    let (b20, ev20) = direct_block(0x20, 950, 0x02, K);
    n.add_block(b20, ev20, true);
    let (b30, ev30) = direct_block(0x30, 990, 0x03, K);
    n.add_block(b30, ev30, true);

    let args = ProduceArgs::parse(Some(&json!({"claim_block_id": h(0x20), "pow_nullifier": h(0x02)}))).unwrap();
    let f = discover(&n, &args).unwrap();
    assert_eq!((f.block_id.as_str(), f.nullifier.as_str()), (h(0x20).as_str(), h(0x02).as_str()));
    assert!(n.ranges.borrow().is_empty(), "pinned mode must not scan");

    let no_block = ProduceArgs::parse(Some(&json!({"pow_nullifier": h(0x02)}))).unwrap();
    assert!(discover(&n, &no_block).unwrap_err().contains("claim_block_id"));
    let missing = ProduceArgs::parse(Some(&json!({"claim_block_id": h(0x99), "pow_nullifier": h(0x02)}))).unwrap();
    assert!(discover(&n, &missing).unwrap_err().contains("claim block not found"));
    let wrong = ProduceArgs::parse(Some(&json!({"claim_block_id": h(0x30), "pow_nullifier": h(0x02)}))).unwrap();
    assert!(discover(&n, &wrong).unwrap_err().contains("no PoWRewardClaimed"));
}

/// Claim minted to MINER; same tx contains `transfer_op`.
fn spend_scenario(transfer_op: Value) -> FakeNode {
    let mut n = node(1000, &h(0x40));
    let u = utxo(0x40, MINER);
    let tx = h(0xb0);
    let b = block(&h(0x40), &h(0x3f), 995, vec![(tx.clone(), vec![transfer_op])]);
    n.add_block(b, vec![claim_event(&tx, &h(0x0b), &u)], true);
    n
}

#[cfg(feature = "strict-ownership")]
#[test]
fn path_b_hit_strict() {
    let nid = pow_claim_core::note_id_hex(&utxo(0x40, MINER)).unwrap();
    let n = spend_scenario(transfer(&[h(0x77), nid], K));
    let f = discover(&n, &ProduceArgs::default()).unwrap();
    assert_eq!(f.path, Path::SpentTo);
    assert_eq!(f.k, K);
    assert_eq!(f.nullifier, h(0x0b));
}

#[cfg(feature = "strict-ownership")]
#[test]
fn front_run_rejected_strict() {
    // Attacker's tx: lifted claim (minted to MINER) + Transfer of the
    // attacker's own note to K. Does not spend NoteId(utxo).
    let n = spend_scenario(transfer(&[h(0x77)], K));
    assert!(discover(&n, &ProduceArgs::default()).is_err());
    // Spending the minted note but paying someone else is not ownership either.
    let nid = pow_claim_core::note_id_hex(&utxo(0x40, MINER)).unwrap();
    let n = spend_scenario(transfer(&[nid], ATTACKER));
    assert!(discover(&n, &ProduceArgs::default()).is_err());
}

#[cfg(not(feature = "strict-ownership"))]
#[test]
fn front_run_accepted_loose() {
    let n = spend_scenario(transfer(&[h(0x77)], K));
    let f = discover(&n, &ProduceArgs::default()).unwrap();
    assert_eq!(f.path, Path::SpentTo);
    assert_eq!(f.k, K);
}

#[test]
fn transfer_in_other_tx_does_not_count() {
    let mut n = node(1000, &h(0x40));
    let u = utxo(0x40, MINER);
    let b = block(&h(0x40), &h(0x3f), 995, vec![(h(0xb0), vec![]), (h(0xb1), vec![transfer(&[h(0x77)], K)])]);
    n.add_block(b, vec![claim_event(&h(0xb0), &h(0x0b), &u)], true);
    assert!(discover(&n, &ProduceArgs::default()).is_err());
}

#[test]
fn produce_http_rejects_bad_args_without_network() {
    let e = pow_claim_core::produce_http(&h(1), Some(&json!("{\"rate_max\": \"x\"}"))).unwrap_err();
    assert!(e.starts_with("rate_max"), "{e}");
}
