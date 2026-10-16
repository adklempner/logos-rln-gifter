//! Tests over the recorded real-node fixtures (`tests/fixtures/real/`,
//! captured from a node 0.3.0-rc.5 run by `tools/pow-claim-poc/run.sh`).

use pow_claim_core::{challenge, node::testing::FakeNode, produce, ProduceArgs};
use serde_json::{json, Value};

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real")
}

fn meta() -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join("meta.json")).unwrap()).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

fn args(extra: Value) -> ProduceArgs {
    let m = meta();
    let mut a = json!({"audience": m["audience"], "rate_max": m["rate_max"]});
    for (k, v) in extra.as_object().unwrap() {
        a[k] = v.clone();
    }
    ProduceArgs::parse(Some(&a)).unwrap()
}

fn idc() -> String {
    s(&meta()["id_commitment_hex"])
}

#[test]
fn real_produce_reproduces_recorded_payload() {
    let m = meta();
    let n = FakeNode::from_dir(dir()).unwrap();
    let p = produce(&n, &idc(), &args(json!({}))).unwrap();

    assert_eq!(hex::encode(&p.payload), s(&m["payload_hex"]));
    assert_eq!(p.k_hex, s(&m["k"]));
    assert_eq!(p.claim_block_id, s(&m["claim_block_id"]));
    assert_eq!(p.pow_nullifier, s(&m["pow_nullifier"]));

    let idc_bytes: [u8; 32] = hex::decode(idc()).unwrap().try_into().unwrap();
    let nul: [u8; 32] = hex::decode(s(&m["pow_nullifier"])).unwrap().try_into().unwrap();
    let want = challenge::digest(&s(&m["audience"]), &idc_bytes, m["rate_max"].as_u64().unwrap(), &nul);
    assert_eq!(p.digest, want);
    let sign = n.last_sign().unwrap();
    assert_eq!(sign.tx_hash, hex::encode(want));
    assert_eq!(sign.pk, s(&m["k"]));
}

#[cfg(feature = "strict-ownership")]
#[test]
fn real_ownership_is_path_b_via_note_id() {
    use pow_claim_core::ownership::{note_id_hex, owner, Path};
    use pow_claim_core::Payload;

    let m = meta();
    let k = s(&m["k"]);
    let bid = s(&m["claim_block_id"]);
    let tx_hash = s(&m["tx_hash"]);
    let n = FakeNode::from_dir(dir()).unwrap();
    let block = n.blocks.get(&bid).unwrap();
    let ev = n.events.get(&bid).unwrap().iter().find(|e| {
        e["Tx"]["payload"]["PoWRewardClaimed"]["pow_nullifier"] == m["pow_nullifier"]
    }).unwrap();
    let utxo = &ev["Tx"]["payload"]["PoWRewardClaimed"]["utxo"];

    // The reward note pays a throwaway ticket key, not K.
    assert_ne!(utxo["note"]["pk"].as_str().unwrap().to_lowercase(), k);

    let nid = note_id_hex(utxo).unwrap();
    let tx = block["transactions"].as_array().unwrap().iter()
        .find(|t| t["mantle_tx"]["hash"] == m["tx_hash"]).unwrap();
    assert_eq!(s(&tx["mantle_tx"]["hash"]), tx_hash);
    let transfer = tx["mantle_tx"]["ops"].as_array().unwrap().iter()
        .find(|o| o["opcode"].as_u64() == Some(0)).unwrap();
    let inputs: Vec<String> = transfer["payload"]["inputs"].as_array().unwrap()
        .iter().map(|i| s(i).to_lowercase()).collect();
    assert!(inputs.contains(&nid), "NoteId {nid} not in Transfer inputs");
    assert!(transfer["payload"]["outputs"].as_array().unwrap().iter()
        .any(|o| s(&o["pk"]).to_lowercase() == k));

    let (got, path) = owner(ev, block, std::slice::from_ref(&k)).unwrap();
    assert_eq!(got, k);
    assert_eq!(path, Path::SpentTo);
    assert_ne!(path, Path::Direct);

    // Payload decodes to the same K.
    let d = Payload::decode(&hex::decode(s(&m["payload_hex"])).unwrap()).unwrap();
    assert_eq!(hex::encode(d.k), k);
}

#[test]
fn real_discovery_uses_immutable_range() {
    let m = meta();
    let slot = m["slot"].as_u64().unwrap();
    let n = FakeNode::from_dir(dir()).unwrap();
    produce(&n, &idc(), &args(json!({}))).unwrap();
    let ranges = n.ranges.borrow();
    assert!(!ranges.is_empty());
    assert!(ranges.iter().any(|&(a, b)| a <= slot && slot <= b), "{ranges:?}");
}

#[test]
fn real_pinned_mode_matches() {
    let m = meta();
    let n = FakeNode::from_dir(dir()).unwrap();
    let p = produce(&n, &idc(), &args(json!({
        "claim_block_id": m["claim_block_id"], "pow_nullifier": m["pow_nullifier"],
    }))).unwrap();
    assert_eq!(p.claim_block_id, s(&m["claim_block_id"]));
    assert_eq!(p.pow_nullifier, s(&m["pow_nullifier"]));
    assert_eq!(hex::encode(&p.payload), s(&m["payload_hex"]));
    assert!(n.ranges.borrow().is_empty(), "pinned mode must not scan");
}

#[test]
fn real_excluded_nullifier_yields_not_found() {
    let m = meta();
    let n = FakeNode::from_dir(dir()).unwrap();
    let e = produce(&n, &idc(), &args(json!({
        "exclude_nullifiers": [m["pow_nullifier"]], "allow_unfinal": false,
    }))).unwrap_err();
    assert!(e.contains("no redeemable"), "{e}");
}
