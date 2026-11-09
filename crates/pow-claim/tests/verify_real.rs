//! Chain checks over the recorded real-node fixtures (`tests/fixtures/real`,
//! node 0.3.0-rc.5): known answers, accept, the reject matrix and operator
//! errors. The signature half is the logos scheme's (rln_auth_vectors).

use pow_claim::verify::{check, check_claim, Config};
use pow_claim::{node::testing::FakeNode, Claim, Evidence};
use serde_json::{json, Value};

const BID: &str = "7f75381ba1613693212cff6490d850fb41d625961bb46c6213ed0ab0a9756992";
const NUL: &str = "efcd48f40a04d764b408f89a74f9a216bd849ffef7fff75196e65985067d2410";
const NOTE_ID: &str = "1e8021be6a7711ff5b7738e14161c41789004733141b3e66bcfaaf59255b4f2e";
const SLOT: u64 = 13112243;

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real")
}

fn node() -> FakeNode {
    FakeNode::from_dir(dir()).unwrap()
}

fn meta() -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join("meta.json")).unwrap()).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_string()
}

fn arr(v: &Value) -> [u8; 32] {
    hex::decode(s(v)).unwrap().try_into().unwrap()
}

fn op64(n: &FakeNode) -> Value {
    n.blocks[BID]["transactions"][0]["mantle_tx"]["ops"][0].clone()
}

fn event(n: &FakeNode) -> Value {
    n.events[BID][0]["Tx"].clone()
}

fn claim() -> Claim {
    let m = meta();
    Claim {
        k: arr(&m["k"]),
        evidence: Evidence {
            claim_block_id: arr(&m["claim_block_id"]),
            pow_nullifier: arr(&m["pow_nullifier"]),
            spend: None,
        },
    }
}

fn base_cfg() -> Value {
    json!({"node_url": "http://fake", "audience": "poc"})
}

fn run_cfg(n: &FakeNode, cfg: Value) -> Result<Result<(), String>, String> {
    let c = Config::parse(Some(&cfg)).unwrap();
    check_claim(&[n], &claim(), &c).map(|c| c.outcome.map(|_| ()))
}

fn run(n: &FakeNode) -> Result<Result<(), String>, String> {
    run_cfg(n, base_cfg())
}

#[track_caller]
fn assert_reject(v: Result<Result<(), String>, String>, needle: &str) {
    let v = v.unwrap_or_else(|e| panic!("expected reject containing {needle:?}, got Err {e}"));
    let r = v.expect_err(&format!(
        "expected reject containing {needle:?}, got accept"
    ));
    assert!(
        r.to_lowercase().contains(needle),
        "reason {r:?} lacks {needle:?}"
    );
}

fn block_mut(n: &mut FakeNode) -> &mut Value {
    n.blocks.get_mut(BID).unwrap()
}

fn event_mut(n: &mut FakeNode) -> &mut Value {
    &mut n.events.get_mut(BID).unwrap()[0]["Tx"]
}

// ---- known answers ----

#[test]
fn known_answer_puzzle_ticket() {
    let n = node();
    let op = op64(&n);
    assert_eq!(op["opcode"], 64);
    let t = pow_claim::verify::ticket::puzzle_ticket(&op["payload"]).unwrap();
    assert_eq!(hex::encode(t), NUL);
}

#[test]
fn known_answer_ticket_accepts_hex_block_hash() {
    let n = node();
    let mut p = op64(&n)["payload"].clone();
    let bh = pow_claim::ownership::bytes32(&p["block_hash"], "bh").unwrap();
    p["block_hash"] = json!(hex::encode(bh));
    assert_eq!(
        hex::encode(pow_claim::verify::puzzle_ticket(&p).unwrap()),
        NUL
    );
}

#[test]
fn known_answer_note_id() {
    let n = node();
    let utxo = &event(&n)["payload"]["PoWRewardClaimed"]["utxo"];
    assert_eq!(pow_claim::note_id_hex(utxo).unwrap(), NOTE_ID);
}

#[test]
fn known_answer_op_id() {
    let n = node();
    let op = op64(&n);
    let got = pow_claim::verify::ticket::claim_op_id(&op["payload"]).unwrap();
    let want = pow_claim::ownership::bytes32(&event(&n)["op_id"], "op_id").unwrap();
    assert_eq!(got, want);
}

// ---- accept ----

#[test]
fn real_accepts_via_spent_to_and_records_the_decision() {
    let dir = std::env::temp_dir().join(format!("pca-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&log);
    let mut cfg = base_cfg();
    cfg["audit_log"] = json!(log.to_str().unwrap());
    let n = node();
    let c = check(&[&n], &claim(), &Config::parse(Some(&cfg)).unwrap()).unwrap();
    assert_eq!(c.outcome, Ok(pow_claim::Path::SpentTo));
    assert_eq!(c.lib_slot, Some(13112244));
    assert!(n.ranges.borrow().contains(&(SLOT, SLOT)));
    let line: Value = serde_json::from_str(
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(line["verdict"], "accept");
    assert_eq!(line["path"], "spent_to");
    assert_eq!(line["nullifier"], NUL);
    assert_eq!(line["lib_slot"], 13112244);
    assert_eq!(line["node"], "http://fake");
}

#[test]
fn real_accepts_exact_min_payout() {
    let mut cfg = base_cfg();
    cfg["min_payout"] = json!(999108);
    assert_eq!(run_cfg(&node(), cfg), Ok(Ok(())));
}

// ---- rejects: chain ----

#[test]
fn reject_not_final() {
    let mut n = node();
    n.info["cryptarchia_info"]["lib_slot"] = json!(SLOT - 1);
    assert_reject(run(&n), "not final");
}

#[test]
fn reject_block_missing() {
    let mut n = node();
    n.blocks.clear();
    assert_reject(run(&n), "unknown");
}

#[test]
fn reject_immutable_empty() {
    let mut n = node();
    n.immutable.clear();
    assert_reject(run(&n), "not canonical");
}

#[test]
fn reject_nullifier_absent() {
    let mut n = node();
    event_mut(&mut n)["payload"]["PoWRewardClaimed"]["pow_nullifier"] = json!("00".repeat(32));
    assert_reject(run(&n), "no powrewardclaimed");
    let mut n = node();
    n.events.clear();
    assert_reject(run(&n), "no powrewardclaimed");
}

#[test]
fn reject_tx_hash_changed() {
    let mut n = node();
    block_mut(&mut n)["transactions"][0]["mantle_tx"]["hash"] = json!("ab".repeat(32));
    assert_reject(run(&n), "not found");
}

#[test]
fn reject_epoch_nonce_altered() {
    let mut n = node();
    let op = &mut block_mut(&mut n)["transactions"][0]["mantle_tx"]["ops"][0]["payload"];
    op["epoch_nonce"] = json!("2e2ddf918544bca603c5a291c7dd1b902d6769ff4b00021506780e075c06051a");
    assert_reject(run(&n), "ticket recompute mismatch");
}

#[test]
fn reject_utxo_pk_altered() {
    let mut n = node();
    event_mut(&mut n)["payload"]["PoWRewardClaimed"]["utxo"]["note"]["pk"] =
        json!("e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07");
    assert_reject(run(&n), "public_key");
}

#[test]
fn reject_utxo_op_id_altered() {
    let mut n = node();
    event_mut(&mut n)["payload"]["PoWRewardClaimed"]["utxo"]["op_id"][0] = json!(0);
    assert_reject(run(&n), "op_id");
    let mut n = node();
    let ev = event_mut(&mut n);
    ev["op_id"][0] = json!(0);
    ev["payload"]["PoWRewardClaimed"]["utxo"]["op_id"][0] = json!(0);
    assert_reject(run(&n), "op_id recompute");
}

#[test]
fn reject_transfer_input_changed_front_run() {
    let mut n = node();
    let t = &mut block_mut(&mut n)["transactions"][0]["mantle_tx"]["ops"][1]["payload"];
    t["inputs"][0] = json!("2e8021be6a7711ff5b7738e14161c41789004733141b3e66bcfaaf59255b4f2e");
    assert_reject(run(&n), "does not own");
}

#[test]
fn reject_min_payout_above_output() {
    let mut cfg = base_cfg();
    cfg["min_payout"] = json!(999109);
    assert_reject(run_cfg(&node(), cfg), "does not own");
}

#[test]
fn reject_other_key() {
    let mut c = claim();
    c.k = [0x11; 32];
    let cfg = Config::parse(Some(&base_cfg())).unwrap();
    let r = check_claim(&[&node()], &c, &cfg).unwrap();
    assert!(r.outcome.unwrap_err().contains("does not own"));
}

// ---- operator errors ----

#[test]
fn err_no_node_url() {
    assert!(Config::parse(Some(&json!({"audience": "poc"})))
        .unwrap_err()
        .contains("node_url"));
    assert!(Config::parse(None).unwrap_err().contains("node_url"));
}

#[test]
fn err_audience_256() {
    let cfg = json!({"node_url": "http://x:1", "audience": "a".repeat(256)});
    assert!(Config::parse(Some(&cfg)).unwrap_err().contains("255"));
}

#[test]
fn err_info_without_lib_slot() {
    let mut n = node();
    n.info = json!({});
    assert!(run(&n).unwrap_err().contains("lib_slot"));
}

#[test]
fn err_no_node_configured() {
    let cfg = Config::parse(Some(&base_cfg())).unwrap();
    assert!(check_claim(&[], &claim(), &cfg)
        .unwrap_err()
        .contains("no node"));
}

#[test]
fn http_unreachable_is_err() {
    let cfg = json!({"node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 500});
    let c = Config::parse(Some(&cfg)).unwrap();
    let node = pow_claim::HttpNode::new(&c.node_url, c.http_timeout_ms);
    let e = check(&[&node], &claim(), &c).unwrap_err();
    assert!(e.contains("unreachable"), "{e}");
}
