//! Verifier over the recorded real-node fixtures (`pow-claim-core/tests/fixtures/real`,
//! node 0.3.0-rc.5): known answers, accept, reject matrix and operator errors.

use pow_claim_core::{node::testing::FakeNode, Payload};
use pow_claim_verifier::{default_vk, verify_request, verify_with, Config, Verdict, VerifyRequest};
use serde_json::{json, Value};

const BID: &str = "7f75381ba1613693212cff6490d850fb41d625961bb46c6213ed0ab0a9756992";
const NUL: &str = "efcd48f40a04d764b408f89a74f9a216bd849ffef7fff75196e65985067d2410";
const NOTE_ID: &str = "1e8021be6a7711ff5b7738e14161c41789004733141b3e66bcfaaf59255b4f2e";
const SLOT: u64 = 13112243;
/// Offset of zksig in a 234-byte payload.
const SIG_OFF: usize = 106;

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pow-claim-core/tests/fixtures/real")
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

fn op64(n: &FakeNode) -> Value {
    n.blocks[BID]["transactions"][0]["mantle_tx"]["ops"][0].clone()
}

fn event(n: &FakeNode) -> Value {
    n.events[BID][0]["Tx"].clone()
}

fn payload_hex() -> String {
    s(&meta()["payload_hex"])
}

fn payload_bytes() -> Vec<u8> {
    hex::decode(payload_hex()).unwrap()
}

fn req(payload_hex: &str, idc: &str, rate: u64, cfg: Value) -> VerifyRequest {
    VerifyRequest {
        auth_type: "pow-claim".into(),
        payload_hex: payload_hex.into(),
        id_commitment_hex: idc.into(),
        rate,
        config: Some(cfg),
    }
}

fn base_cfg() -> Value {
    json!({"node_url": "http://fake", "audience": "poc"})
}

fn run_full(n: &FakeNode, payload: &str, idc: &str, rate: u64, cfg: Value) -> Result<Verdict, String> {
    let r = req(payload, idc, rate, cfg.clone());
    let c = Config::parse(Some(&cfg)).unwrap();
    verify_with(&[n], &r, &c, default_vk().unwrap())
}

fn run(n: &FakeNode) -> Result<Verdict, String> {
    run_full(n, &payload_hex(), &s(&meta()["id_commitment_hex"]), 100, base_cfg())
}

fn run_payload(bytes: &[u8]) -> Verdict {
    run_full(&node(), &hex::encode(bytes), &s(&meta()["id_commitment_hex"]), 100, base_cfg()).unwrap()
}

#[track_caller]
fn assert_reject(v: Result<Verdict, String>, needle: &str) {
    let v = v.unwrap_or_else(|e| panic!("expected reject containing {needle:?}, got Err {e}"));
    assert!(!v.ok, "expected reject containing {needle:?}, got accept");
    let r = v.reason.unwrap_or_default();
    assert!(r.to_lowercase().contains(needle), "reason {r:?} lacks {needle:?}");
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
    let t = pow_claim_verifier::ticket::puzzle_ticket(&op["payload"]).unwrap();
    assert_eq!(hex::encode(t), NUL);
}

#[test]
fn known_answer_ticket_accepts_hex_block_hash() {
    let n = node();
    let mut p = op64(&n)["payload"].clone();
    let bh = pow_claim_core::ownership::bytes32(&p["block_hash"], "bh").unwrap();
    p["block_hash"] = json!(hex::encode(bh));
    assert_eq!(hex::encode(pow_claim_verifier::puzzle_ticket(&p).unwrap()), NUL);
}

#[test]
fn known_answer_note_id() {
    let n = node();
    let utxo = &event(&n)["payload"]["PoWRewardClaimed"]["utxo"];
    assert_eq!(pow_claim_core::note_id_hex(utxo).unwrap(), NOTE_ID);
}

#[test]
fn known_answer_op_id() {
    let n = node();
    let op = op64(&n);
    let got = pow_claim_verifier::ticket::claim_op_id(&op["payload"]).unwrap();
    let want = pow_claim_core::ownership::bytes32(&event(&n)["op_id"], "op_id").unwrap();
    assert_eq!(got, want);
}

// ---- accept ----

#[test]
fn real_accepts_via_spent_to() {
    let dir = std::env::temp_dir().join(format!("pca-audit-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("audit.jsonl");
    let _ = std::fs::remove_file(&log);
    let mut cfg = base_cfg();
    cfg["audit_log"] = json!(log.to_str().unwrap());
    let n = node();
    let v = run_full(&n, &payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg).unwrap();
    assert!(v.ok, "{:?}", v.reason);
    assert_eq!(v.nullifier.as_deref(), Some(NUL));
    assert!(n.ranges.borrow().contains(&(SLOT, SLOT)));
    let line: Value =
        serde_json::from_str(std::fs::read_to_string(&log).unwrap().lines().last().unwrap()).unwrap();
    assert_eq!(line["verdict"], "accept");
    assert_eq!(line["path"], "spent_to");
    assert_eq!(line["nullifier"], NUL);
    assert_eq!(line["lib_slot"], 13112244);
    assert_eq!(line["node"], "http://fake");
}

#[test]
fn real_accepts_lower_rate_and_exact_min_payout() {
    let n = node();
    let idc = s(&meta()["id_commitment_hex"]);
    assert!(run_full(&n, &payload_hex(), &idc, 50, base_cfg()).unwrap().ok);
    let mut cfg = base_cfg();
    cfg["min_payout"] = json!(999108);
    assert!(run_full(&n, &payload_hex(), &idc, 100, cfg).unwrap().ok);
    assert!(run_full(&n, &format!("0x{}", payload_hex()), &idc, 100, base_cfg()).unwrap().ok);
}

// ---- rejects: payload / signature ----

#[test]
fn reject_sig_flip_pi_a() {
    let mut b = payload_bytes();
    b[SIG_OFF + 5] ^= 1;
    let v = run_payload(&b);
    assert!(!v.ok);
    assert!(v.reason.unwrap().contains("signature"));
}

#[test]
fn reject_sig_flip_pi_b() {
    let mut b = payload_bytes();
    b[SIG_OFF + 32 + 5] ^= 1;
    let v = run_payload(&b);
    assert!(!v.ok);
    assert!(v.reason.unwrap().contains("signature"));
}

#[test]
fn reject_sig_flip_pi_c() {
    let mut b = payload_bytes();
    b[SIG_OFF + 96 + 5] ^= 1;
    assert!(!run_payload(&b).ok);
}

#[test]
fn reject_other_idc() {
    let v = run_full(&node(), &payload_hex(), &"11".repeat(32), 100, base_cfg());
    assert_reject(v, "signature");
}

#[test]
fn reject_bad_idc() {
    assert_reject(run_full(&node(), &payload_hex(), "abcd", 100, base_cfg()), "id_commitment");
}

#[test]
fn reject_audience_evil() {
    let mut cfg = base_cfg();
    cfg["audience"] = json!("evil");
    let v = run_full(&node(), &payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg);
    assert_reject(v, "signature");
}

#[test]
fn reject_rate_above_rate_max() {
    let v = run_full(&node(), &payload_hex(), &s(&meta()["id_commitment_hex"]), 101, base_cfg());
    assert_reject(v, "rate_max");
}

#[test]
fn reject_length_plus_minus_one() {
    let b = payload_bytes();
    assert!(run_payload(&b[..b.len() - 1]).reason.unwrap().contains("length"));
    let mut l = b.clone();
    l.push(0);
    assert!(run_payload(&l).reason.unwrap().contains("length"));
}

#[test]
fn reject_bad_hex() {
    assert_reject(run_full(&node(), "zz", &"11".repeat(32), 100, base_cfg()), "hex");
}

#[test]
fn reject_version_2() {
    let mut b = payload_bytes();
    b[0] = 2;
    assert!(run_payload(&b).reason.unwrap().contains("version"));
}

#[test]
fn reject_unknown_flag() {
    let mut b = payload_bytes();
    b[1] = 2;
    assert!(run_payload(&b).reason.unwrap().contains("flags"));
}

#[test]
fn reject_spend_locator() {
    let mut p = Payload::decode(&payload_bytes()).unwrap();
    p.spend = Some(([1; 32], [2; 32]));
    let v = run_payload(&p.encode());
    assert_eq!(v.reason.as_deref(), Some("spend locator unsupported in this PoC"));
    let mut cfg = base_cfg();
    cfg["allow_spend_locator"] = json!(false);
    let v = run_full(&node(), &hex::encode(p.encode()), &s(&meta()["id_commitment_hex"]), 100, cfg);
    assert_reject(v, "spend locator");
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
    let v = run_full(&node(), &payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg);
    assert_reject(v, "does not own");
}

// ---- operator errors ----

#[test]
fn err_no_node_url() {
    let r = req(&payload_hex(), &s(&meta()["id_commitment_hex"]), 100, json!({"audience": "poc"}));
    assert!(verify_request(&r).unwrap_err().contains("node_url"));
    let mut r = r;
    r.config = None;
    assert!(verify_request(&r).unwrap_err().contains("node_url"));
}

#[test]
fn err_bad_vk_path() {
    let mut cfg = base_cfg();
    cfg["zksign_vk_path"] = json!("/nonexistent/vk.json");
    let r = req(&payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg);
    assert!(verify_request(&r).unwrap_err().contains("zksign_vk_path"));
}

#[test]
fn vk_path_override_works() {
    let mut cfg = json!({"node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 500});
    cfg["zksign_vk_path"] =
        json!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/zksign_vk_v0.5.7.json"));
    let r = req(&payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg);
    // Signature passes with the file VK, then the unreachable node is an Err.
    assert!(verify_request(&r).unwrap_err().contains("unreachable"));
}

#[test]
fn err_audience_256() {
    let cfg = json!({"node_url": "http://x:1", "audience": "a".repeat(256)});
    let r = req(&payload_hex(), &s(&meta()["id_commitment_hex"]), 100, cfg);
    assert!(verify_request(&r).unwrap_err().contains("255"));
}

#[test]
fn err_info_without_lib_slot() {
    let mut n = node();
    n.info = json!({});
    assert!(run(&n).unwrap_err().contains("lib_slot"));
}

#[test]
fn http_unreachable_is_err_after_sig_and_tampered_is_reject() {
    let cfg = json!({"node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 500});
    let idc = s(&meta()["id_commitment_hex"]);
    let e = verify_request(&req(&payload_hex(), &idc, 100, cfg.clone())).unwrap_err();
    assert!(e.contains("unreachable"), "{e}");
    let mut b = payload_bytes();
    b[SIG_OFF + 5] ^= 1;
    let v = verify_request(&req(&hex::encode(b), &idc, 100, cfg)).unwrap();
    assert!(!v.ok);
}
