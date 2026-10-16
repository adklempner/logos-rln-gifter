//! Chain checks (steps 3–8) against the verifier's own node.
//!
//! Classification: node transport / missing `lib_slot` = `Err` (operator
//! problem); anything that depends on the payload or chain content = reject.

use pow_claim_core::{
    node::NodeApi,
    ownership::{bytes32, note_id_hex, tx_event, Path},
    Payload,
};
use serde_json::Value;

use crate::{config::Config, ticket::{ClaimOp, OPCODE_CLAIM_POW_REWARD}};

/// Outcome of the chain checks. `outcome` is `Ok(path)` on accept or
/// `Err(reason)` on reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCheck {
    pub lib_slot: Option<u64>,
    pub outcome: Result<Path, String>,
}

fn node_err(e: String) -> String {
    format!("node unreachable or failing: {e}")
}

fn eq32(v: &Value, want: &[u8; 32]) -> bool {
    bytes32(v, "").map(|b| &b == want).unwrap_or(false)
}

/// Path B: an opcode-0 Transfer in `tx` whose `inputs` contain `note_id_hex`
/// and whose `outputs` pay `k` (`pk == K`) at least `min_payout`.
pub fn spent_to_k(tx: &Value, note_id_hex: &str, k: &[u8; 32], min_payout: u64) -> bool {
    let Some(ops) = tx["mantle_tx"]["ops"].as_array() else { return false };
    ops.iter().filter(|op| op["opcode"].as_u64() == Some(0)).any(|op| {
        let p = &op["payload"];
        let spends = p["inputs"].as_array().is_some_and(|ins| {
            ins.iter()
                .any(|i| i.as_str().is_some_and(|s| s.eq_ignore_ascii_case(note_id_hex)))
        });
        spends
            && p["outputs"].as_array().is_some_and(|outs| {
                outs.iter().any(|o| {
                    eq32(&o["pk"], k) && o["value"].as_u64().is_some_and(|v| v >= min_payout)
                })
            })
    })
}

/// Steps 3–8 for an already signature-checked payload.
pub fn check_claim(nodes: &[&dyn NodeApi], p: &Payload, cfg: &Config) -> Result<ClaimCheck, String> {
    let node = match nodes {
        [] => return Err("no node configured".into()),
        [n] => *n,
        _ => return Err("quorum verification is unsupported in this PoC".into()),
    };
    let mut lib_slot = None;
    let outcome = run(node, p, cfg, &mut lib_slot)?;
    Ok(ClaimCheck { lib_slot, outcome })
}

fn run(
    node: &dyn NodeApi,
    p: &Payload,
    cfg: &Config,
    lib_out: &mut Option<u64>,
) -> Result<Result<Path, String>, String> {
    macro_rules! reject {
        ($($t:tt)*) => { return Ok(Err(format!($($t)*))) };
    }
    let bid = hex::encode(p.claim_block_id);
    let nul = p.pow_nullifier;

    // 3. LIB.
    let info = node.info().map_err(node_err)?;
    let lib_slot = info["cryptarchia_info"]["lib_slot"]
        .as_u64()
        .ok_or_else(|| format!("node /cryptarchia/info: no cryptarchia_info.lib_slot in {info}"))?;
    *lib_out = Some(lib_slot);

    // 4. Claim block known and final.
    let Some(block) = node.block(&bid).map_err(node_err)? else {
        reject!("claim block unknown to node: {bid}");
    };
    if !block["header"]["id"].as_str().is_some_and(|s| s.eq_ignore_ascii_case(&bid)) {
        reject!("claim block {bid}: node returned a block with a different id");
    }
    let Some(s) = block["header"]["slot"].as_u64() else {
        reject!("claim block {bid}: no header.slot");
    };
    if s > lib_slot {
        reject!("claim block not final yet (slot {s} > lib_slot {lib_slot})");
    }

    // 5. Canonical: in the immutable chain at its slot.
    let imm = node.immutable_blocks(s, s).map_err(node_err)?;
    if !imm
        .iter()
        .any(|b| b["header"]["id"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(&bid)))
    {
        reject!("claim block not canonical (not in the immutable chain at slot {s})");
    }

    // 6. The PoWRewardClaimed event for this nullifier.
    let events = node.events(&bid).map_err(node_err)?;
    let Some(ev) = events
        .iter()
        .map(tx_event)
        .find(|e| eq32(&e["payload"]["PoWRewardClaimed"]["pow_nullifier"], &nul))
    else {
        reject!("no PoWRewardClaimed event with this nullifier in the claim block");
    };
    let utxo = &ev["payload"]["PoWRewardClaimed"]["utxo"];

    // 7. The claim tx and its opcode-64 op reproduce the nullifier.
    let Some(tx_hash) = ev["tx_hash"].as_str() else {
        reject!("claim event has no tx_hash");
    };
    let Some(tx) = block["transactions"].as_array().and_then(|txs| {
        txs.iter().find(|t| {
            t["mantle_tx"]["hash"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(tx_hash))
        })
    }) else {
        reject!("claim tx {tx_hash} not found in the claim block");
    };
    let ops = tx["mantle_tx"]["ops"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let Some(op) = ops
        .iter()
        .filter(|o| o["opcode"].as_u64() == Some(OPCODE_CLAIM_POW_REWARD))
        .filter_map(|o| ClaimOp::parse(&o["payload"]).ok())
        .find(|op| op.puzzle_ticket() == nul)
    else {
        reject!("ticket recompute mismatch: no claim op in tx {tx_hash} derives this nullifier");
    };
    if !eq32(&utxo["note"]["pk"], &op.public_key) {
        reject!("minted note pk differs from the claim op's public_key");
    }
    let Ok(ev_op_id) = bytes32(&ev["op_id"], "event.op_id") else {
        reject!("claim event has no valid op_id");
    };
    if !eq32(&utxo["op_id"], &ev_op_id) {
        reject!("utxo.op_id differs from the event op_id");
    }
    if op.op_id() != ev_op_id {
        reject!("op_id recompute mismatch");
    }

    // 8. Ownership by K.
    let value = utxo["note"]["value"].as_u64().unwrap_or(0);
    if cfg.allow_direct_ownership && op.public_key == p.k && value >= cfg.min_payout {
        return Ok(Ok(Path::Direct));
    }
    let nid = match note_id_hex(utxo) {
        Ok(n) => n,
        Err(e) => reject!("minted utxo malformed: {e}"),
    };
    if spent_to_k(tx, &nid, &p.k, cfg.min_payout) {
        return Ok(Ok(Path::SpentTo));
    }
    if op.public_key == p.k && !cfg.allow_direct_ownership {
        reject!("K owns the minted note directly but direct ownership is disabled by config");
    }
    reject!(
        "K does not own the claimed note (no Transfer in the claim tx spends NoteId {nid} to K with value >= {})",
        cfg.min_payout
    )
}
