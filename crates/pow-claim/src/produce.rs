//! End-to-end producer (§4.2 steps 4–5).

use serde_json::Value;

use crate::{
    args::{hex32_bytes, ProduceArgs},
    challenge::digest,
    discover::discover,
    http::HttpNode,
    node::NodeApi,
    payload::{Payload, FLAG_SPEND_LOCATOR, VERSION},
};
use rln_auth_vector::hex::norm_hex32;

#[derive(Debug, Clone)]
pub struct Produced {
    pub payload: Vec<u8>,
    pub k_hex: String,
    pub claim_block_id: String,
    pub pow_nullifier: String,
    pub digest: [u8; 32],
}

pub fn produce(node: &dyn NodeApi, id_commitment_hex: &str, args: &ProduceArgs) -> Result<Produced, String> {
    let idc = hex32_bytes("id_commitment_hex", id_commitment_hex)?;
    let found = discover(node, args)?;
    let k = hex32_bytes("k", &found.k)?;
    let block = hex32_bytes("claim_block_id", &found.block_id)?;
    let nul = hex32_bytes("pow_nullifier", &found.nullifier)?;

    // Audience length is capped at 255 B by ProduceArgs::parse, so digest cannot panic.
    let d = digest(&args.audience, &idc, args.rate_max, &nul);
    let zksig = node.sign_zk(&d, &found.k)?;

    let spend = match (&args.spend_block_id, &args.spend_tx_hash) {
        (Some(b), Some(t)) => Some((hex32_bytes("spend_block_id", b)?, hex32_bytes("spend_tx_hash", t)?)),
        (None, None) => None,
        _ => return Err("spend_block_id and spend_tx_hash must be given together".into()),
    };
    let p = Payload {
        version: VERSION,
        flags: if spend.is_some() { FLAG_SPEND_LOCATOR } else { 0 },
        k,
        claim_block_id: block,
        pow_nullifier: nul,
        rate_max: args.rate_max,
        spend,
        zksig,
    };
    Ok(Produced {
        payload: p.encode(),
        k_hex: norm_hex32("k", &found.k)?,
        claim_block_id: found.block_id,
        pow_nullifier: found.nullifier,
        digest: d,
    })
}

/// Module entry point: parse `args` (object or stringified JSON), talk to
/// the node over HTTP, return the payload hex.
pub fn produce_http(id_commitment_hex: &str, raw_args: Option<&Value>) -> Result<String, String> {
    let args = ProduceArgs::parse(raw_args)?;
    let node = HttpNode::new(&args.node_url, args.http_timeout_ms);
    produce(&node, id_commitment_hex, &args).map(|p| hex::encode(p.payload))
}
