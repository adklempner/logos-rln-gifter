//! End-to-end producer (§4.2 steps 4–5).

use serde_json::Value;

use crate::{
    args::{hex32_bytes, norm_hex32, ProduceArgs},
    challenge::digest,
    discover::discover,
    http::HttpNode,
    node::NodeApi,
    payload::{Payload, FLAG_SPEND_LOCATOR, VERSION},
};

#[derive(Debug, Clone)]
pub struct Produced {
    pub payload: Vec<u8>,
    pub k_hex: String,
    pub claim_block_id: String,
    pub pow_nullifier: String,
    pub digest: [u8; 32],
}

fn sig_part<const N: usize>(sig: &Value, name: &str) -> Result<[u8; N], String> {
    let s = sig[name]
        .as_str()
        .ok_or_else(|| format!("sign reply: sig.{name} missing or not a string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 2 * N {
        return Err(format!(
            "sign reply: sig.{name} must be {} hex chars ({N} bytes), got {}",
            2 * N,
            s.len()
        ));
    }
    let mut o = [0u8; N];
    hex::decode_to_slice(s, &mut o).map_err(|e| format!("sign reply: sig.{name}: {e}"))?;
    Ok(o)
}

/// Parses `{"sig": {"pi_a": 32B hex, "pi_b": 64B hex, "pi_c": 32B hex}}` into
/// `pi_a ‖ pi_b ‖ pi_c`.
pub fn parse_sig_reply(reply: &Value) -> Result<[u8; 128], String> {
    let sig = reply
        .get("sig")
        .filter(|s| s.is_object())
        .ok_or_else(|| format!("sign reply: missing sig object: {reply}"))?;
    let a: [u8; 32] = sig_part(sig, "pi_a")?;
    let b: [u8; 64] = sig_part(sig, "pi_b")?;
    let c: [u8; 32] = sig_part(sig, "pi_c")?;
    let mut o = [0u8; 128];
    o[..32].copy_from_slice(&a);
    o[32..96].copy_from_slice(&b);
    o[96..].copy_from_slice(&c);
    Ok(o)
}

pub fn produce(node: &dyn NodeApi, id_commitment_hex: &str, args: &ProduceArgs) -> Result<Produced, String> {
    let idc = hex32_bytes("id_commitment_hex", id_commitment_hex)?;
    if args.audience.len() > 255 {
        return Err("audience: at most 255 bytes".into());
    }
    let found = discover(node, args)?;
    let k = hex32_bytes("k", &found.k)?;
    let block = hex32_bytes("claim_block_id", &found.block_id)?;
    let nul = hex32_bytes("pow_nullifier", &found.nullifier)?;

    let d = digest(&args.audience, &idc, args.rate_max, &nul);
    let reply = node.sign_zk(&d, &found.k)?;
    let zksig = parse_sig_reply(&reply)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply(a: usize, b: usize, c: usize) -> Value {
        json!({"sig": {"pi_a": "aa".repeat(a), "pi_b": "bb".repeat(b), "pi_c": "cc".repeat(c)}})
    }

    #[test]
    fn sig_reply_ok() {
        let s = parse_sig_reply(&reply(32, 64, 32)).unwrap();
        assert!(s[..32].iter().all(|&x| x == 0xaa));
        assert!(s[32..96].iter().all(|&x| x == 0xbb));
        assert!(s[96..].iter().all(|&x| x == 0xcc));
    }

    #[test]
    fn sig_reply_errors() {
        assert!(parse_sig_reply(&json!({})).unwrap_err().contains("missing sig"));
        assert!(parse_sig_reply(&json!({"sig": "x"})).unwrap_err().contains("missing sig"));
        assert!(parse_sig_reply(&reply(31, 64, 32)).unwrap_err().contains("pi_a"));
        assert!(parse_sig_reply(&reply(32, 32, 32)).unwrap_err().contains("pi_b"));
        assert!(parse_sig_reply(&reply(32, 64, 33)).unwrap_err().contains("pi_c"));
        let bad = json!({"sig": {"pi_a": "zz".repeat(32), "pi_b": "bb".repeat(64), "pi_c": "cc".repeat(32)}});
        assert!(parse_sig_reply(&bad).unwrap_err().contains("pi_a"));
        let missing = json!({"sig": {"pi_a": "aa".repeat(32), "pi_c": "cc".repeat(32)}});
        assert!(parse_sig_reply(&missing).unwrap_err().contains("pi_b"));
    }
}
