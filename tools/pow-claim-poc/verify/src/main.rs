use pow_claim_verify::*;
use std::process::exit;

fn h32(s: &str, what: &str) -> [u8; 32] {
    match hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    {
        Some(a) => a,
        None => {
            eprintln!("malformed {what}: need 32-byte hex");
            exit(2)
        }
    }
}

fn main() {
    let mut payload = None;
    let mut idc = None;
    let mut aud = String::new();
    let mut vk = None;
    let mut expect = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let v = match a.as_str() {
            "--payload-hex" | "--id-commitment-hex" | "--audience" | "--vk" | "--expect-k" => {
                it.next().unwrap_or_else(|| {
                    eprintln!("missing value for {a}");
                    exit(2)
                })
            }
            _ => {
                eprintln!("unknown arg {a}");
                exit(2)
            }
        };
        match a.as_str() {
            "--payload-hex" => payload = Some(v),
            "--id-commitment-hex" => idc = Some(v),
            "--audience" => aud = v,
            "--vk" => vk = Some(v),
            _ => expect = Some(v),
        }
    }
    let (Some(payload), Some(idc)) = (payload, idc) else {
        eprintln!("usage: pow-claim-verify --payload-hex H --id-commitment-hex C [--audience A] [--vk P] [--expect-k K]");
        exit(2)
    };
    if aud.len() > 255 {
        eprintln!("audience > 255 bytes");
        exit(2)
    }
    let bytes = hex::decode(payload.trim()).unwrap_or_else(|e| {
        eprintln!("payload hex: {e}");
        exit(2)
    });
    let p = decode_payload(&bytes).unwrap_or_else(|e| {
        eprintln!("{e}");
        exit(2)
    });
    let idc = h32(&idc, "id-commitment");
    let vk_json = match vk {
        Some(path) => std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("vk {path}: {e}");
            exit(2)
        }),
        None => DEFAULT_VK_JSON.to_string(),
    };
    let digest = challenge_digest(&aud, &idc, p.rate_max, &p.pow_nullifier);
    let sig_valid = match verify_sig(&vk_json, &p.k, &digest, &p.zksig) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("verify error: {e}");
            exit(2)
        }
    };
    let expect_match = expect.map(|e| h32(&e, "expect-k") == p.k);
    let opt = |o: Option<[u8; 32]>| {
        o.map(|v| serde_json::Value::String(hex::encode(v)))
            .unwrap_or(serde_json::Value::Null)
    };
    let out = serde_json::json!({
        "sig_valid": sig_valid, "version": p.version, "flags": p.flags,
        "k": hex::encode(p.k), "claim_block_id": hex::encode(p.claim_block_id),
        "pow_nullifier": hex::encode(p.pow_nullifier), "rate_max": p.rate_max,
        "spend_block_id": opt(p.spend_block_id), "spend_tx_hash": opt(p.spend_tx_hash),
        "digest": hex::encode(digest), "expect_k_match": expect_match,
    });
    println!("{out}");
    exit(if sig_valid && expect_match != Some(false) { 0 } else { 1 });
}
