use pow_claim_verify::*;

fn check(payload: &[u8], idc: &[u8; 32], aud: &str) -> bool {
    let p = decode_payload(payload).unwrap();
    let d = challenge_digest(aud, idc, p.rate_max, &p.pow_nullifier);
    verify_sig(DEFAULT_VK_JSON, &p.k, &d, &p.zksig).unwrap_or(false)
}

#[test]
fn golden() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/golden.json");
    let Ok(s) = std::fs::read_to_string(path) else {
        println!("golden fixture absent; skipped");
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let payload = hex::decode(v["payload_hex"].as_str().unwrap()).unwrap();
    let idc: [u8; 32] = hex::decode(v["id_commitment_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let aud = v["audience"].as_str().unwrap();
    assert!(check(&payload, &idc, aud), "golden must verify");
    let sig_off = payload.len() - 128;
    let mut bad = payload.clone();
    bad[sig_off + 5] ^= 1;
    assert!(!check(&bad, &idc, aud), "flipped sig byte");
    let mut idc2 = idc;
    idc2[0] ^= 1;
    assert!(!check(&payload, &idc2, aud), "different idc");
    let mut rm = payload.clone();
    let r = u64::from_le_bytes(rm[98..106].try_into().unwrap()) + 1;
    rm[98..106].copy_from_slice(&r.to_le_bytes());
    assert!(!check(&rm, &idc, aud), "rate_max+1");
}
