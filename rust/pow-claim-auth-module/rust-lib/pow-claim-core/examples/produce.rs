//! Tiny CLI around `pow_claim_core`.
//!
//! ```text
//! produce --node-url U --id-commitment-hex H [--args-json J]
//! produce --decode <payload_hex>
//! ```

use pow_claim_core::{HttpNode, Payload, ProduceArgs};
use serde_json::{json, Value};

fn usage() -> ! {
    eprintln!(
        "usage: produce --node-url U --id-commitment-hex H [--args-json J]\n       produce --decode <payload_hex>"
    );
    std::process::exit(2)
}

fn decode(h: &str) -> Result<Payload, String> {
    let b = hex::decode(h.trim().trim_start_matches("0x")).map_err(|e| format!("payload hex: {e}"))?;
    Payload::decode(&b)
}

fn run() -> Result<Value, String> {
    let mut it = std::env::args().skip(1);
    let (mut node_url, mut idc, mut args_json, mut dec) = (None, None, None, None);
    while let Some(a) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--node-url" => node_url = Some(val()),
            "--id-commitment-hex" => idc = Some(val()),
            "--args-json" => args_json = Some(val()),
            "--decode" => dec = Some(val()),
            _ => usage(),
        }
    }
    if let Some(h) = dec {
        return Ok(decode(&h)?.to_json());
    }
    let idc = idc.unwrap_or_else(|| usage());
    let mut raw: Value = match args_json {
        Some(s) => serde_json::from_str(&s).map_err(|e| format!("--args-json: {e}"))?,
        None => json!({}),
    };
    if let Some(u) = node_url {
        raw.as_object_mut()
            .ok_or("--args-json must be an object")?
            .insert("node_url".into(), Value::String(u));
    }
    let args = ProduceArgs::parse(Some(&raw))?;
    let node = HttpNode::new(&args.node_url, args.http_timeout_ms);
    let p = pow_claim_core::produce(&node, &idc, &args)?;
    Ok(json!({
        "payload_hex": hex::encode(&p.payload),
        "payload_len": p.payload.len(),
        "k": p.k_hex,
        "claim_block_id": p.claim_block_id,
        "pow_nullifier": p.pow_nullifier,
        "digest": hex::encode(p.digest),
        "decoded": Payload::decode(&p.payload)?.to_json(),
    }))
}

fn main() {
    match run() {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            println!("{}", json!({ "error": e }));
            std::process::exit(1);
        }
    }
}
