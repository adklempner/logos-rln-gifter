//! Plain-http client for a local logos-blockchain node (ureq 2 without TLS):
//! `/pow/status` and `/wallet/sign/zk`.

use std::time::Duration;

use serde_json::Value;

/// Minimum timeout for `/wallet/sign/zk`. Proving was observed at ~80 ms–1 s
/// on a local node; the floor leaves room for a loaded or slow host.
pub const SIGN_MIN_TIMEOUT_MS: u64 = 60_000;

/// Appended to an HTTP 404 from the PoW / zkSign routes.
pub const OLD_NODE_HINT: &str = "node predates the PoW routes (0.3.0-rc.5 or later required)";

fn agent(timeout_ms: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
}

fn base(url: &str) -> &str {
    url.trim().trim_end_matches('/')
}

fn finish(method: &str, path: &str, r: Result<ureq::Response, ureq::Error>) -> Result<Value, String> {
    match r {
        Ok(resp) => {
            let body = resp
                .into_string()
                .map_err(|e| format!("node {method} {path}: reading body: {e}"))?;
            serde_json::from_str(&body).map_err(|e| format!("node {method} {path}: invalid JSON: {e}: {body}"))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(status_error(method, path, code, body.trim()))
        }
        Err(e) => Err(format!("node {method} {path}: {e}")),
    }
}

fn status_error(method: &str, path: &str, code: u16, body: &str) -> String {
    let mut e = format!("node {method} {path}: HTTP {code} {body}");
    if code == 404 {
        e = format!("{} ({OLD_NODE_HINT})", e.trim_end());
    }
    e
}

/// `GET <url>/pow/status` as JSON.
pub fn pow_status(url: &str, timeout_ms: u64) -> Result<Value, String> {
    let path = "/pow/status";
    let r = agent(timeout_ms).get(&format!("{}{path}", base(url))).call();
    finish("GET", path, r)
}

/// The `{"tx_hash","pks"}` request body for a single-key zkSign: `pk_hex`
/// alone in slot 0 (the node fills the rest with the zero key).
pub fn sign_zk_body(digest: &[u8; 32], pk_hex: &str) -> Value {
    serde_json::json!({ "tx_hash": hex::encode(digest), "pks": [pk_hex] })
}

/// `POST <url>/wallet/sign/zk` signing `digest` (raw 32 bytes, reduced mod p
/// by the node) with the node-held key `pk_hex`; returns `pi_a‖pi_b‖pi_c`.
/// `pk_hex` is normalised with [`crate::norm_hex32`] first. The timeout is
/// at least [`SIGN_MIN_TIMEOUT_MS`].
pub fn sign_zk(url: &str, digest: &[u8; 32], pk_hex: &str, timeout_ms: u64) -> Result<[u8; 128], String> {
    let pk = crate::norm_hex32("pk", pk_hex)?;
    let path = "/wallet/sign/zk";
    let r = agent(timeout_ms.max(SIGN_MIN_TIMEOUT_MS))
        .post(&format!("{}{path}", base(url)))
        .set("Content-Type", "application/json")
        .send_string(&sign_zk_body(digest, &pk).to_string());
    parse_sig_reply(&finish("POST", path, r)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply(a: usize, b: usize, c: usize) -> Value {
        json!({"sig": {"pi_a": "aa".repeat(a), "pi_b": "bb".repeat(b), "pi_c": "cc".repeat(c)}})
    }

    #[test]
    fn sig_reply_concatenates_parts() {
        let s = parse_sig_reply(&reply(32, 64, 32)).unwrap();
        assert!(s[..32].iter().all(|&x| x == 0xaa));
        assert!(s[32..96].iter().all(|&x| x == 0xbb));
        assert!(s[96..].iter().all(|&x| x == 0xcc));
        let pre = json!({"sig": {"pi_a": format!("0x{}", "aa".repeat(32)), "pi_b": "bb".repeat(64), "pi_c": "cc".repeat(32)}});
        assert_eq!(parse_sig_reply(&pre).unwrap(), s);
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

    #[test]
    fn sign_body_puts_the_key_alone_in_slot_zero() {
        let b = sign_zk_body(&[0xab; 32], "k1");
        assert_eq!(b, json!({"tx_hash": "ab".repeat(32), "pks": ["k1"]}));
    }

    #[test]
    fn http_404_carries_the_old_node_hint() {
        let e = status_error("POST", "/wallet/sign/zk", 404, "");
        assert_eq!(e, format!("node POST /wallet/sign/zk: HTTP 404 ({OLD_NODE_HINT})"));
        let e = status_error("GET", "/pow/status", 500, "boom");
        assert_eq!(e, "node GET /pow/status: HTTP 500 boom");
    }

    #[test]
    fn sign_zk_rejects_a_malformed_key_before_any_request() {
        let e = sign_zk("http://127.0.0.1:1", &[0; 32], "zz", 500).unwrap_err();
        assert!(e.starts_with("pk:"), "{e}");
    }

    #[test]
    fn unreachable_node_is_an_error() {
        let e = pow_status("http://127.0.0.1:1", 500).unwrap_err();
        assert!(e.starts_with("node GET /pow/status"), "{e}");
    }
}
