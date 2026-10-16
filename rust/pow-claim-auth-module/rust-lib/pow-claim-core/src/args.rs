//! `ProduceRequest.args` parsing (§4.2 plus PoC extras).

use serde_json::Value;

pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:8080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProduceArgs {
    pub node_url: String,
    pub audience: String,
    pub rate_max: u64,
    pub claim_block_id: Option<String>,
    pub pow_nullifier: Option<String>,
    pub spend_block_id: Option<String>,
    pub spend_tx_hash: Option<String>,
    pub exclude_nullifiers: Vec<String>,
    /// PoC: use this K instead of `/pow/status` auto-claim targets.
    pub claim_address: Option<String>,
    /// PoC: also walk non-final blocks back from the tip.
    pub allow_unfinal: bool,
    pub scan_window_slots: u64,
    pub scan_depth_blocks: u64,
    pub http_timeout_ms: u64,
}

impl Default for ProduceArgs {
    fn default() -> Self {
        Self {
            node_url: DEFAULT_NODE_URL.to_string(),
            audience: String::new(),
            rate_max: 100,
            claim_block_id: None,
            pow_nullifier: None,
            spend_block_id: None,
            spend_tx_hash: None,
            exclude_nullifiers: Vec::new(),
            claim_address: None,
            allow_unfinal: false,
            scan_window_slots: 3000,
            scan_depth_blocks: 300,
            http_timeout_ms: 8000,
        }
    }
}

/// Normalise a 32-byte hex field: strip optional `0x`, lowercase, require
/// exactly 64 hex chars.
pub fn norm_hex32(field: &str, s: &str) -> Result<String, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t)
        .to_ascii_lowercase();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{field}: expected 64 hex chars (32 bytes), got {s:?}"));
    }
    Ok(t)
}

pub fn hex32_bytes(field: &str, s: &str) -> Result<[u8; 32], String> {
    let h = norm_hex32(field, s)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(&h, &mut out).map_err(|e| format!("{field}: {e}"))?;
    Ok(out)
}

fn opt_str(o: &serde_json::Map<String, Value>, k: &str) -> Result<Option<String>, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(v) => Err(format!("{k}: expected string, got {v}")),
    }
}

fn opt_hex(o: &serde_json::Map<String, Value>, k: &str) -> Result<Option<String>, String> {
    opt_str(o, k)?.map(|s| norm_hex32(k, &s)).transpose()
}

fn opt_u64(o: &serde_json::Map<String, Value>, k: &str, d: u64) -> Result<u64, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(d),
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| format!("{k}: expected unsigned integer, got {n}")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("{k}: expected unsigned integer, got {s:?}")),
        Some(v) => Err(format!("{k}: expected unsigned integer, got {v}")),
    }
}

fn opt_bool(o: &serde_json::Map<String, Value>, k: &str, d: bool) -> Result<bool, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(d),
        Some(Value::Bool(b)) => Ok(*b),
        Some(v) => Err(format!("{k}: expected bool, got {v}")),
    }
}

impl ProduceArgs {
    /// Accepts `None`, a JSON object, or a JSON string containing JSON (the
    /// RLN membership module may stringify `auth_args`). An empty string or
    /// `null` means defaults.
    pub fn parse(raw: Option<&Value>) -> Result<ProduceArgs, String> {
        let owned;
        let v = match raw {
            None | Some(Value::Null) => return Ok(Self::default()),
            Some(Value::String(s)) => {
                if s.trim().is_empty() {
                    return Ok(Self::default());
                }
                owned = serde_json::from_str::<Value>(s)
                    .map_err(|e| format!("args: string is not valid JSON: {e}"))?;
                if let Value::String(_) = owned {
                    return Err("args: doubly-stringified JSON is not accepted".into());
                }
                return Self::parse(Some(&owned));
            }
            Some(v) => v,
        };
        let o = v
            .as_object()
            .ok_or_else(|| format!("args: expected JSON object, got {v}"))?;
        let d = Self::default();
        let node_url = opt_str(o, "node_url")?
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(d.node_url);
        let audience = opt_str(o, "audience")?.unwrap_or_default();
        if audience.len() > 255 {
            return Err(format!("audience: at most 255 bytes, got {}", audience.len()));
        }
        let exclude_nullifiers = match o.get("exclude_nullifiers") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| {
                    x.as_str()
                        .ok_or_else(|| format!("exclude_nullifiers: expected string, got {x}"))
                        .and_then(|s| norm_hex32("exclude_nullifiers", s))
                })
                .collect::<Result<_, _>>()?,
            Some(v) => return Err(format!("exclude_nullifiers: expected array, got {v}")),
        };
        Ok(ProduceArgs {
            node_url,
            audience,
            rate_max: opt_u64(o, "rate_max", d.rate_max)?,
            claim_block_id: opt_hex(o, "claim_block_id")?,
            pow_nullifier: opt_hex(o, "pow_nullifier")?,
            spend_block_id: opt_hex(o, "spend_block_id")?,
            spend_tx_hash: opt_hex(o, "spend_tx_hash")?,
            exclude_nullifiers,
            claim_address: opt_hex(o, "claim_address")?,
            allow_unfinal: opt_bool(o, "allow_unfinal", d.allow_unfinal)?,
            scan_window_slots: opt_u64(o, "scan_window_slots", d.scan_window_slots)?,
            scan_depth_blocks: opt_u64(o, "scan_depth_blocks", d.scan_depth_blocks)?,
            http_timeout_ms: opt_u64(o, "http_timeout_ms", d.http_timeout_ms)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_and_null_give_defaults() {
        assert_eq!(ProduceArgs::parse(None).unwrap(), ProduceArgs::default());
        assert_eq!(ProduceArgs::parse(Some(&Value::Null)).unwrap(), ProduceArgs::default());
        assert_eq!(ProduceArgs::parse(Some(&json!(""))).unwrap(), ProduceArgs::default());
        let d = ProduceArgs::default();
        assert_eq!(d.node_url, "http://127.0.0.1:8080");
        assert_eq!(d.rate_max, 100);
    }

    #[test]
    fn object_and_string_parse_identically() {
        let obj = json!({
            "node_url": "http://127.0.0.1:18080/",
            "audience": "poc",
            "rate_max": 7,
            "claim_address": "0X".to_string() + &"AB".repeat(32),
            "exclude_nullifiers": ["0x".to_string() + &"cd".repeat(32)],
            "allow_unfinal": true
        });
        let a = ProduceArgs::parse(Some(&obj)).unwrap();
        let s = ProduceArgs::parse(Some(&Value::String(obj.to_string()))).unwrap();
        assert_eq!(a, s);
        assert_eq!(a.node_url, "http://127.0.0.1:18080");
        assert_eq!(a.audience, "poc");
        assert_eq!(a.rate_max, 7);
        assert_eq!(a.claim_address.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(a.exclude_nullifiers, vec!["cd".repeat(32)]);
        assert!(a.allow_unfinal);
        assert_eq!(a.scan_window_slots, 3000);
    }

    #[test]
    fn hex_validation_names_field() {
        for f in ["claim_block_id", "pow_nullifier", "spend_block_id", "spend_tx_hash", "claim_address"] {
            let e = ProduceArgs::parse(Some(&json!({ f: "abc" }))).unwrap_err();
            assert!(e.starts_with(f), "{e}");
            let e = ProduceArgs::parse(Some(&json!({ f: "zz".repeat(32) }))).unwrap_err();
            assert!(e.starts_with(f), "{e}");
        }
        let e = ProduceArgs::parse(Some(&json!({"exclude_nullifiers": ["00"]}))).unwrap_err();
        assert!(e.starts_with("exclude_nullifiers"), "{e}");
    }

    #[test]
    fn rejects_bad_shapes() {
        assert!(ProduceArgs::parse(Some(&json!([1]))).is_err());
        assert!(ProduceArgs::parse(Some(&json!("not json"))).is_err());
        assert!(ProduceArgs::parse(Some(&json!({"rate_max": -1}))).is_err());
        assert!(ProduceArgs::parse(Some(&json!({"audience": "x".repeat(256)}))).is_err());
        assert!(ProduceArgs::parse(Some(&json!({"audience": "x".repeat(255)}))).is_ok());
    }
}
