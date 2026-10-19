// Producer `args` helpers shared by the vectors: unwrapping a stringified
// args object, and the rate/audience binding of the logos and lez digests.

use serde_json::{Map, Value};

/// `rate_max` when `args` names none — the gifter's default rate.
pub const DEFAULT_RATE_MAX: u64 = 100;
/// Longest accepted `audience`, as for pow-claim.
pub const MAX_AUDIENCE_LEN: usize = 255;

/// `args` as an object: `None`, `null` and `""` are no args; a string holding
/// a JSON object (the membership module may stringify `auth_args`) is
/// unwrapped; anything else that is not an object is an error.
pub fn args_object(raw: Option<&Value>) -> Result<Option<Map<String, Value>>, String> {
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => {
            let inner: Value = serde_json::from_str(s).map_err(|e| format!("args: string is not valid JSON: {e}"))?;
            match inner {
                Value::Null => Ok(None),
                Value::Object(o) => Ok(Some(o)),
                other => Err(format!("args: expected JSON object, got {other}")),
            }
        }
        Some(Value::Object(o)) => Ok(Some(o.clone())),
        Some(v) => Err(format!("args: expected JSON object, got {v}")),
    }
}

/// What the logos and lez digests bind besides the commitment: the highest
/// rate the payload may be used for, and the gifter it is meant for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub rate_max: u64,
    pub audience: String,
}

impl Default for Binding {
    fn default() -> Self {
        Binding { rate_max: DEFAULT_RATE_MAX, audience: String::new() }
    }
}

impl Binding {
    /// `args.rate_max` (u64, default 100) and `args.audience` (string,
    /// default "", at most 255 bytes).
    pub fn from_object(o: Option<&Map<String, Value>>) -> Result<Binding, String> {
        let mut b = Binding::default();
        let Some(o) = o else { return Ok(b) };
        match o.get("rate_max") {
            None | Some(Value::Null) => {}
            Some(Value::Number(n)) => {
                b.rate_max = n.as_u64().ok_or_else(|| format!("rate_max: expected unsigned integer, got {n}"))?
            }
            Some(v) => return Err(format!("rate_max: expected unsigned integer, got {v}")),
        }
        match o.get("audience") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if s.len() <= MAX_AUDIENCE_LEN => b.audience = s.clone(),
            Some(Value::String(s)) => {
                return Err(format!("audience: at most {MAX_AUDIENCE_LEN} bytes, got {}", s.len()))
            }
            Some(v) => return Err(format!("audience: expected string, got {v}")),
        }
        Ok(b)
    }

    pub fn parse(raw: Option<&Value>) -> Result<Binding, String> {
        Binding::from_object(args_object(raw)?.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn args_object_unwraps_strings() {
        assert_eq!(args_object(None).unwrap(), None);
        assert_eq!(args_object(Some(&json!(null))).unwrap(), None);
        assert_eq!(args_object(Some(&json!(" "))).unwrap(), None);
        assert_eq!(args_object(Some(&json!("null"))).unwrap(), None);
        let o = args_object(Some(&json!("{\"private_key\":\"0x01\"}"))).unwrap().unwrap();
        assert_eq!(o["private_key"], "0x01");
        assert!(args_object(Some(&json!("[1]"))).unwrap_err().contains("expected JSON object"));
        assert!(args_object(Some(&json!("{"))).unwrap_err().contains("not valid JSON"));
        assert!(args_object(Some(&json!(7))).unwrap_err().contains("expected JSON object"));
    }

    #[test]
    fn binding_defaults_and_overrides() {
        assert_eq!(Binding::parse(None).unwrap(), Binding { rate_max: 100, audience: String::new() });
        let b = Binding::parse(Some(&json!({ "rate_max": 7, "audience": "poc" }))).unwrap();
        assert_eq!(b, Binding { rate_max: 7, audience: "poc".into() });
        let s = Binding::parse(Some(&json!("{\"rate_max\": 9}"))).unwrap();
        assert_eq!(s.rate_max, 9);
        assert!(Binding::parse(Some(&json!({ "rate_max": -1 }))).unwrap_err().starts_with("rate_max"));
        assert!(Binding::parse(Some(&json!({ "rate_max": "x" }))).unwrap_err().starts_with("rate_max"));
        assert!(Binding::parse(Some(&json!({ "audience": 1 }))).unwrap_err().starts_with("audience"));
        assert!(Binding::parse(Some(&json!({ "audience": "x".repeat(256) }))).is_err());
        assert!(Binding::parse(Some(&json!({ "audience": "x".repeat(255) }))).is_ok());
    }
}
