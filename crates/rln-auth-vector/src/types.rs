//! The wire shapes of the two module methods, and the caller-side parsers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical producer method name every vector module exposes.
pub const PRODUCE_METHOD: &str = "produce_auth";
/// Canonical verifier method name every vector module exposes.
pub const VERIFY_METHOD: &str = "verify_auth";

/// `produce_auth` input: make the `authentication_payload` for this
/// commitment. `args` is the caller's opaque extra material, forwarded
/// verbatim from the requesting application: the binding's `rate_max` and
/// `audience` ([`crate::Binding::from_produce`]) plus whatever the signer and
/// the claimant need (a node URL, a private key, a claim locator …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceRequest {
    pub auth_type: String,
    pub id_commitment_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
}

/// `produce_auth` output: the payload bytes, hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProduceReply {
    pub payload_hex: String,
}

/// `verify_auth` input. `config` is the gifter operator's opaque per-vector
/// configuration (an allowlist, trusted CAs, a node URL …), passed through
/// verbatim from the gifter's `authVerifiers` entry on every call — verifiers
/// stay stateless. `rate` is the rate the gifter settled on for this request.
/// `peer_id` is the requester's libp2p peer id as the transport authenticated
/// it (the gifter reads it from the accepted stream); schemes that sign
/// nothing prove their identity from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub auth_type: String,
    pub payload_hex: String,
    pub id_commitment_hex: String,
    #[serde(default)]
    pub rate: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
}

/// `verify_auth` output. A refusal is `ok: false` + `reason` — still a
/// successful verify call. Returning a `nullifier` (any stable lowercase
/// string identifying the spent credential) opts in to the gifter's shared
/// replay protection: reserved before the on-chain register, rolled back on
/// its failure, persisted on success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
}

impl Verdict {
    pub fn accept(nullifier: Option<String>) -> Self {
        Verdict {
            ok: true,
            reason: None,
            nullifier,
        }
    }
    pub fn reject(reason: impl Into<String>) -> Self {
        Verdict {
            ok: false,
            reason: Some(reason.into()),
            nullifier: None,
        }
    }
}

/// The key the gifter persists a spent credential under: one namespace per
/// registry and auth type, so a credential buys one membership per registry
/// and two vectors with the same nullifier form never collide.
pub fn namespaced_nullifier(registry: &str, auth_type: &str, nullifier: &str) -> String {
    format!("{registry}:{auth_type}:{nullifier}")
}

pub(crate) fn error_reply(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

/// Parse a producer module's reply (the caller side of [`PRODUCE_METHOD`]),
/// surfacing the `{"error"}` envelope as `Err`.
pub fn parse_produce_reply(reply: &Value) -> Result<ProduceReply, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    serde_json::from_value(reply.clone()).map_err(|e| format!("produce_auth reply: {e}"))
}

/// Parse a verifier module's reply (the caller side of [`VERIFY_METHOD`]),
/// surfacing the `{"error"}` envelope as `Err`.
pub fn parse_verdict(reply: &Value) -> Result<Verdict, String> {
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_string());
    }
    serde_json::from_value(reply.clone()).map_err(|e| format!("verify_auth reply: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_parsers_surface_the_error_envelope() {
        let ok = serde_json::json!({ "payload_hex": "aa" });
        assert_eq!(parse_produce_reply(&ok).unwrap().payload_hex, "aa");
        let err = serde_json::json!({ "error": "boom" });
        assert_eq!(parse_produce_reply(&err).unwrap_err(), "boom");

        let verdict = serde_json::json!({ "ok": true, "nullifier": "n" });
        assert_eq!(
            parse_verdict(&verdict).unwrap().nullifier.as_deref(),
            Some("n")
        );
        assert_eq!(parse_verdict(&err).unwrap_err(), "boom");
    }

    #[test]
    fn request_shapes_round_trip_with_optional_fields_omitted() {
        let req = VerifyRequest {
            auth_type: "t-a".into(),
            payload_hex: "aa".into(),
            id_commitment_hex: "bb".into(),
            rate: 0,
            config: None,
            peer_id: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("config").is_none(), "unset config must be omitted");
        assert!(v.get("peer_id").is_none(), "unset peer_id must be omitted");
        let back: VerifyRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back.auth_type, "t-a");

        // Older callers omitting `rate` still parse (serde default).
        let min = serde_json::json!({
            "auth_type": "t-a", "payload_hex": "aa", "id_commitment_hex": "bb"
        });
        let back: VerifyRequest = serde_json::from_value(min).unwrap();
        assert_eq!(back.rate, 0);
    }

    #[test]
    fn nullifiers_are_namespaced_by_registry_and_auth_type() {
        assert_eq!(
            namespaced_nullifier("cfg1", "eth-allowlist", "0xab"),
            "cfg1:eth-allowlist:0xab"
        );
    }
}
