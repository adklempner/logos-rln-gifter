//! [`NodeApi`] over the node's HTTP API (plain http to localhost, ureq 2
//! without TLS).

use std::time::Duration;

use serde_json::Value;

use crate::node::NodeApi;

/// Minimum timeout for `/wallet/sign/zk` (proving takes ~15 s).
pub const SIGN_MIN_TIMEOUT_MS: u64 = 60_000;

pub struct HttpNode {
    pub base: String,
    pub timeout_ms: u64,
}

impl HttpNode {
    pub fn new(base: &str, timeout_ms: u64) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            timeout_ms,
        }
    }

    fn agent(&self, timeout_ms: u64) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
    }

    fn finish(method: &str, path: &str, r: Result<ureq::Response, ureq::Error>) -> Result<Option<Value>, String> {
        match r {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|e| format!("node {method} {path}: reading body: {e}"))?;
                serde_json::from_str(&body)
                    .map(Some)
                    .map_err(|e| format!("node {method} {path}: invalid JSON: {e}: {body}"))
            }
            Err(ureq::Error::Status(404, _)) if method == "GET" => Ok(None),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("node {method} {path}: HTTP {code} {}", body.trim()))
            }
            Err(e) => Err(format!("node {method} {path}: {e}")),
        }
    }

    fn get(&self, path: &str) -> Result<Option<Value>, String> {
        let r = self.agent(self.timeout_ms).get(&format!("{}{path}", self.base)).call();
        Self::finish("GET", path, r)
    }

    fn get_some(&self, path: &str) -> Result<Value, String> {
        self.get(path)?
            .ok_or_else(|| format!("node GET {path}: HTTP 404"))
    }
}

fn as_array(path: &str, v: Value) -> Result<Vec<Value>, String> {
    match v {
        Value::Array(a) => Ok(a),
        Value::Null => Ok(Vec::new()),
        other => Err(format!("node GET {path}: expected array, got {other}")),
    }
}

impl NodeApi for HttpNode {
    fn pow_status(&self) -> Result<Value, String> {
        self.get_some("/pow/status")
    }

    fn info(&self) -> Result<Value, String> {
        self.get_some("/cryptarchia/info")
    }

    fn block(&self, id_hex: &str) -> Result<Option<Value>, String> {
        self.get(&format!("/cryptarchia/blocks/{id_hex}"))
    }

    fn immutable_blocks(&self, slot_from: u64, slot_to: u64) -> Result<Vec<Value>, String> {
        let path = format!("/cryptarchia/blocks?slot_from={slot_from}&slot_to={slot_to}");
        as_array(&path, self.get_some(&path)?)
    }

    fn events(&self, id_hex: &str) -> Result<Vec<Value>, String> {
        let path = format!("/cryptarchia/blocks/{id_hex}/events");
        as_array(&path, self.get_some(&path)?)
    }

    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<Value, String> {
        let path = "/wallet/sign/zk";
        let body = serde_json::json!({ "tx_hash": hex::encode(digest), "pks": [pk_hex] });
        let r = self
            .agent(self.timeout_ms.max(SIGN_MIN_TIMEOUT_MS))
            .post(&format!("{}{path}", self.base))
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        Self::finish("POST", path, r)?
            .ok_or_else(|| format!("node POST {path}: empty reply"))
    }
}
