//! [`NodeApi`] over the node's HTTP API (plain http to localhost, ureq 2
//! without TLS). The PoW/zkSign routes come from `zksign_light`; the chain
//! reads are this crate's own.

use std::time::Duration;

use serde_json::Value;

use crate::node::NodeApi;

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

    fn agent(&self) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
    }

    fn finish(path: &str, r: Result<ureq::Response, ureq::Error>) -> Result<Option<Value>, String> {
        match r {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|e| format!("node GET {path}: reading body: {e}"))?;
                serde_json::from_str(&body)
                    .map(Some)
                    .map_err(|e| format!("node GET {path}: invalid JSON: {e}: {body}"))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(format!("node GET {path}: HTTP {code} {}", body.trim()))
            }
            Err(e) => Err(format!("node GET {path}: {e}")),
        }
    }

    fn get(&self, path: &str) -> Result<Option<Value>, String> {
        let r = self.agent().get(&format!("{}{path}", self.base)).call();
        Self::finish(path, r)
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
        zksign_light::pow_status(&self.base, self.timeout_ms)
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

    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
        zksign_light::sign_zk(&self.base, digest, pk_hex, self.timeout_ms)
    }
}
