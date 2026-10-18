// logos-allowlist PRODUCER for gifted RLN registration — the client-side half
// of the logos auth vector (the verifier half is logos-auth-module). It asks a
// local logos-blockchain node to zkSign `sha256(DOMAIN || id_commitment)` with
// one of the node's KMS keys (`POST /wallet/sign/zk`), so the key never
// leaves the node. The allocator operator allowlists that key K (32-byte LE
// Fr hex, as `/pow/status` shows it) once.
// FEATURE: RLN gifter logos-allowlist auth vector (produce)

use rln_auth_vector::{dispatch_produce, AuthVector, ProduceReply, ProduceRequest};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use zksign_light::{hex32_bytes, norm_hex32};

pub trait LogosSignModule: Send + 'static {
    /// rln_auth_vector PRODUCE_METHOD for auth_type "logos-allowlist". One
    /// JSON-string arg (ProduceRequest; `args`:
    /// `{"node_url"?,"public_key"?,"http_timeout_ms"?}`) → `{"payload_hex"}`:
    /// `K(32) || zksig(128)` (160 bytes), the node's zkSign by K over
    /// `sha256("logos/rln/logos-sign/1" || id_commitment)`. K is
    /// `args.public_key`, else the node's single `/pow/status` auto-claim
    /// target. `{"error"}` on a malformed request or node failure.
    fn produce_auth(&mut self, args_json: String) -> String;
    /// The key `produce_auth` would sign with for these args (same shape as
    /// ProduceRequest.args; "" or "{}" for defaults) — what an allocator
    /// operator allowlists. `{"public_key","source":"args"|"pow_status"}` or
    /// `{"error"}`.
    fn public_key(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

#[cfg(not(test))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

// The unit tests never cross the C ABI; they only need the context shape.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct RustModuleContext {
    pub module_path: String,
    pub instance_id: String,
    pub instance_persistence_path: String,
}

pub const LOGOS_ALLOWLIST_AUTH_TYPE: &str = "logos-allowlist";
/// Domain of the signed digest; must match logos-auth-module's.
pub const DOMAIN: &[u8] = b"logos/rln/logos-sign/1";
pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:8080";
/// Timeout for `/pow/status`; signing always gets at least
/// `zksign_light::SIGN_MIN_TIMEOUT_MS`.
pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 8000;

/// The 32 bytes the node signs: `sha256(DOMAIN || id_commitment)`.
pub fn digest(id_commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.finalize().into()
}

/// The node operations the producer needs (seam for tests).
pub trait ZkNode {
    fn pow_status(&self) -> Result<Value, String>;
    /// zkSign of `digest` by the node-held key `pk_hex` → `pi_a‖pi_b‖pi_c`.
    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String>;
}

pub struct HttpZkNode {
    pub url: String,
    pub timeout_ms: u64,
}

impl ZkNode for HttpZkNode {
    fn pow_status(&self) -> Result<Value, String> {
        zksign_light::pow_status(&self.url, self.timeout_ms)
    }
    fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
        zksign_light::sign_zk(&self.url, digest, pk_hex, self.timeout_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub node_url: String,
    pub public_key: Option<String>,
    pub http_timeout_ms: u64,
}

impl Default for Args {
    fn default() -> Self {
        Args { node_url: DEFAULT_NODE_URL.into(), public_key: None, http_timeout_ms: DEFAULT_HTTP_TIMEOUT_MS }
    }
}

impl Args {
    /// `None`, `null`, `""`, an object, or a string holding a JSON object (the
    /// membership module may stringify `auth_args`).
    pub fn parse(raw: Option<&Value>) -> Result<Args, String> {
        let v = match raw {
            None | Some(Value::Null) => return Ok(Args::default()),
            Some(Value::String(s)) if s.trim().is_empty() => return Ok(Args::default()),
            Some(Value::String(s)) => {
                let inner: Value = serde_json::from_str(s).map_err(|e| format!("args: string is not valid JSON: {e}"))?;
                if !inner.is_object() && !inner.is_null() {
                    return Err(format!("args: expected JSON object, got {inner}"));
                }
                return Args::parse(Some(&inner));
            }
            Some(v) => v,
        };
        let o = v.as_object().ok_or_else(|| format!("args: expected JSON object, got {v}"))?;
        let mut a = Args::default();
        match o.get("node_url") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if !s.trim().is_empty() => a.node_url = s.trim().trim_end_matches('/').to_string(),
            Some(Value::String(_)) => {}
            Some(v) => return Err(format!("node_url: expected string, got {v}")),
        }
        match o.get("public_key") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => a.public_key = Some(norm_hex32("public_key", s)?),
            Some(v) => return Err(format!("public_key: expected string, got {v}")),
        }
        match o.get("http_timeout_ms") {
            None | Some(Value::Null) => {}
            Some(Value::Number(n)) => {
                a.http_timeout_ms = n.as_u64().ok_or_else(|| format!("http_timeout_ms: expected unsigned integer, got {n}"))?
            }
            Some(v) => return Err(format!("http_timeout_ms: expected unsigned integer, got {v}")),
        }
        Ok(a)
    }

    fn node(&self) -> HttpZkNode {
        HttpZkNode { url: self.node_url.clone(), timeout_ms: self.http_timeout_ms }
    }
}

/// K and where it came from: `args.public_key`, else the node's single
/// `/pow/status` auto-claim target.
pub fn resolve_key(node: &dyn ZkNode, args: &Args) -> Result<(String, &'static str), String> {
    if let Some(k) = &args.public_key {
        return Ok((k.clone(), "args"));
    }
    let st = node.pow_status()?;
    let targets = st
        .pointer("/auto_claim/targets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    match targets {
        [t] => {
            let k = t["public_key"]
                .as_str()
                .ok_or("/pow/status: auto_claim.targets[0].public_key missing")?;
            Ok((norm_hex32("/pow/status public_key", k)?, "pow_status"))
        }
        [] => Err(format!(
            "node {} reports no /pow/status auto-claim target; set args.public_key to a node key",
            args.node_url
        )),
        many => Err(format!(
            "node {} reports {} /pow/status auto-claim targets; set args.public_key to choose one",
            args.node_url,
            many.len()
        )),
    }
}

/// `hex(K || zksig)` for `id_commitment_hex`.
pub fn produce(node: &dyn ZkNode, id_commitment_hex: &str, args: &Args) -> Result<String, String> {
    let idc = hex32_bytes("id_commitment_hex", id_commitment_hex)
        .map_err(|_| format!("id_commitment must be 32 bytes (64 hex), got {id_commitment_hex:?}"))?;
    let (k_hex, _) = resolve_key(node, args)?;
    let k = hex32_bytes("public_key", &k_hex)?;
    let sig = node.sign_zk(&digest(&idc), &k_hex)?;
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(&k);
    out.extend_from_slice(&sig);
    Ok(hex::encode(out))
}

/// One produce call's vector; `node` overrides the http node (tests).
struct LogosSignVector<'a> {
    node: Option<&'a dyn ZkNode>,
}

impl AuthVector for LogosSignVector<'_> {
    fn auth_type(&self) -> &'static str {
        LOGOS_ALLOWLIST_AUTH_TYPE
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        let args = Args::parse(req.args.as_ref())?;
        let http;
        let node: &dyn ZkNode = match self.node {
            Some(n) => n,
            None => {
                http = args.node();
                &http
            }
        };
        Ok(ProduceReply { payload_hex: produce(node, &req.id_commitment_hex, &args)? })
    }
}

fn public_key_with(node: Option<&dyn ZkNode>, args_json: &str) -> Result<String, String> {
    let raw = Value::String(args_json.to_string());
    let args = Args::parse(Some(&raw))?;
    let http;
    let node: &dyn ZkNode = match node {
        Some(n) => n,
        None => {
            http = args.node();
            &http
        }
    };
    let (k, source) = resolve_key(node, &args)?;
    Ok(json!({ "public_key": k, "source": source }).to_string())
}

fn error_json(e: String) -> String {
    json!({ "error": e }).to_string()
}

#[derive(Default)]
struct LogosSign {}

impl LogosSignModule for LogosSign {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn produce_auth(&mut self, args_json: String) -> String {
        dispatch_produce(&args_json, &[&LogosSignVector { node: None }])
    }
    fn public_key(&mut self, args_json: String) -> String {
        public_key_with(None, &args_json).unwrap_or_else(error_json)
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LogosSign>();
}

#[cfg(test)]
mod real_node_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const K: &str = "e2c2755d57430e8548315b5a65fddf8fb34e9d2393cac26c80b1ff097a35ea08";
    const K2: &str = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07";
    const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    struct FakeNode {
        targets: Vec<&'static str>,
        /// Request bodies the node would have received on /wallet/sign/zk.
        signed: RefCell<Vec<Value>>,
    }

    impl FakeNode {
        fn new(targets: Vec<&'static str>) -> Self {
            FakeNode { targets, signed: RefCell::new(Vec::new()) }
        }
    }

    impl ZkNode for FakeNode {
        fn pow_status(&self) -> Result<Value, String> {
            let t: Vec<Value> = self.targets.iter().map(|k| json!({ "public_key": k, "threshold": 1, "balance": 0 })).collect();
            Ok(json!({ "auto_claim": { "is_armed": true, "targets": t } }))
        }
        fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
            self.signed.borrow_mut().push(zksign_light::client::sign_zk_body(digest, pk_hex));
            Ok([0x5a; 128])
        }
    }

    fn req(idc: &str, args: Option<Value>) -> String {
        let mut v = json!({ "auth_type": LOGOS_ALLOWLIST_AUTH_TYPE, "id_commitment_hex": idc });
        if let Some(a) = args {
            v["args"] = a;
        }
        v.to_string()
    }

    fn run(node: &FakeNode, args_json: &str) -> Value {
        serde_json::from_str(&dispatch_produce(args_json, &[&LogosSignVector { node: Some(node) }])).unwrap()
    }

    fn expected_tx_hash(idc_hex: &str) -> String {
        let mut buf = DOMAIN.to_vec();
        buf.extend_from_slice(&hex::decode(idc_hex).unwrap());
        hex::encode(Sha256::digest(&buf))
    }

    #[test]
    fn signs_domain_digest_with_the_single_pow_target() {
        let node = FakeNode::new(vec![K]);
        let reply = run(&node, &req(IDC, None));
        let payload = reply["payload_hex"].as_str().unwrap_or_else(|| panic!("{reply}"));
        assert_eq!(payload.len(), 320);
        assert_eq!(&payload[..64], K);
        assert_eq!(&payload[64..], "5a".repeat(128));
        let signed = node.signed.borrow();
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0]["tx_hash"], expected_tx_hash(IDC));
        assert_eq!(signed[0]["pks"], json!([K]));
    }

    #[test]
    fn args_public_key_wins_and_is_normalised() {
        let node = FakeNode::new(vec![]);
        let pk = format!("0x{}", K2.to_uppercase());
        // Stringified args, as the membership module may send them.
        let args = Value::String(json!({ "public_key": pk }).to_string());
        let reply = run(&node, &req(&IDC.to_uppercase(), Some(args)));
        assert_eq!(&reply["payload_hex"].as_str().unwrap()[..64], K2);
        assert_eq!(node.signed.borrow()[0]["pks"], json!([K2]));
        assert_eq!(node.signed.borrow()[0]["tx_hash"], expected_tx_hash(IDC));
    }

    #[test]
    fn zero_or_many_targets_ask_for_public_key() {
        for targets in [vec![], vec![K, K2]] {
            let node = FakeNode::new(targets);
            let reply = run(&node, &req(IDC, None));
            let e = reply["error"].as_str().unwrap_or_else(|| panic!("{reply}"));
            assert!(e.contains("args.public_key"), "{e}");
            assert!(node.signed.borrow().is_empty());
        }
    }

    #[test]
    fn malformed_requests_are_errors() {
        let node = FakeNode::new(vec![K]);
        assert!(run(&node, &req("abcd", None))["error"].as_str().unwrap().contains("32 bytes"));
        let e = run(&node, &req(IDC, Some(json!({ "public_key": "zz" }))));
        assert!(e["error"].as_str().unwrap().starts_with("public_key"), "{e}");
        let e = run(&node, &req(IDC, Some(json!([1]))));
        assert!(e["error"].as_str().unwrap().contains("expected JSON object"), "{e}");
        let e = run(&node, &json!({ "auth_type": "eth-allowlist", "id_commitment_hex": IDC }).to_string());
        assert!(e["error"].as_str().unwrap().contains("unknown auth_type"), "{e}");
        assert!(node.signed.borrow().is_empty());
    }

    #[test]
    fn public_key_reports_source() {
        let node = FakeNode::new(vec![K]);
        let v: Value = serde_json::from_str(&public_key_with(Some(&node), "").unwrap()).unwrap();
        assert_eq!(v, json!({ "public_key": K, "source": "pow_status" }));
        let v: Value =
            serde_json::from_str(&public_key_with(Some(&node), &json!({ "public_key": K2 }).to_string()).unwrap()).unwrap();
        assert_eq!(v, json!({ "public_key": K2, "source": "args" }));
        assert!(public_key_with(Some(&FakeNode::new(vec![])), "{}").unwrap_err().contains("no /pow/status"));
    }

    #[test]
    fn args_defaults_and_overrides() {
        assert_eq!(Args::parse(None).unwrap(), Args::default());
        assert_eq!(Args::parse(Some(&json!(""))).unwrap(), Args::default());
        let a = Args::parse(Some(&json!({ "node_url": "http://127.0.0.1:18080/", "http_timeout_ms": 5 }))).unwrap();
        assert_eq!(a.node_url, "http://127.0.0.1:18080");
        assert_eq!(a.http_timeout_ms, 5);
        assert!(Args::parse(Some(&json!({ "http_timeout_ms": -1 }))).is_err());
    }

    #[test]
    fn unreachable_node_is_an_error() {
        let mut m = LogosSign::default();
        let e = m.public_key(json!({ "node_url": "http://127.0.0.1:1", "http_timeout_ms": 500 }).to_string());
        assert!(e.contains("\"error\"") && e.contains("/pow/status"), "{e}");
    }
}
