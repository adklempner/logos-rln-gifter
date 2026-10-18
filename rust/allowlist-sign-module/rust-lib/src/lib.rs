// Allowlist PRODUCERS for gifted RLN registration — the client-side half of
// the three allowlist auth vectors in one module (the verifier half is
// allowlist-auth-module), so a membership module can drive any of them
// through `auth_provider` without a wallet in the loop:
//   eth-allowlist   EIP-191 by a module-owned secp256k1 key   (eth.rs)
//   lez-allowlist   BIP-340 by a module-owned LEZ account key (lez.rs)
//   logos-allowlist zkSign by a logos-blockchain node key     (logos.rs)
// `identity` reports what the allocator operator allowlists for each.
//
// Key custody (eth, lez) is demo-grade on purpose: each key is a plaintext
// hex file under the module's host-stamped persistence path (0600). Hosts
// that stamp no path (logos-standalone-app) get in-memory keys that change
// per run. The logos key never leaves the node's KMS.
// FEATURE: RLN gifter allowlist auth vectors (produce)

use k256::ecdsa::SigningKey;
use rln_auth_vector::dispatch_produce;
use serde_json::{json, Value};

pub mod eth;
pub mod lez;
pub mod logos;

use eth::{EthSignVector, ETH_ALLOWLIST_AUTH_TYPE};
use lez::{LezKey, LezSignVector, LEZ_ALLOWLIST_AUTH_TYPE};
use logos::{LogosSignVector, ZkNode, LOGOS_ALLOWLIST_AUTH_TYPE};

pub trait AllowlistSignModule: Send + 'static {
    /// rln_auth_vector PRODUCE_METHOD for auth_type "eth-allowlist",
    /// "lez-allowlist" and "logos-allowlist". One JSON-string arg
    /// (ProduceRequest) → `{"payload_hex"}` or `{"error"}`. eth and lez sign
    /// with the module key of that type unless `args.private_key` (hex,
    /// optional 0x) names another one; logos asks the node (`args`:
    /// `{"node_url"?,"public_key"?,"http_timeout_ms"?}`).
    fn produce_auth(&mut self, args_json: String) -> String;
    /// What an allocator operator allowlists for one auth type.
    /// `{"auth_type","args"?}` → `{"auth_type","id","persisted"}` plus
    /// `"id_base58"` (lez) or `"source"` (logos; `args` as for produce).
    /// Generates and persists the eth/lez module key on first use.
    fn identity(&mut self, req_json: String) -> String;
    /// Replace the eth or lez module key and persist it.
    /// `{"auth_type","private_key"}` → the identity object, or `{"error"}`
    /// (logos-allowlist keys live in the node's KMS).
    fn import_key(&mut self, req_json: String) -> String;
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

const ETH_KEY_FILE: &str = "eth_sign_key.hex";
const LEZ_KEY_FILE: &str = "lez_sign_key.hex";
const LOGOS_IMPORT_REFUSAL: &str = "logos-allowlist keys live in the node's KMS; nothing to import";

/// A module-owned key type the custody code persists as one hex line.
trait ModuleKey: Clone + Sized {
    const FILE: &'static str;
    const AUTH_TYPE: &'static str;
    fn parse(hex_str: &str) -> Result<Self, String>;
    fn random() -> Self;
    fn to_hex(&self) -> String;
}

impl ModuleKey for SigningKey {
    const FILE: &'static str = ETH_KEY_FILE;
    const AUTH_TYPE: &'static str = ETH_ALLOWLIST_AUTH_TYPE;
    fn parse(hex_str: &str) -> Result<Self, String> {
        eth::parse_key(hex_str)
    }
    fn random() -> Self {
        SigningKey::random(&mut rand_core::OsRng)
    }
    fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl ModuleKey for LezKey {
    const FILE: &'static str = LEZ_KEY_FILE;
    const AUTH_TYPE: &'static str = LEZ_ALLOWLIST_AUTH_TYPE;
    fn parse(hex_str: &str) -> Result<Self, String> {
        LezKey::parse(hex_str)
    }
    fn random() -> Self {
        LezKey::random()
    }
    fn to_hex(&self) -> String {
        LezKey::to_hex(self)
    }
}

#[derive(Default)]
struct AllowlistSign {
    persistence_path: String,
    eth: Option<SigningKey>,
    lez: Option<LezKey>,
}

fn key_path_in(persistence_path: &str, file: &str) -> Option<std::path::PathBuf> {
    if persistence_path.is_empty() {
        None
    } else {
        Some(std::path::Path::new(persistence_path).join(file))
    }
}

fn persist_key<K: ModuleKey>(persistence_path: &str, key: &K) -> Result<(), String> {
    let Some(path) = key_path_in(persistence_path, K::FILE) else { return Ok(()) };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(&path).map_err(|e| format!("open {}: {e}", path.display()))?;
    writeln!(f, "{}", key.to_hex()).map_err(|e| format!("write {}: {e}", path.display()))
}

/// The module key in `slot`: cached, else loaded from its key file, else
/// freshly generated (and persisted when a path exists).
fn module_key<'a, K: ModuleKey>(persistence_path: &str, slot: &'a mut Option<K>) -> Result<&'a K, String> {
    if slot.is_none() {
        let loaded = match key_path_in(persistence_path, K::FILE) {
            Some(p) if p.exists() => {
                let s = std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
                Some(K::parse(&s).map_err(|e| format!("{}: {e}", p.display()))?)
            }
            _ => None,
        };
        let key = match loaded {
            Some(k) => k,
            None => {
                let k = K::random();
                persist_key(persistence_path, &k)?;
                if persistence_path.is_empty() {
                    eprintln!(
                        "allowlist_sign_module: no persistence path — the {} signing key is in-memory and changes per run",
                        K::AUTH_TYPE
                    );
                }
                k
            }
        };
        *slot = Some(key);
    }
    Ok(slot.as_ref().unwrap())
}

/// `{"auth_type", …}` → (auth_type, the whole request).
fn parse_typed_request(req_json: &str, what: &str) -> Result<(String, Value), String> {
    let v: Value = serde_json::from_str(req_json).map_err(|e| format!("{what}: {e}"))?;
    let t = v
        .get("auth_type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{what}: auth_type (string) is required"))?
        .to_string();
    Ok((t, v))
}

fn unknown_type(t: &str) -> String {
    format!("unknown auth_type '{t}' on this module")
}

impl AllowlistSign {
    fn persisted(&self, file: &str) -> bool {
        key_path_in(&self.persistence_path, file).map(|p| p.exists()).unwrap_or(false)
    }

    fn eth_identity(&self, key: &SigningKey) -> Value {
        json!({
            "auth_type": ETH_ALLOWLIST_AUTH_TYPE,
            "id": eth::address_of(key.verifying_key()),
            "persisted": self.persisted(ETH_KEY_FILE),
        })
    }

    fn lez_identity(&self, key: &LezKey) -> Value {
        let id = key.identity();
        json!({
            "auth_type": LEZ_ALLOWLIST_AUTH_TYPE,
            "id": id["account_id"],
            "id_base58": id["account_id_base58"],
            "persisted": self.persisted(LEZ_KEY_FILE),
        })
    }

    /// `node` overrides the http node of the logos vector (tests).
    fn produce_with(&mut self, node: Option<&dyn ZkNode>, args_json: &str) -> Result<String, String> {
        // Peek at auth_type and args.private_key before dispatch: they decide
        // which key the eth/lez vector borrows (only the requested type's key
        // is resolved); dispatch_produce then does the parse/route.
        let peek = serde_json::from_str::<Value>(args_json).ok();
        let auth_type = peek.as_ref().and_then(|v| v.get("auth_type")?.as_str().map(str::to_owned));
        let override_key = peek
            .as_ref()
            .and_then(|v| v.get("args")?.get("private_key")?.as_str().map(str::to_owned));
        let mut eth_key = None;
        let mut lez_key = None;
        match auth_type.as_deref() {
            Some(ETH_ALLOWLIST_AUTH_TYPE) => {
                eth_key = Some(match &override_key {
                    Some(h) => eth::parse_key(h)?,
                    None => module_key(&self.persistence_path, &mut self.eth)?.clone(),
                })
            }
            Some(LEZ_ALLOWLIST_AUTH_TYPE) => {
                lez_key = Some(match &override_key {
                    Some(h) => LezKey::parse(h)?,
                    None => module_key(&self.persistence_path, &mut self.lez)?.clone(),
                })
            }
            _ => {}
        }
        Ok(dispatch_produce(
            args_json,
            &[
                &EthSignVector { key: eth_key.as_ref() },
                &LezSignVector { key: lez_key.as_ref() },
                &LogosSignVector { node },
            ],
        ))
    }

    fn identity_with(&mut self, node: Option<&dyn ZkNode>, req_json: &str) -> Result<String, String> {
        let (t, req) = parse_typed_request(req_json, "identity")?;
        let out = match t.as_str() {
            ETH_ALLOWLIST_AUTH_TYPE => {
                let key = module_key(&self.persistence_path, &mut self.eth)?.clone();
                self.eth_identity(&key)
            }
            LEZ_ALLOWLIST_AUTH_TYPE => {
                let key = module_key(&self.persistence_path, &mut self.lez)?.clone();
                self.lez_identity(&key)
            }
            LOGOS_ALLOWLIST_AUTH_TYPE => {
                // logos::public_key_with takes the args as a JSON string ("" for defaults).
                let args = match req.get("args") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                };
                let pk: Value = serde_json::from_str(&logos::public_key_with(node, &args)?)
                    .map_err(|e| format!("public_key reply: {e}"))?;
                // The key is held durably by the node's KMS.
                json!({
                    "auth_type": LOGOS_ALLOWLIST_AUTH_TYPE,
                    "id": pk["public_key"],
                    "source": pk["source"],
                    "persisted": true,
                })
            }
            other => return Err(unknown_type(other)),
        };
        Ok(out.to_string())
    }

    fn import_impl(&mut self, req_json: &str) -> Result<String, String> {
        let (t, req) = parse_typed_request(req_json, "import_key")?;
        if t == LOGOS_ALLOWLIST_AUTH_TYPE {
            return Err(LOGOS_IMPORT_REFUSAL.into());
        }
        if t != ETH_ALLOWLIST_AUTH_TYPE && t != LEZ_ALLOWLIST_AUTH_TYPE {
            return Err(unknown_type(&t));
        }
        let pk = req
            .get("private_key")
            .and_then(Value::as_str)
            .ok_or("import_key: private_key (hex string) is required")?;
        let out = if t == ETH_ALLOWLIST_AUTH_TYPE {
            let key = eth::parse_key(pk)?;
            persist_key(&self.persistence_path, &key)?;
            self.eth = Some(key.clone());
            self.eth_identity(&key)
        } else {
            let key = LezKey::parse(pk)?;
            persist_key(&self.persistence_path, &key)?;
            self.lez = Some(key.clone());
            self.lez_identity(&key)
        };
        Ok(out.to_string())
    }
}

fn error_json(e: String) -> String {
    json!({ "error": e }).to_string()
}

impl AllowlistSignModule for AllowlistSign {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn produce_auth(&mut self, args_json: String) -> String {
        self.produce_with(None, &args_json).unwrap_or_else(error_json)
    }
    fn identity(&mut self, req_json: String) -> String {
        self.identity_with(None, &req_json).unwrap_or_else(error_json)
    }
    fn import_key(&mut self, req_json: String) -> String {
        self.import_impl(&req_json).unwrap_or_else(error_json)
    }
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        self.persistence_path = ctx.instance_persistence_path.clone();
        self.eth = None;
        self.lez = None;
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<AllowlistSign>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth::tests::{recover, ADDR42, PK42};
    use lez::tests::{verify as lez_verify, ACCT3_B58, ACCT3_HEX, SK3};
    use logos::tests::{FakeNode, K, K2};

    const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn tmpdir(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("allowlist-sign-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.to_string_lossy().into_owned()
    }

    fn produce_req(auth_type: &str, idc: &str, args: Option<Value>) -> String {
        let mut v = json!({ "auth_type": auth_type, "id_commitment_hex": idc });
        if let Some(a) = args {
            v["args"] = a;
        }
        v.to_string()
    }

    fn parse(s: String) -> Value {
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("{e}: {s}"))
    }

    fn identity(m: &mut AllowlistSign, auth_type: &str) -> Value {
        parse(m.identity(json!({ "auth_type": auth_type }).to_string()))
    }

    fn import(m: &mut AllowlistSign, auth_type: &str, pk: &str) -> String {
        m.import_key(json!({ "auth_type": auth_type, "private_key": pk }).to_string())
    }

    fn with_ctx(dir: &str) -> AllowlistSign {
        let mut m = AllowlistSign::default();
        m.on_context_ready(&RustModuleContext { instance_persistence_path: dir.into(), ..Default::default() });
        m
    }

    // ---- eth-allowlist (from eth-sign-module) ----

    #[test]
    fn eth_module_key_signature_recovers_to_address() {
        let mut m = AllowlistSign::default();
        let addr = identity(&mut m, "eth-allowlist");
        assert_eq!(addr["persisted"], false);
        let reply = parse(m.produce_auth(produce_req("eth-allowlist", IDC, None)));
        let payload = reply["payload_hex"].as_str().expect("payload_hex");
        assert_eq!(payload.len(), 130);
        assert_eq!(recover(IDC, payload), addr["id"].as_str().unwrap());
    }

    #[test]
    fn eth_private_key_override_is_honoured() {
        let mut m = AllowlistSign::default();
        let module_addr = identity(&mut m, "eth-allowlist");
        let reply = parse(m.produce_auth(produce_req("eth-allowlist", IDC, Some(json!({ "private_key": PK42 })))));
        let recovered = recover(IDC, reply["payload_hex"].as_str().unwrap());
        assert_eq!(recovered, ADDR42);
        assert_ne!(recovered, module_addr["id"].as_str().unwrap());
    }

    #[test]
    fn eth_malformed_requests_are_errors() {
        let mut m = AllowlistSign::default();
        let wrong_type = m.produce_auth(json!({ "auth_type": "keycard-attestation", "id_commitment_hex": IDC }).to_string());
        assert!(wrong_type.contains("\"error\""), "got: {wrong_type}");
        let short = m.produce_auth(produce_req("eth-allowlist", "abcd", None));
        assert!(short.contains("32 bytes"), "got: {short}");
        let bad_override = m.produce_auth(produce_req("eth-allowlist", IDC, Some(json!({ "private_key": "zz" }))));
        assert!(bad_override.contains("private key hex"), "got: {bad_override}");
        assert!(import(&mut m, "eth-allowlist", "0x00").contains("\"error\""));
    }

    #[test]
    fn eth_key_persists_across_instances_and_import_replaces_it() {
        let dir = tmpdir("eth-persist");
        let mut a = with_ctx(&dir);
        let first = identity(&mut a, "eth-allowlist");
        assert_eq!(first["persisted"], true);
        let key_file = std::path::Path::new(&dir).join(ETH_KEY_FILE);
        assert!(key_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let mut b = with_ctx(&dir);
        let again = identity(&mut b, "eth-allowlist");
        assert_eq!(again["id"], first["id"], "same path, same key");

        let imported = parse(import(&mut b, "eth-allowlist", PK42));
        assert_eq!(imported["id"], ADDR42);
        let mut c = with_ctx(&dir);
        let after = identity(&mut c, "eth-allowlist");
        assert_eq!(after["id"], ADDR42, "import is persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- lez-allowlist (from lez-sign-module) ----

    #[test]
    fn lez_module_key_signature_verifies_to_account_id() {
        let mut m = AllowlistSign::default();
        let id = identity(&mut m, "lez-allowlist");
        assert_eq!(id["persisted"], false);
        let reply = parse(m.produce_auth(produce_req("lez-allowlist", IDC, None)));
        let payload = reply["payload_hex"].as_str().expect("payload_hex");
        assert_eq!(payload.len(), 192);
        let pk = m.lez.as_ref().unwrap().identity()["public_key"].clone();
        assert_eq!(&payload[..64], pk.as_str().unwrap());
        assert_eq!(lez_verify(IDC, payload).unwrap(), id["id"].as_str().unwrap());
    }

    #[test]
    fn lez_private_key_override_is_honoured() {
        let mut m = AllowlistSign::default();
        let module_id = identity(&mut m, "lez-allowlist");
        let reply = parse(m.produce_auth(produce_req("lez-allowlist", IDC, Some(json!({ "private_key": SK3 })))));
        let acct = lez_verify(IDC, reply["payload_hex"].as_str().unwrap()).unwrap();
        assert_eq!(acct, ACCT3_HEX);
        assert_ne!(acct, module_id["id"].as_str().unwrap());
    }

    #[test]
    fn lez_malformed_requests_are_errors() {
        let mut m = AllowlistSign::default();
        let wrong_type = m.produce_auth(json!({ "auth_type": "keycard-attestation", "id_commitment_hex": IDC }).to_string());
        assert!(wrong_type.contains("\"error\""), "got: {wrong_type}");
        let short = m.produce_auth(produce_req("lez-allowlist", "abcd", None));
        assert!(short.contains("32 bytes"), "got: {short}");
        let bad_override = m.produce_auth(produce_req("lez-allowlist", IDC, Some(json!({ "private_key": "zz" }))));
        assert!(bad_override.contains("private key hex"), "got: {bad_override}");
        assert!(import(&mut m, "lez-allowlist", "0x00").contains("\"error\""));
        assert!(import(&mut m, "lez-allowlist", &format!("0x{}", "00".repeat(32))).contains("\"error\""));
    }

    #[test]
    fn lez_key_persists_across_instances_and_import_replaces_it() {
        let dir = tmpdir("lez-persist");
        let mut a = with_ctx(&dir);
        let first = identity(&mut a, "lez-allowlist");
        assert_eq!(first["persisted"], true);
        let key_file = std::path::Path::new(&dir).join(LEZ_KEY_FILE);
        assert!(key_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let mut b = with_ctx(&dir);
        let again = identity(&mut b, "lez-allowlist");
        assert_eq!(again["id"], first["id"], "same path, same key");

        let imported = parse(import(&mut b, "lez-allowlist", SK3));
        assert_eq!(imported["id"], ACCT3_HEX);
        let mut c = with_ctx(&dir);
        let after = identity(&mut c, "lez-allowlist");
        assert_eq!(after["id"], ACCT3_HEX, "import is persisted");
        assert_eq!(after["id_base58"], ACCT3_B58);
        assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim(), SK3.trim_start_matches("0x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- logos-allowlist (from logos-sign-module) ----

    #[test]
    fn logos_unreachable_node_is_an_error() {
        let mut m = AllowlistSign::default();
        let e = m.identity(
            json!({ "auth_type": "logos-allowlist", "args": { "node_url": "http://127.0.0.1:1", "http_timeout_ms": 500 } })
                .to_string(),
        );
        assert!(e.contains("\"error\"") && e.contains("/pow/status"), "{e}");
    }

    // ---- routing ----

    #[test]
    fn identity_routes_per_auth_type() {
        let mut m = AllowlistSign::default();
        let eth = identity(&mut m, "eth-allowlist");
        assert_eq!(eth["auth_type"], "eth-allowlist");
        let addr = eth["id"].as_str().unwrap();
        assert!(addr.starts_with("0x") && addr.len() == 42 && addr == addr.to_lowercase(), "{addr}");
        assert!(eth.get("id_base58").is_none() && eth.get("source").is_none());

        let lez = identity(&mut m, "lez-allowlist");
        assert_eq!(lez["auth_type"], "lez-allowlist");
        let hex_id = lez["id"].as_str().unwrap();
        assert_eq!(hex_id.len(), 64);
        use base58::FromBase58;
        let b58 = lez["id_base58"].as_str().unwrap().from_base58().unwrap();
        assert_eq!(hex::encode(b58), hex_id);

        let node = FakeNode::new(vec![K]);
        let logos = parse(m.identity_with(Some(&node), &json!({ "auth_type": "logos-allowlist" }).to_string()).unwrap());
        assert_eq!(logos, json!({ "auth_type": "logos-allowlist", "id": K, "source": "pow_status", "persisted": true }));
        let logos = parse(
            m.identity_with(Some(&node), &json!({ "auth_type": "logos-allowlist", "args": { "public_key": K2 } }).to_string())
                .unwrap(),
        );
        assert_eq!(logos["id"], K2);
        assert_eq!(logos["source"], "args");

        let e = m.identity(json!({ "auth_type": "keycard-attestation" }).to_string());
        assert!(e.contains("unknown auth_type"), "{e}");
        assert!(m.identity("{}".into()).contains("auth_type"));
    }

    #[test]
    fn produce_routes_per_auth_type() {
        let mut m = AllowlistSign::default();
        let node = FakeNode::new(vec![K]);
        let eth = parse(m.produce_with(Some(&node), &produce_req("eth-allowlist", IDC, None)).unwrap());
        assert_eq!(eth["payload_hex"].as_str().unwrap().len(), 130);
        let lez = parse(m.produce_with(Some(&node), &produce_req("lez-allowlist", IDC, None)).unwrap());
        assert_eq!(lez["payload_hex"].as_str().unwrap().len(), 192);
        assert!(node.signed.borrow().is_empty(), "eth/lez must not touch the node");
        let logos = parse(m.produce_with(Some(&node), &produce_req("logos-allowlist", IDC, None)).unwrap());
        let p = logos["payload_hex"].as_str().unwrap_or_else(|| panic!("{logos}"));
        assert_eq!(p.len(), 320);
        assert_eq!(&p[..64], K);
        assert_eq!(node.signed.borrow().len(), 1);
    }

    #[test]
    fn import_refuses_logos_and_unknown_types() {
        let mut m = AllowlistSign::default();
        let e = parse(import(&mut m, "logos-allowlist", PK42));
        assert_eq!(e, json!({ "error": LOGOS_IMPORT_REFUSAL }));
        assert_eq!(e["error"], "logos-allowlist keys live in the node's KMS; nothing to import");
        assert!(import(&mut m, "keycard-attestation", PK42).contains("unknown auth_type"));
        assert!(m.import_key(json!({ "auth_type": "eth-allowlist" }).to_string()).contains("private_key"));
    }

    #[test]
    fn eth_import_does_not_touch_the_lez_key() {
        let dir = tmpdir("separate");
        let mut a = with_ctx(&dir);
        let lez_before = identity(&mut a, "lez-allowlist");
        let lez_file = std::path::Path::new(&dir).join(LEZ_KEY_FILE);
        let lez_bytes = std::fs::read_to_string(&lez_file).unwrap();

        let imported = parse(import(&mut a, "eth-allowlist", PK42));
        assert_eq!(imported, json!({ "auth_type": "eth-allowlist", "id": ADDR42, "persisted": true }));
        assert_eq!(identity(&mut a, "lez-allowlist"), lez_before);
        assert_eq!(std::fs::read_to_string(&lez_file).unwrap(), lez_bytes);

        let mut b = with_ctx(&dir);
        assert_eq!(identity(&mut b, "lez-allowlist")["id"], lez_before["id"]);
        assert_eq!(identity(&mut b, "eth-allowlist")["id"], ADDR42);

        // And the other way round: a lez import leaves the eth key alone.
        let lez = parse(import(&mut b, "lez-allowlist", SK3));
        assert_eq!(lez["id"], ACCT3_HEX);
        assert_eq!(lez["id_base58"], ACCT3_B58);
        assert_eq!(identity(&mut b, "eth-allowlist")["id"], ADDR42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_keys_are_per_type() {
        let mut m = AllowlistSign::default();
        assert!(m.eth.is_none() && m.lez.is_none());
        identity(&mut m, "eth-allowlist");
        assert!(m.eth.is_some() && m.lez.is_none(), "only the requested type's key is generated");
        let _ = m.produce_auth(produce_req("logos-allowlist", "abcd", None));
        assert!(m.lez.is_none());
    }
}
