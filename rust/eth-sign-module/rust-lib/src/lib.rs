// EIP-191 eth-allowlist PRODUCER for gifted RLN registration — the client-side
// half of the eth auth vector (the verifier half is eth-auth-module). It signs
// the requester's identity commitment with a module-owned secp256k1 key, so a
// membership module can drive the vector through `auth_provider` without any
// wallet in the loop: the allocator operator allowlists `address()` once.
//
// Key custody is demo-grade on purpose: the key is a plaintext hex file under
// the module's host-stamped persistence path (0600). Hosts that stamp no path
// (logos-standalone-app) get an in-memory key that changes per run.
// FEATURE: RLN gifter eth-allowlist auth vector (produce)

use k256::ecdsa::{SigningKey, VerifyingKey};
use rln_auth_vector::{dispatch_produce, AuthVector, ProduceReply, ProduceRequest};
use serde_json::json;

pub trait EthSignModule: Send + 'static {
    /// rln_auth_vector PRODUCE_METHOD for auth_type "eth-allowlist". One
    /// JSON-string arg (ProduceRequest) → `{"payload_hex"}`: the 65-byte
    /// recoverable EIP-191 personal_sign signature (r||s||recid, recid 0/1)
    /// over the lowercase hex of the 32-byte identity commitment, exactly
    /// what eth-auth-module recovers. Signs with the module key unless
    /// `args.private_key` (hex, optional 0x) names another one. `{"error"}`
    /// on a malformed request.
    fn produce_auth(&mut self, args_json: String) -> String;
    /// The module key's address — what an allocator operator allowlists.
    /// `{"address":"0x…" (lowercase),"persisted":bool}`; generates and
    /// persists the key on first use.
    fn address(&mut self) -> String;
    /// Replace the module key (hex, optional 0x) and persist it.
    /// `{"address"}` or `{"error"}`.
    fn import_key(&mut self, private_key_hex: String) -> String;
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

const KEY_FILE: &str = "eth_sign_key.hex";

#[derive(Default)]
struct EthSign {
    persistence_path: String,
    key: Option<SigningKey>,
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

// The EIP-191 personal_sign digest over the LOWERCASE HEX of the 32-byte
// commitment — byte-for-byte eth-auth-module's `eip191_digest`, and what
// `cast wallet sign "<hex>"` signs.
fn eip191_digest(id_commitment: &[u8]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

fn address_of(vk: &VerifyingKey) -> String {
    let enc = vk.to_encoded_point(false);
    let h = keccak256(&enc.as_bytes()[1..]);
    format!("0x{}", hex::encode(&h[12..]))
}

fn parse_key(hex_str: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|e| format!("private key hex: {e}"))?;
    SigningKey::from_slice(&bytes).map_err(|e| format!("private key: {e}"))
}

fn sign_commitment(key: &SigningKey, id_commitment_hex: &str) -> Result<String, String> {
    let idc = hex::decode(id_commitment_hex.trim_start_matches("0x"))
        .map_err(|e| format!("id_commitment hex: {e}"))?;
    if idc.len() != 32 {
        return Err(format!("id_commitment must be 32 bytes, got {}", idc.len()));
    }
    let (sig, recid) = key
        .sign_prehash_recoverable(&eip191_digest(&idc))
        .map_err(|e| format!("sign: {e}"))?;
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    Ok(hex::encode(out))
}

/// One produce call's vector: borrows the key chosen for this request.
struct EthSignVector<'a> {
    key: &'a SigningKey,
}

impl AuthVector for EthSignVector<'_> {
    fn auth_type(&self) -> &'static str {
        rln_auth_vector::ETH_ALLOWLIST_AUTH_TYPE
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        Ok(ProduceReply { payload_hex: sign_commitment(self.key, &req.id_commitment_hex)? })
    }
}

impl EthSign {
    fn key_path(&self) -> Option<std::path::PathBuf> {
        if self.persistence_path.is_empty() {
            None
        } else {
            Some(std::path::Path::new(&self.persistence_path).join(KEY_FILE))
        }
    }

    fn persist(&self, key: &SigningKey) -> Result<(), String> {
        let Some(path) = self.key_path() else { return Ok(()) };
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
        writeln!(f, "{}", hex::encode(key.to_bytes()))
            .map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// The module key: cached, else loaded from the key file, else freshly
    /// generated (and persisted when a path exists).
    fn module_key(&mut self) -> Result<&SigningKey, String> {
        if self.key.is_none() {
            let loaded = match self.key_path() {
                Some(p) if p.exists() => {
                    let s = std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
                    Some(parse_key(&s).map_err(|e| format!("{}: {e}", p.display()))?)
                }
                _ => None,
            };
            let key = match loaded {
                Some(k) => k,
                None => {
                    let k = SigningKey::random(&mut rand_core::OsRng);
                    self.persist(&k)?;
                    if self.persistence_path.is_empty() {
                        eprintln!("eth_sign_module: no persistence path — the signing key is in-memory and changes per run");
                    }
                    k
                }
            };
            self.key = Some(key);
        }
        Ok(self.key.as_ref().unwrap())
    }

    fn produce_impl(&mut self, args_json: &str) -> Result<String, String> {
        // Peek at args.private_key before dispatch: the override decides which
        // key the vector borrows; dispatch_produce then does the parse/route.
        let override_key = serde_json::from_str::<serde_json::Value>(args_json)
            .ok()
            .and_then(|v| v.get("args")?.get("private_key")?.as_str().map(str::to_owned));
        let key = match override_key {
            Some(h) => parse_key(&h)?,
            None => self.module_key()?.clone(),
        };
        Ok(dispatch_produce(args_json, &[&EthSignVector { key: &key }]))
    }

    fn address_impl(&mut self) -> Result<String, String> {
        let addr = address_of(self.module_key()?.verifying_key());
        let persisted = self.key_path().map(|p| p.exists()).unwrap_or(false);
        Ok(json!({ "address": addr, "persisted": persisted }).to_string())
    }

    fn import_impl(&mut self, private_key_hex: &str) -> Result<String, String> {
        let key = parse_key(private_key_hex)?;
        self.persist(&key)?;
        let addr = address_of(key.verifying_key());
        self.key = Some(key);
        Ok(json!({ "address": addr }).to_string())
    }
}

fn error_json(e: String) -> String {
    json!({ "error": e }).to_string()
}

impl EthSignModule for EthSign {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn produce_auth(&mut self, args_json: String) -> String {
        self.produce_impl(&args_json).unwrap_or_else(error_json)
    }
    fn address(&mut self) -> String {
        self.address_impl().unwrap_or_else(error_json)
    }
    fn import_key(&mut self, private_key_hex: String) -> String {
        self.import_impl(&private_key_hex).unwrap_or_else(error_json)
    }
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        self.persistence_path = ctx.instance_persistence_path.clone();
        self.key = None;
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<EthSign>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature};

    const PK42: &str = "0x4242424242424242424242424242424242424242424242424242424242424242";
    const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
    const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    // `cast wallet sign --private-key $PK42 "$IDC"` (foundry; EIP-191 over the
    // hex string, v = 27 + recid).
    const CAST_SIG: &str = "84b1aff4c2850be46cefd3e12e22349bc886dea47e7b0e509c2e3059f1035fc1606d3c249c695f72556bd1d12ff301671244780f72177a2e3f89a033a8dd94c81c";

    // eth-auth-module's recovery, re-implemented so the two crates stay
    // independent: 65-byte r||s||recid (0/1 or 27/28) over the EIP-191 envelope.
    fn recover(idc_hex: &str, sig_hex: &str) -> String {
        let sig = hex::decode(sig_hex).unwrap();
        assert_eq!(sig.len(), 65);
        let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
        let recid = RecoveryId::from_byte(recid_byte).unwrap();
        let signature = Signature::from_slice(&sig[0..64]).unwrap();
        let digest = eip191_digest(&hex::decode(idc_hex).unwrap());
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
        address_of(&vk)
    }

    fn tmpdir(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("eth-sign-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.to_string_lossy().into_owned()
    }

    fn produce_req(idc: &str, args: Option<serde_json::Value>) -> String {
        let mut v = json!({ "auth_type": "eth-allowlist", "id_commitment_hex": idc });
        if let Some(a) = args {
            v["args"] = a;
        }
        v.to_string()
    }

    #[test]
    fn module_key_signature_recovers_to_address() {
        let mut m = EthSign::default();
        let addr: serde_json::Value = serde_json::from_str(&m.address()).unwrap();
        assert_eq!(addr["persisted"], false);
        let reply: serde_json::Value = serde_json::from_str(&m.produce_auth(produce_req(IDC, None))).unwrap();
        let payload = reply["payload_hex"].as_str().expect("payload_hex");
        assert_eq!(payload.len(), 130);
        assert_eq!(recover(IDC, payload), addr["address"].as_str().unwrap());
    }

    #[test]
    fn matches_foundry_cast_vector() {
        let key = parse_key(PK42).unwrap();
        let ours = sign_commitment(&key, IDC).unwrap();
        assert_eq!(&ours[..128], &CAST_SIG[..128], "r||s differs from cast");
        let v = u8::from_str_radix(&CAST_SIG[128..], 16).unwrap();
        assert_eq!(u8::from_str_radix(&ours[128..], 16).unwrap(), v - 27);
        assert_eq!(recover(IDC, &ours), ADDR42);
        assert_eq!(recover(IDC, CAST_SIG), ADDR42);
    }

    #[test]
    fn private_key_override_is_honoured() {
        let mut m = EthSign::default();
        let module_addr: serde_json::Value = serde_json::from_str(&m.address()).unwrap();
        let reply: serde_json::Value =
            serde_json::from_str(&m.produce_auth(produce_req(IDC, Some(json!({ "private_key": PK42 }))))).unwrap();
        let recovered = recover(IDC, reply["payload_hex"].as_str().unwrap());
        assert_eq!(recovered, ADDR42);
        assert_ne!(recovered, module_addr["address"].as_str().unwrap());
    }

    #[test]
    fn malformed_requests_are_errors() {
        let mut m = EthSign::default();
        let wrong_type = m.produce_auth(json!({ "auth_type": "keycard-attestation", "id_commitment_hex": IDC }).to_string());
        assert!(wrong_type.contains("\"error\""), "got: {wrong_type}");
        let short = m.produce_auth(produce_req("abcd", None));
        assert!(short.contains("32 bytes"), "got: {short}");
        let bad_override = m.produce_auth(produce_req(IDC, Some(json!({ "private_key": "zz" }))));
        assert!(bad_override.contains("private key hex"), "got: {bad_override}");
        assert!(m.import_key("0x00".into()).contains("\"error\""));
    }

    #[test]
    fn key_persists_across_instances_and_import_replaces_it() {
        let dir = tmpdir("persist");
        let ctx = RustModuleContext { instance_persistence_path: dir.clone(), ..Default::default() };
        let mut a = EthSign::default();
        a.on_context_ready(&ctx);
        let first: serde_json::Value = serde_json::from_str(&a.address()).unwrap();
        assert_eq!(first["persisted"], true);
        assert!(std::path::Path::new(&dir).join(KEY_FILE).exists());

        let mut b = EthSign::default();
        b.on_context_ready(&ctx);
        let again: serde_json::Value = serde_json::from_str(&b.address()).unwrap();
        assert_eq!(again["address"], first["address"], "same path, same key");

        let imported: serde_json::Value = serde_json::from_str(&b.import_key(PK42.into())).unwrap();
        assert_eq!(imported["address"], ADDR42);
        let mut c = EthSign::default();
        c.on_context_ready(&ctx);
        let after: serde_json::Value = serde_json::from_str(&c.address()).unwrap();
        assert_eq!(after["address"], ADDR42, "import is persisted");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
