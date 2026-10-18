// BIP-340 lez-allowlist PRODUCER for gifted RLN registration — the client-side
// half of the LEZ auth vector (the verifier half is lez-auth-module). It signs
// sha256("logos/rln/lez-sign/1" || id_commitment) with a module-owned
// secp256k1 key used as a LEZ public-account key (untweaked, x-only), so a
// membership module can drive the vector through `auth_provider` without a
// wallet in the loop: the allocator operator allowlists `account_id()` once.
// Importing the same private key into a LEZ wallet yields the same account id.
//
// Key custody is demo-grade on purpose: the key is a plaintext hex file under
// the module's host-stamped persistence path (0600). Hosts that stamp no path
// (logos-standalone-app) get an in-memory key that changes per run.
// FEATURE: RLN gifter lez-allowlist auth vector (produce)

use base58::ToBase58;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::SecretKey;
use rand_core::RngCore;
use rln_auth_vector::{dispatch_produce, AuthVector, ProduceReply, ProduceRequest};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const LEZ_ALLOWLIST_AUTH_TYPE: &str = "lez-allowlist";
/// Byte-for-byte lez-auth-module's `DOMAIN`.
const DOMAIN: &[u8] = b"logos/rln/lez-sign/1";
/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

pub trait LezSignModule: Send + 'static {
    /// rln_auth_vector PRODUCE_METHOD for auth_type "lez-allowlist". One
    /// JSON-string arg (ProduceRequest) → `{"payload_hex"}`: x-only public
    /// key (32 B) || BIP-340 signature (64 B) over sha256("logos/rln/lez-sign/1"
    /// || id_commitment), exactly what lez-auth-module verifies. Signs with
    /// the module key unless `args.private_key` (hex, optional 0x) names
    /// another one. `{"error"}` on a malformed request.
    fn produce_auth(&mut self, args_json: String) -> String;
    /// The module key's LEZ account id — what an allocator operator
    /// allowlists. `{"account_id":"<64 hex>","account_id_base58","public_key":
    /// "<64 hex x-only>","persisted":bool}`; generates and persists the key on
    /// first use.
    fn account_id(&mut self) -> String;
    /// Replace the module key (hex, optional 0x) and persist it.
    /// `{"account_id","account_id_base58","public_key"}` or `{"error"}`.
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

const KEY_FILE: &str = "lez_sign_key.hex";

/// A private key as given (not BIP-340-normalised), so what is persisted and
/// imported elsewhere is the caller's own scalar.
#[derive(Clone)]
struct LezKey([u8; 32]);

#[derive(Default)]
struct LezSign {
    persistence_path: String,
    key: Option<LezKey>,
}

fn digest(id_commitment: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.finalize().into()
}

fn account_id_of(xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEE_ACCOUNT_ID_PREFIX);
    h.update(xonly);
    h.finalize().into()
}

impl LezKey {
    fn parse(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
            .map_err(|e| format!("private key hex: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("private key must be 32 bytes, got {}", b.len()))?;
        SigningKey::from_bytes(&arr).map_err(|e| format!("private key: {e}"))?;
        Ok(LezKey(arr))
    }

    fn random() -> Self {
        LezKey(SecretKey::random(&mut rand_core::OsRng).to_bytes().into())
    }

    /// LEE's x-only key: the x coordinate of the public point (identical
    /// whether or not BIP-340 normalises the scalar to even Y).
    fn xonly(&self) -> [u8; 32] {
        let pk = SecretKey::from_slice(&self.0).expect("validated").public_key();
        (*pk.to_encoded_point(false).x().expect("not identity")).into()
    }

    fn identity(&self) -> serde_json::Value {
        let xonly = self.xonly();
        let acct = account_id_of(&xonly);
        json!({
            "account_id": hex::encode(acct),
            "account_id_base58": acct.to_base58(),
            "public_key": hex::encode(xonly),
        })
    }

    fn sign_commitment(&self, id_commitment_hex: &str) -> Result<String, String> {
        let idc = hex::decode(id_commitment_hex.trim_start_matches("0x"))
            .map_err(|e| format!("id_commitment hex: {e}"))?;
        if idc.len() != 32 {
            return Err(format!("id_commitment must be 32 bytes, got {}", idc.len()));
        }
        let sk = SigningKey::from_bytes(&self.0).map_err(|e| format!("private key: {e}"))?;
        let mut aux = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut aux);
        let sig = sk
            .sign_prehash_with_aux_rand(&digest(&idc), &aux)
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = self.xonly().to_vec();
        out.extend_from_slice(&sig.to_bytes());
        Ok(hex::encode(out))
    }
}

/// One produce call's vector: borrows the key chosen for this request.
struct LezSignVector<'a> {
    key: &'a LezKey,
}

impl AuthVector for LezSignVector<'_> {
    fn auth_type(&self) -> &'static str {
        LEZ_ALLOWLIST_AUTH_TYPE
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        Ok(ProduceReply { payload_hex: self.key.sign_commitment(&req.id_commitment_hex)? })
    }
}

impl LezSign {
    fn key_path(&self) -> Option<std::path::PathBuf> {
        if self.persistence_path.is_empty() {
            None
        } else {
            Some(std::path::Path::new(&self.persistence_path).join(KEY_FILE))
        }
    }

    fn persist(&self, key: &LezKey) -> Result<(), String> {
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
        writeln!(f, "{}", hex::encode(key.0)).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// The module key: cached, else loaded from the key file, else freshly
    /// generated (and persisted when a path exists).
    fn module_key(&mut self) -> Result<&LezKey, String> {
        if self.key.is_none() {
            let loaded = match self.key_path() {
                Some(p) if p.exists() => {
                    let s = std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
                    Some(LezKey::parse(&s).map_err(|e| format!("{}: {e}", p.display()))?)
                }
                _ => None,
            };
            let key = match loaded {
                Some(k) => k,
                None => {
                    let k = LezKey::random();
                    self.persist(&k)?;
                    if self.persistence_path.is_empty() {
                        eprintln!("lez_sign_module: no persistence path — the signing key is in-memory and changes per run");
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
            Some(h) => LezKey::parse(&h)?,
            None => self.module_key()?.clone(),
        };
        Ok(dispatch_produce(args_json, &[&LezSignVector { key: &key }]))
    }

    fn account_id_impl(&mut self) -> Result<String, String> {
        let mut id = self.module_key()?.identity();
        id["persisted"] = json!(self.key_path().map(|p| p.exists()).unwrap_or(false));
        Ok(id.to_string())
    }

    fn import_impl(&mut self, private_key_hex: &str) -> Result<String, String> {
        let key = LezKey::parse(private_key_hex)?;
        self.persist(&key)?;
        let id = key.identity();
        self.key = Some(key);
        Ok(id.to_string())
    }
}

fn error_json(e: String) -> String {
    json!({ "error": e }).to_string()
}

impl LezSignModule for LezSign {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn produce_auth(&mut self, args_json: String) -> String {
        self.produce_impl(&args_json).unwrap_or_else(error_json)
    }
    fn account_id(&mut self) -> String {
        self.account_id_impl().unwrap_or_else(error_json)
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
    install::<LezSign>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::signature::hazmat::PrehashVerifier;
    use k256::schnorr::{Signature, VerifyingKey};

    // BIP-340 test vector 0 (sk = 3) and its LEZ account id (python3:
    // sha256(b"/LEE/v0.3/AccountId/Public/" + b"\0"*5 + pk), base58 Bitcoin alphabet).
    const SK3: &str = "0x0000000000000000000000000000000000000000000000000000000000000003";
    const PK3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const ACCT3_HEX: &str = "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
    const ACCT3_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";
    const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    // lez-auth-module's check, re-implemented so the two crates stay
    // independent: verify, then derive the account id from the x-only key.
    fn verify(idc_hex: &str, payload_hex: &str) -> Result<String, String> {
        let p = hex::decode(payload_hex).unwrap();
        assert_eq!(p.len(), 96);
        let vk = VerifyingKey::from_bytes(&p[..32]).map_err(|e| e.to_string())?;
        let sig = Signature::try_from(&p[32..]).map_err(|e| e.to_string())?;
        vk.verify_prehash(&digest(&hex::decode(idc_hex).unwrap()), &sig).map_err(|e| e.to_string())?;
        Ok(hex::encode(account_id_of(&p[..32].try_into().unwrap())))
    }

    fn tmpdir(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("lez-sign-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.to_string_lossy().into_owned()
    }

    fn produce_req(idc: &str, args: Option<serde_json::Value>) -> String {
        let mut v = json!({ "auth_type": "lez-allowlist", "id_commitment_hex": idc });
        if let Some(a) = args {
            v["args"] = a;
        }
        v.to_string()
    }

    fn odd_y(k: &LezKey) -> bool {
        SecretKey::from_slice(&k.0).unwrap().public_key().to_encoded_point(true).as_bytes()[0] == 0x03
    }

    #[test]
    fn lee_prefix_is_32_bytes() {
        assert_eq!(LEE_ACCOUNT_ID_PREFIX.len(), 32);
    }

    #[test]
    fn module_key_signature_verifies_to_account_id() {
        let mut m = LezSign::default();
        let id: serde_json::Value = serde_json::from_str(&m.account_id()).unwrap();
        assert_eq!(id["persisted"], false);
        let reply: serde_json::Value = serde_json::from_str(&m.produce_auth(produce_req(IDC, None))).unwrap();
        let payload = reply["payload_hex"].as_str().expect("payload_hex");
        assert_eq!(payload.len(), 192);
        assert_eq!(&payload[..64], id["public_key"].as_str().unwrap());
        assert_eq!(verify(IDC, payload).unwrap(), id["account_id"].as_str().unwrap());
    }

    #[test]
    fn known_answer_and_xonly_matches_bip340_for_odd_y() {
        let k3 = LezKey::parse(SK3).unwrap();
        let id = k3.identity();
        assert_eq!(id["public_key"], PK3);
        assert_eq!(id["account_id"], ACCT3_HEX);
        assert_eq!(id["account_id_base58"], ACCT3_B58);

        let mut seen_odd = false;
        for n in 1..=8u8 {
            let mut b = [0u8; 32];
            b[31] = n;
            let k = LezKey(b);
            seen_odd |= odd_y(&k);
            let vk: [u8; 32] = SigningKey::from_bytes(&b).unwrap().verifying_key().to_bytes().into();
            assert_eq!(vk, k.xonly(), "sk {n}");
            let payload = k.sign_commitment(IDC).unwrap();
            assert_eq!(verify(IDC, &payload).unwrap(), hex::encode(account_id_of(&k.xonly())), "sk {n}");
        }
        assert!(seen_odd);
    }

    #[test]
    fn private_key_override_is_honoured() {
        let mut m = LezSign::default();
        let module_id: serde_json::Value = serde_json::from_str(&m.account_id()).unwrap();
        let reply: serde_json::Value =
            serde_json::from_str(&m.produce_auth(produce_req(IDC, Some(json!({ "private_key": SK3 }))))).unwrap();
        let acct = verify(IDC, reply["payload_hex"].as_str().unwrap()).unwrap();
        assert_eq!(acct, ACCT3_HEX);
        assert_ne!(acct, module_id["account_id"].as_str().unwrap());
    }

    #[test]
    fn flipped_signature_rejects() {
        let k3 = LezKey::parse(SK3).unwrap();
        let mut p = hex::decode(k3.sign_commitment(IDC).unwrap()).unwrap();
        p[40] ^= 0x01;
        assert!(verify(IDC, &hex::encode(p)).is_err());
    }

    #[test]
    fn malformed_requests_are_errors() {
        let mut m = LezSign::default();
        let wrong_type = m.produce_auth(json!({ "auth_type": "eth-allowlist", "id_commitment_hex": IDC }).to_string());
        assert!(wrong_type.contains("\"error\""), "got: {wrong_type}");
        let short = m.produce_auth(produce_req("abcd", None));
        assert!(short.contains("32 bytes"), "got: {short}");
        let bad_override = m.produce_auth(produce_req(IDC, Some(json!({ "private_key": "zz" }))));
        assert!(bad_override.contains("private key hex"), "got: {bad_override}");
        assert!(m.import_key("0x00".into()).contains("\"error\""));
        assert!(m.import_key(format!("0x{}", "00".repeat(32))).contains("\"error\""));
    }

    #[test]
    fn key_persists_across_instances_and_import_replaces_it() {
        let dir = tmpdir("persist");
        let ctx = RustModuleContext { instance_persistence_path: dir.clone(), ..Default::default() };
        let mut a = LezSign::default();
        a.on_context_ready(&ctx);
        let first: serde_json::Value = serde_json::from_str(&a.account_id()).unwrap();
        assert_eq!(first["persisted"], true);
        let key_file = std::path::Path::new(&dir).join(KEY_FILE);
        assert!(key_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let mut b = LezSign::default();
        b.on_context_ready(&ctx);
        let again: serde_json::Value = serde_json::from_str(&b.account_id()).unwrap();
        assert_eq!(again["account_id"], first["account_id"], "same path, same key");

        let imported: serde_json::Value = serde_json::from_str(&b.import_key(SK3.into())).unwrap();
        assert_eq!(imported["account_id"], ACCT3_HEX);
        let mut c = LezSign::default();
        c.on_context_ready(&ctx);
        let after: serde_json::Value = serde_json::from_str(&c.account_id()).unwrap();
        assert_eq!(after["account_id"], ACCT3_HEX, "import is persisted");
        assert_eq!(after["account_id_base58"], ACCT3_B58);
        assert_eq!(std::fs::read_to_string(&key_file).unwrap().trim(), SK3.trim_start_matches("0x"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
