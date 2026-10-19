// logos-allowlist VERIFIER for gifted RLN registration — the server-side half
// of the logos auth vector (the producer half is allowlist-sign-module, which has
// a logos-blockchain node zkSign the commitment). Verification is offline: a
// Groth16 check against the bundled zkSign VK (or `config.zksign_vk_path`).
// The key K is the nullifier, so each allowlisted key grants one membership
// through the gifter's shared, persisted replay store.
// FEATURE: RLN gifter logos-allowlist auth vector (verify)

use std::collections::HashMap;
// Arc/Mutex are referenced fully qualified: the generated provider_gen.rs
// (included outside cfg(test)) imports Mutex into this module too.
use std::sync::OnceLock;

use rln_auth_vector::{AuthVector, Verdict, VerifyRequest};
use sha2::{Digest as _, Sha256};
use zksign_light::{is_canonical_fr, norm_hex32, strip_0x, verify_sig, zero_pk_le, PreparedVk};

// payload: `K(32) || zksig(128) || rate_max u64 LE(8)`, a zkSign by the
// logos-blockchain key K (32-byte LE Fr) over
// `sha256("logos/rln/logos-sign/2" || id_commitment || rate_max LE || audience)`;
// config: `{"allowlist": ["<64 hex K>", …], "audience"?: "", "zksign_vk_path"?}`.
// Rejects when the requested rate exceeds the signed rate_max. Accepts with
// hex(K) as the nullifier.

pub const LOGOS_ALLOWLIST_AUTH_TYPE: &str = "logos-allowlist";
/// Domain of the signed digest; must match allowlist-sign-module's logos.rs.
pub const DOMAIN: &[u8] = b"logos/rln/logos-sign/2";
pub const PAYLOAD_LEN: usize = 32 + 128 + 8;
/// Longest accepted `config.audience`, as for pow-claim.
pub const MAX_AUDIENCE_LEN: usize = 255;

/// The 32 bytes the node signed:
/// `sha256(DOMAIN || id_commitment || rate_max LE || audience)`.
pub fn digest(id_commitment: &[u8; 32], rate_max: u64, audience: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.update(rate_max.to_le_bytes());
    h.update(audience.as_bytes());
    h.finalize().into()
}

enum Vk {
    Default(&'static PreparedVk),
    File(std::sync::Arc<PreparedVk>),
}

impl Vk {
    fn get(&self) -> &PreparedVk {
        match self {
            Vk::Default(v) => v,
            Vk::File(v) => v,
        }
    }
}

type VkKey = (String, Option<std::time::SystemTime>, u64);

/// VKs from `config.zksign_vk_path`, prepared once per (path, mtime, len), so
/// a VK file replaced in place is picked up on the next request.
fn vk_from_path(path: &str) -> Result<std::sync::Arc<PreparedVk>, String> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<VkKey, std::sync::Arc<PreparedVk>>>> = OnceLock::new();
    let meta = std::fs::metadata(path).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
    let key: VkKey = (path.to_string(), meta.modified().ok(), meta.len());
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return Ok(v.clone());
    }
    let v = std::sync::Arc::new(PreparedVk::from_path(path)?);
    let mut c = cache.lock().unwrap();
    c.retain(|(p, _, _), _| p != path);
    c.insert(key, v.clone());
    Ok(v)
}

struct Config {
    allowlist: Vec<String>,
    audience: String,
    vk: Vk,
}

fn allowlist_entry(e: &serde_json::Value) -> Result<String, String> {
    let s = e.as_str().ok_or("config.allowlist entries must be strings")?;
    let h = norm_hex32("config.allowlist entry", s)?;
    let mut le = [0u8; 32];
    hex::decode_to_slice(&h, &mut le).map_err(|e| format!("config.allowlist entry {s:?}: {e}"))?;
    if !is_canonical_fr(&le) {
        return Err(format!(
            "config.allowlist entry {s:?}: not a canonical BN254 scalar (big-endian paste?); \
             keys are 32-byte little-endian, as /pow/status prints them"
        ));
    }
    Ok(h)
}

fn parse_config(config: Option<&serde_json::Value>) -> Result<Config, String> {
    let entries = config
        .and_then(|c| c.get("allowlist"))
        .and_then(|v| v.as_array())
        .ok_or("config.allowlist (array of 64-hex logos public keys) is required")?;
    let allowlist: Vec<String> = entries.iter().map(allowlist_entry).collect::<Result<_, String>>()?;
    if allowlist.is_empty() {
        return Err("config.allowlist is empty — nothing can verify".into());
    }
    let audience = match config.and_then(|c| c.get("audience")) {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) if s.len() <= MAX_AUDIENCE_LEN => s.clone(),
        Some(serde_json::Value::String(s)) => {
            return Err(format!("config.audience: at most {MAX_AUDIENCE_LEN} bytes, got {}", s.len()))
        }
        Some(v) => return Err(format!("config.audience: expected a string, got {v}")),
    };
    let vk = match config.and_then(|c| c.get("zksign_vk_path")) {
        None | Some(serde_json::Value::Null) => Vk::Default(zksign_light::default_vk()?),
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => Vk::File(vk_from_path(p.trim())?),
        Some(v) => return Err(format!("config.zksign_vk_path: expected a non-empty string, got {v}")),
    };
    Ok(Config { allowlist, audience, vk })
}

pub struct LogosAllowlistVector;

impl AuthVector for LogosAllowlistVector {
    fn auth_type(&self) -> &'static str {
        LOGOS_ALLOWLIST_AUTH_TYPE
    }

    // Malformed config (incl. an unreadable or wrong-shape VK) is an Err
    // (operator mistake, error envelope); a bad payload/commitment, an
    // unlisted key, a rate above the signed rate_max or an invalid signature
    // is a REJECT verdict (untrusted input, normal flow). The allowlist check
    // runs before the (costlier) proof verification.
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let cfg = parse_config(req.config.as_ref())?;

        let payload = match hex::decode(strip_0x(&req.payload_hex)) {
            Ok(p) => p,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        if payload.len() != PAYLOAD_LEN {
            return Ok(Verdict::reject(format!(
                "payload must be {PAYLOAD_LEN} bytes (K 32 || zksig 128 || rate_max 8), got {}",
                payload.len()
            )));
        }
        let idc = match zksign_light::hex32_bytes("id_commitment_hex", &req.id_commitment_hex) {
            Ok(c) => c,
            Err(e) => return Ok(Verdict::reject(e)),
        };
        let k: [u8; 32] = payload[..32].try_into().unwrap();
        let sig: [u8; 128] = payload[32..160].try_into().unwrap();
        let rate_max = u64::from_le_bytes(payload[160..].try_into().unwrap());
        let k_hex = hex::encode(k);
        if !cfg.allowlist.contains(&k_hex) {
            return Ok(Verdict::reject(format!("public key not allowlisted: {k_hex}")));
        }
        if k == zero_pk_le() {
            return Ok(Verdict::reject("public key is the zero key"));
        }
        if req.rate > rate_max {
            return Ok(Verdict::reject(format!("rate {} exceeds the signed rate_max {rate_max}", req.rate)));
        }
        if let Err(e) = verify_sig(cfg.vk.get(), &k, &digest(&idc, rate_max, &cfg.audience), &sig) {
            return Ok(Verdict::reject(e));
        }
        Ok(Verdict::accept(Some(k_hex)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AllowlistAuthModule;
    use serde_json::{json, Value};

    /// Recorded by allowlist-sign-module's ignored real-node test (follower
    /// node 0.3.2, its test PoWClaim key): `{idc, k, rate_max, audience, payload_hex}`.
    const REAL: &str = include_str!("../tests/fixtures/logos_sign_real.json");

    /// Known answer shared with allowlist-sign-module's logos.rs: idc
    /// 0x01..0x20, rate_max 100, audience "".
    const DIGEST_KAT: &str = "80fe3eca4c6aad0e47ad67edfb288d23ad0f342d5f05a20d8ad44bc3e3507e23";

    struct Real {
        idc: String,
        k: String,
        rate_max: u64,
        audience: String,
        payload: Vec<u8>,
    }

    fn real() -> Real {
        let v: Value = serde_json::from_str(REAL).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        Real {
            idc: s("idc"),
            k: s("k"),
            rate_max: v["rate_max"].as_u64().unwrap(),
            audience: s("audience"),
            payload: hex::decode(s("payload_hex")).unwrap(),
        }
    }

    fn req(payload: &[u8], idc: &str, config: Option<Value>) -> VerifyRequest {
        VerifyRequest {
            auth_type: LOGOS_ALLOWLIST_AUTH_TYPE.into(),
            payload_hex: hex::encode(payload),
            id_commitment_hex: idc.into(),
            rate: 100,
            config,
        }
    }

    fn verify(payload: &[u8], idc: &str, allow: &[&str]) -> Verdict {
        LogosAllowlistVector.verify(&req(payload, idc, Some(json!({ "allowlist": allow })))).unwrap()
    }

    #[track_caller]
    fn assert_reject(v: Verdict, needle: &str) {
        assert!(!v.ok, "expected reject containing {needle:?}, got accept");
        let r = v.reason.unwrap_or_default();
        assert!(r.contains(needle), "reason {r:?} lacks {needle:?}");
        assert!(v.nullifier.is_none());
    }

    #[test]
    fn recorded_node_signature_accepts_with_key_nullifier() {
        let r = real();
        assert_eq!((r.rate_max, r.audience.as_str()), (100, ""), "fixture binds the defaults");
        assert_eq!(u64::from_le_bytes(r.payload[160..].try_into().unwrap()), r.rate_max);
        let v = verify(&r.payload, &r.idc, &[&r.k]);
        assert!(v.ok, "{:?}", v.reason);
        assert_eq!(v.nullifier.as_deref(), Some(r.k.as_str()));
        // Through the module-method glue too.
        let reply: Value = serde_json::from_str(&crate::AllowlistAuth::default().verify_auth(
            json!({
                "auth_type": LOGOS_ALLOWLIST_AUTH_TYPE,
                "payload_hex": format!("0X{}", hex::encode(&r.payload)),
                "id_commitment_hex": r.idc,
                "rate": 100,
                "config": { "allowlist": [r.k] }
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["nullifier"], r.k);
    }

    #[test]
    fn fixture_digest_exceeds_the_field_modulus() {
        // The node signs Fr::from_le_bytes_mod_order(digest). A fixture digest
        // >= p proves producer and verifier agree on that reduction; one < p
        // would also pass a verifier that (wrongly) required a canonical digest.
        let r = real();
        let d = digest(&zksign_light::hex32_bytes("idc", &r.idc).unwrap(), r.rate_max, &r.audience);
        assert!(!is_canonical_fr(&d), "fixture digest {} is < p; re-record with another idc", hex::encode(d));
    }

    #[test]
    fn rate_above_signed_rate_max_rejects() {
        let r = real();
        let mut q = req(&r.payload, &r.idc, Some(json!({ "allowlist": [r.k] })));
        q.rate = r.rate_max + 1;
        assert_reject(LogosAllowlistVector.verify(&q).unwrap(), "rate 101 exceeds the signed rate_max 100");
        q.rate = 1;
        assert!(LogosAllowlistVector.verify(&q).unwrap().ok, "a lower rate is within the signed bound");
    }

    #[test]
    fn altered_rate_max_or_other_audience_rejects() {
        let r = real();
        let mut p = r.payload.clone();
        p[160..].copy_from_slice(&1000u64.to_le_bytes());
        assert_reject(verify(&p, &r.idc, &[&r.k]), "zkSign signature invalid");
        let cfg = json!({ "allowlist": [r.k], "audience": "other-gifter" });
        assert_reject(LogosAllowlistVector.verify(&req(&r.payload, &r.idc, Some(cfg))).unwrap(), "zkSign signature invalid");
    }

    #[test]
    fn flipped_signature_bytes_reject() {
        let r = real();
        // pi_a, pi_b, pi_c, last byte of pi_c
        for off in [32usize, 64, 128, 159] {
            let mut p = r.payload.clone();
            p[off] ^= 0x01;
            assert_reject(verify(&p, &r.idc, &[&r.k]), "zkSign signature invalid");
        }
    }

    #[test]
    fn other_commitment_rejects() {
        let r = real();
        let mut idc = hex::decode(&r.idc).unwrap();
        idc[0] ^= 0x01;
        assert_reject(verify(&r.payload, &hex::encode(idc), &[&r.k]), "zkSign signature invalid");
        assert_reject(verify(&r.payload, "abcd", &[&r.k]), "id_commitment_hex");
    }

    #[test]
    fn unlisted_key_rejects_before_proof_check() {
        let r = real();
        let mut p = r.payload.clone();
        p[100] ^= 0xff; // would also fail the proof; the allowlist reason must win
        assert_reject(verify(&p, &r.idc, &["11".repeat(32).as_str()]), "not allowlisted");
    }

    #[test]
    fn wrong_length_and_bad_hex_reject() {
        let r = real();
        let mut long = r.payload.clone();
        long.push(0);
        assert_reject(verify(&long, &r.idc, &[&r.k]), "168 bytes");
        assert_reject(verify(&r.payload[..160], &r.idc, &[&r.k]), "168 bytes");
        let mut q = req(&r.payload, &r.idc, Some(json!({ "allowlist": [r.k] })));
        q.payload_hex = "zz".into();
        assert_reject(LogosAllowlistVector.verify(&q).unwrap(), "payload hex");
        q.payload_hex = format!("0x0x{}", hex::encode(&r.payload));
        assert_reject(LogosAllowlistVector.verify(&q).unwrap(), "payload hex");
    }

    #[test]
    fn byte_reversed_key_rejects() {
        let r = real();
        let mut p = r.payload.clone();
        p[..32].reverse();
        // The reversed key cannot be allowlisted (it is >= p, see
        // non_canonical_allowlist_entry_is_an_operator_error), so it is unlisted.
        assert_reject(verify(&p, &r.idc, &[&r.k]), "not allowlisted");
    }

    #[test]
    fn zero_key_rejects_even_if_allowlisted() {
        let r = real();
        let z = zero_pk_le();
        let mut p = z.to_vec();
        p.extend_from_slice(&r.payload[32..]);
        assert_reject(verify(&p, &r.idc, &[&hex::encode(z)]), "zero key");
    }

    #[test]
    fn missing_empty_or_malformed_config_is_an_operator_error() {
        let r = real();
        let e = |c: Option<Value>| LogosAllowlistVector.verify(&req(&r.payload, &r.idc, c)).unwrap_err();
        assert!(e(None).contains("required"));
        assert!(e(Some(json!({}))).contains("required"));
        assert!(e(Some(json!({ "allowlist": [] }))).contains("empty"));
        assert!(e(Some(json!({ "allowlist": [1] }))).contains("strings"));
        assert!(e(Some(json!({ "allowlist": ["abcd"] }))).contains("64 hex"));
        let bad_vk = e(Some(json!({ "allowlist": [r.k], "zksign_vk_path": "/nonexistent/vk.json" })));
        assert!(bad_vk.contains("zksign_vk_path"), "{bad_vk}");
        assert!(e(Some(json!({ "allowlist": [r.k], "zksign_vk_path": 7 }))).contains("zksign_vk_path"));
        assert!(e(Some(json!({ "allowlist": [r.k], "audience": 7 }))).contains("config.audience"));
        assert!(e(Some(json!({ "allowlist": [r.k], "audience": "x".repeat(256) }))).contains("255 bytes"));
    }

    #[test]
    fn non_canonical_allowlist_entry_is_an_operator_error() {
        let r = real();
        // p = 0x30644e72…f0000001 big-endian; 0xff..ff as LE is far above it.
        let e = LogosAllowlistVector
            .verify(&req(&r.payload, &r.idc, Some(json!({ "allowlist": [r.k, "ff".repeat(32)] }))))
            .unwrap_err();
        assert!(e.contains("not a canonical BN254 scalar (big-endian paste?)"), "{e}");
        // The fixture key pasted big-endian: its first LE byte (0xe2) becomes
        // the top byte, which puts the value above p.
        let mut be = hex::decode(&r.k).unwrap();
        be.reverse();
        let e = LogosAllowlistVector
            .verify(&req(&r.payload, &r.idc, Some(json!({ "allowlist": [hex::encode(be)] }))))
            .unwrap_err();
        assert!(e.contains("big-endian paste?"), "{e}");
    }

    #[test]
    fn wrong_shape_vk_file_is_an_operator_error_not_a_reject() {
        let r = real();
        let mut vk: Value = serde_json::from_str(zksign_light::DEFAULT_VK_JSON).unwrap();
        vk["IC"].as_array_mut().unwrap().pop();
        let path = std::env::temp_dir().join(format!("logos-auth-badvk-{}.json", std::process::id()));
        std::fs::write(&path, vk.to_string()).unwrap();
        let cfg = json!({ "allowlist": [r.k], "zksign_vk_path": path.to_string_lossy() });
        let e = LogosAllowlistVector.verify(&req(&r.payload, &r.idc, Some(cfg))).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(e.contains("zksign_vk_path") && e.contains("vk shape"), "{e}");
    }

    #[test]
    fn replaced_vk_file_is_picked_up() {
        let r = real();
        let path = std::env::temp_dir().join(format!("logos-auth-vk-swap-{}.json", std::process::id()));
        let cfg = json!({ "allowlist": [r.k], "zksign_vk_path": path.to_string_lossy() });
        std::fs::write(&path, zksign_light::DEFAULT_VK_JSON).unwrap();
        assert!(LogosAllowlistVector.verify(&req(&r.payload, &r.idc, Some(cfg.clone()))).unwrap().ok);
        // Same path, different contents (and length): the cached VK must not be reused.
        let mut vk: Value = serde_json::from_str(zksign_light::DEFAULT_VK_JSON).unwrap();
        vk["IC"].as_array_mut().unwrap().pop();
        std::fs::write(&path, vk.to_string()).unwrap();
        let e = LogosAllowlistVector.verify(&req(&r.payload, &r.idc, Some(cfg))).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(e.contains("vk shape"), "{e}");
    }

    #[test]
    fn prefixed_and_uppercase_allowlist_entries_match() {
        let r = real();
        let entry = format!("0x{}", r.k.to_uppercase());
        let v = verify(&r.payload, &r.idc.to_uppercase(), &[&entry]);
        assert!(v.ok, "{:?}", v.reason);
        assert_eq!(v.nullifier.as_deref(), Some(r.k.as_str()));
    }

    #[test]
    fn explicit_vk_path_verifies() {
        let r = real();
        let path = std::env::temp_dir().join(format!("logos-auth-vk-{}.json", std::process::id()));
        std::fs::write(&path, zksign_light::DEFAULT_VK_JSON).unwrap();
        let cfg = json!({ "allowlist": [r.k], "zksign_vk_path": path.to_string_lossy() });
        let v = LogosAllowlistVector.verify(&req(&r.payload, &r.idc, Some(cfg))).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(v.ok, "{:?}", v.reason);
    }

    #[test]
    fn digest_is_domain_separated_sha256() {
        let idc = [7u8; 32];
        let mut buf = b"logos/rln/logos-sign/2".to_vec();
        buf.extend_from_slice(&idc);
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.extend_from_slice(b"aud");
        assert_eq!(digest(&idc, 5, "aud"), <[u8; 32]>::from(Sha256::digest(&buf)));
    }

    #[test]
    fn digest_known_answer() {
        let idc: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(hex::encode(digest(&idc, 100, "")), DIGEST_KAT);
    }
}
