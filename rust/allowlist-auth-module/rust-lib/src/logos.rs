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
use zksign_light::{norm_hex32, verify_sig, zero_pk_le, PreparedVk};

// payload: `K(32) || zksig(128)`, a zkSign by the logos-blockchain key K
// (32-byte LE Fr) over `sha256("logos/rln/logos-sign/1" || id_commitment)`;
// config: `{"allowlist": ["<64 hex K>", …], "zksign_vk_path"?}`. Accepts with
// hex(K) as the nullifier.

pub const LOGOS_ALLOWLIST_AUTH_TYPE: &str = "logos-allowlist";
/// Domain of the signed digest; must match allowlist-sign-module's logos.rs.
pub const DOMAIN: &[u8] = b"logos/rln/logos-sign/1";
pub const PAYLOAD_LEN: usize = 32 + 128;

/// The 32 bytes the node signed: `sha256(DOMAIN || id_commitment)`.
pub fn digest(id_commitment: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
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

/// VKs from `config.zksign_vk_path`, prepared once per path.
fn vk_from_path(path: &str) -> Result<std::sync::Arc<PreparedVk>, String> {
    static CACHE: OnceLock<std::sync::Mutex<HashMap<String, std::sync::Arc<PreparedVk>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(v) = cache.lock().unwrap().get(path) {
        return Ok(v.clone());
    }
    let v = std::sync::Arc::new(PreparedVk::from_path(path)?);
    cache.lock().unwrap().insert(path.to_string(), v.clone());
    Ok(v)
}

struct Config {
    allowlist: Vec<String>,
    vk: Vk,
}

fn parse_config(config: Option<&serde_json::Value>) -> Result<Config, String> {
    let entries = config
        .and_then(|c| c.get("allowlist"))
        .and_then(|v| v.as_array())
        .ok_or("config.allowlist (array of 64-hex logos public keys) is required")?;
    let allowlist: Vec<String> = entries
        .iter()
        .map(|e| {
            let s = e.as_str().ok_or("config.allowlist entries must be strings")?;
            norm_hex32("config.allowlist entry", s)
        })
        .collect::<Result<_, String>>()?;
    if allowlist.is_empty() {
        return Err("config.allowlist is empty — nothing can verify".into());
    }
    let vk = match config.and_then(|c| c.get("zksign_vk_path")) {
        None | Some(serde_json::Value::Null) => Vk::Default(zksign_light::default_vk()?),
        Some(serde_json::Value::String(p)) if !p.trim().is_empty() => Vk::File(vk_from_path(p.trim())?),
        Some(v) => return Err(format!("config.zksign_vk_path: expected a non-empty string, got {v}")),
    };
    Ok(Config { allowlist, vk })
}

pub struct LogosAllowlistVector;

impl AuthVector for LogosAllowlistVector {
    fn auth_type(&self) -> &'static str {
        LOGOS_ALLOWLIST_AUTH_TYPE
    }

    // Malformed config is an Err (operator mistake, error envelope); a bad
    // payload/commitment, an unlisted key or an invalid signature is a REJECT
    // verdict (untrusted input, normal flow). The allowlist check runs before
    // the (costlier) proof verification.
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let cfg = parse_config(req.config.as_ref())?;

        let payload = match hex::decode(req.payload_hex.trim().trim_start_matches("0x")) {
            Ok(p) => p,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        if payload.len() != PAYLOAD_LEN {
            return Ok(Verdict::reject(format!(
                "payload must be {PAYLOAD_LEN} bytes (K 32 || zksig 128), got {}",
                payload.len()
            )));
        }
        let idc = match zksign_light::hex32_bytes("id_commitment_hex", &req.id_commitment_hex) {
            Ok(c) => c,
            Err(e) => return Ok(Verdict::reject(e)),
        };
        let k: [u8; 32] = payload[..32].try_into().unwrap();
        let sig: [u8; 128] = payload[32..].try_into().unwrap();
        let k_hex = hex::encode(k);
        if !cfg.allowlist.contains(&k_hex) {
            return Ok(Verdict::reject(format!("public key not allowlisted: {k_hex}")));
        }
        if k == zero_pk_le() {
            return Ok(Verdict::reject("public key is the zero key"));
        }
        if let Err(e) = verify_sig(cfg.vk.get(), &k, &digest(&idc), &sig) {
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

    /// Recorded by logos-sign-module's ignored real-node test (follower node
    /// 0.3.2, its test PoWClaim key): `{idc, k, payload_hex}`.
    const REAL: &str = include_str!("../tests/fixtures/logos_sign_real.json");

    struct Real {
        idc: String,
        k: String,
        payload: Vec<u8>,
    }

    fn real() -> Real {
        let v: Value = serde_json::from_str(REAL).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        Real { idc: s("idc"), k: s("k"), payload: hex::decode(s("payload_hex")).unwrap() }
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
        let v = verify(&r.payload, &r.idc, &[&r.k]);
        assert!(v.ok, "{:?}", v.reason);
        assert_eq!(v.nullifier.as_deref(), Some(r.k.as_str()));
        // Through the module-method glue too.
        let reply: Value = serde_json::from_str(&crate::AllowlistAuth::default().verify_auth(
            json!({
                "auth_type": LOGOS_ALLOWLIST_AUTH_TYPE,
                "payload_hex": format!("0x{}", hex::encode(&r.payload)),
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
        assert_reject(verify(&long, &r.idc, &[&r.k]), "160 bytes");
        assert_reject(verify(&r.payload[..159], &r.idc, &[&r.k]), "160 bytes");
        let mut q = req(&r.payload, &r.idc, Some(json!({ "allowlist": [r.k] })));
        q.payload_hex = "zz".into();
        assert_reject(LogosAllowlistVector.verify(&q).unwrap(), "payload hex");
    }

    #[test]
    fn byte_reversed_key_rejects() {
        let r = real();
        let mut p = r.payload.clone();
        p[..32].reverse();
        let rev = hex::encode(&p[..32]);
        assert_reject(verify(&p, &r.idc, &[&rev]), "zkSign signature invalid");
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
        let mut buf = b"logos/rln/logos-sign/1".to_vec();
        buf.extend_from_slice(&idc);
        assert_eq!(digest(&idc), <[u8; 32]>::from(Sha256::digest(&buf)));
    }
}
