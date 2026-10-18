// BIP-340 lez-allowlist VERIFIER for gifted RLN registration — the server-side
// half of the LEZ auth vector (the producer half is lez-sign-module). The
// payload is a LEZ public-account key (x-only secp256k1, 32 B) and its BIP-340
// Schnorr signature (64 B) over sha256(DOMAIN || id_commitment). The key's LEZ
// account id is checked against the operator's allowlist and is the
// nullifier, so each allowlisted account grants one membership.
// FEATURE: RLN gifter lez-allowlist auth vector (verify)

use base58::FromBase58;
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use rln_auth_vector::{dispatch_verify, AuthVector, Verdict, VerifyRequest};
use sha2::{Digest, Sha256};

pub const LEZ_ALLOWLIST_AUTH_TYPE: &str = "lez-allowlist";

/// Domain of the signed digest — distinct from LEE's own `/LEE/` prefixes, so
/// a signature made here can never be replayed as a LEZ transaction.
pub const DOMAIN: &[u8] = b"logos/rln/lez-sign/1";

/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
pub const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

pub trait LezAuthModule: Send + 'static {
    /// rln_auth_vector VERIFY_METHOD for auth_type "lez-allowlist". One
    /// JSON-string arg (VerifyRequest); payload: x-only public key (32 B) ||
    /// BIP-340 signature (64 B) over sha256("logos/rln/lez-sign/1" ||
    /// id_commitment); config: `{"allowlist": ["<64 hex or base58 account
    /// id>", …]}`. Accepts with the account id (lowercase hex) as the
    /// nullifier. `{"ok", "reason"?, "nullifier"?}` or `{"error"}`.
    fn verify_auth(&mut self, args_json: String) -> String;
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

#[derive(Default)]
struct LezAuth {}

struct LezAllowlistVector;

/// The digest the producer signs (prehash; BIP-340 signs it as the message).
pub fn digest(id_commitment: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.finalize().into()
}

/// LEE public account id: sha256(LEE_ACCOUNT_ID_PREFIX || xonly).
pub fn account_id(xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEE_ACCOUNT_ID_PREFIX);
    h.update(xonly);
    h.finalize().into()
}

/// An account id as the wallet shows it — 64 hex (optional 0x, any case) or
/// base58 decoding to exactly 32 bytes — normalised to lowercase hex.
pub fn parse_account_id(s: &str) -> Result<String, String> {
    let s = s.trim();
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(h.to_ascii_lowercase());
    }
    let bytes = s.from_base58().map_err(|e| format!("account id '{s}': neither 64 hex nor base58 ({e:?})"))?;
    if bytes.len() != 32 {
        return Err(format!("account id '{s}': base58 decodes to {} bytes, want 32", bytes.len()));
    }
    Ok(hex::encode(bytes))
}

impl AuthVector for LezAllowlistVector {
    fn auth_type(&self) -> &'static str {
        LEZ_ALLOWLIST_AUTH_TYPE
    }

    // Malformed config is an Err (operator mistake, error envelope); a bad
    // payload, bad signature or unlisted account is a REJECT verdict.
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let entries = req
            .config
            .as_ref()
            .and_then(|c| c.get("allowlist"))
            .and_then(|v| v.as_array())
            .ok_or("config.allowlist (array of LEZ account ids, 64 hex or base58) is required")?;
        let allowlist: Vec<String> = entries
            .iter()
            .map(|e| e.as_str().ok_or_else(|| "allowlist entries must be strings".to_string()).and_then(parse_account_id))
            .collect::<Result<_, _>>()?;
        if allowlist.is_empty() {
            return Err("config.allowlist is empty — nothing can verify".into());
        }

        let payload = match hex::decode(req.payload_hex.trim_start_matches("0x")) {
            Ok(p) => p,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        if payload.len() != 96 {
            return Ok(Verdict::reject(format!(
                "payload must be 96 bytes (xonly pubkey || BIP-340 sig), got {}",
                payload.len()
            )));
        }
        let idc = match hex::decode(req.id_commitment_hex.trim_start_matches("0x")) {
            Ok(c) if c.len() == 32 => c,
            Ok(c) => return Ok(Verdict::reject(format!("id_commitment must be 32 bytes, got {}", c.len()))),
            Err(e) => return Ok(Verdict::reject(format!("id_commitment hex: {e}"))),
        };
        let vk = match VerifyingKey::from_bytes(&payload[..32]) {
            Ok(k) => k,
            Err(e) => return Ok(Verdict::reject(format!("public key: {e}"))),
        };
        let sig = match Signature::try_from(&payload[32..]) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("signature: {e}"))),
        };
        if vk.verify_prehash(&digest(&idc), &sig).is_err() {
            return Ok(Verdict::reject("signature verification failed"));
        }
        let xonly: [u8; 32] = payload[..32].try_into().unwrap();
        let acct = hex::encode(account_id(&xonly));
        if !allowlist.contains(&acct) {
            return Ok(Verdict::reject(format!("account not allowlisted: {acct}")));
        }
        Ok(Verdict::accept(Some(acct)))
    }
}

impl LezAuthModule for LezAuth {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn verify_auth(&mut self, args_json: String) -> String {
        dispatch_verify(&args_json, &[&LezAllowlistVector])
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LezAuth>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use base58::ToBase58;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::schnorr::SigningKey;
    use k256::SecretKey;

    const IDC: [u8; 32] = [0x11; 32];
    // BIP-340 test vector 0: sk = 3.
    const BIP340_PK0: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    // python3: hashlib.sha256(b"/LEE/v0.3/AccountId/Public/" + b"\0"*5 + pk).hexdigest(), base58 (Bitcoin alphabet).
    const PK0_ACCT_HEX: &str = "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
    const PK0_ACCT_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";

    fn sk_bytes(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = n;
        b
    }

    /// LEE's x-only derivation: the x coordinate of the (un-normalised) point.
    fn lee_xonly(sk: &[u8; 32]) -> [u8; 32] {
        let pk = SecretKey::from_slice(sk).unwrap().public_key();
        let enc = pk.to_encoded_point(false);
        (*enc.x().unwrap()).into()
    }

    fn odd_y(sk: &[u8; 32]) -> bool {
        let pk = SecretKey::from_slice(sk).unwrap().public_key();
        pk.to_encoded_point(true).as_bytes()[0] == 0x03
    }

    fn request(sk: &[u8; 32], allow: Vec<String>) -> VerifyRequest {
        let key = SigningKey::from_bytes(sk).unwrap();
        let sig = key.sign_prehash_with_aux_rand(&digest(&IDC), &[0x55; 32]).unwrap();
        let mut payload = lee_xonly(sk).to_vec();
        payload.extend_from_slice(&sig.to_bytes());
        VerifyRequest {
            auth_type: LEZ_ALLOWLIST_AUTH_TYPE.into(),
            payload_hex: hex::encode(payload),
            id_commitment_hex: hex::encode(IDC),
            rate: 100,
            config: Some(serde_json::json!({ "allowlist": allow })),
        }
    }

    fn acct_of(sk: &[u8; 32]) -> String {
        hex::encode(account_id(&lee_xonly(sk)))
    }

    #[test]
    fn lee_prefix_is_32_bytes() {
        assert_eq!(LEE_ACCOUNT_ID_PREFIX.len(), 32);
        assert!(LEE_ACCOUNT_ID_PREFIX.starts_with(b"/LEE/v0.3/AccountId/Public/"));
    }

    #[test]
    fn xonly_equals_lee_derivation_for_even_and_odd_keys() {
        let mut seen_odd = false;
        let mut seen_even = false;
        for n in 1..=8u8 {
            let sk = sk_bytes(n);
            if odd_y(&sk) { seen_odd = true } else { seen_even = true }
            let vk_bytes: [u8; 32] = SigningKey::from_bytes(&sk).unwrap().verifying_key().to_bytes().into();
            assert_eq!(vk_bytes, lee_xonly(&sk), "sk {n}");
        }
        assert!(seen_odd && seen_even);
    }

    #[test]
    fn account_id_known_answer_bip340_vector0() {
        assert_eq!(hex::encode(lee_xonly(&sk_bytes(3))), BIP340_PK0);
        let pk: [u8; 32] = hex::decode(BIP340_PK0).unwrap().try_into().unwrap();
        let acct = account_id(&pk);
        assert_eq!(hex::encode(acct), PK0_ACCT_HEX);
        assert_eq!(acct.to_base58(), PK0_ACCT_B58);
        assert_eq!(parse_account_id(PK0_ACCT_B58).unwrap(), PK0_ACCT_HEX);
    }

    #[test]
    fn round_trip_accepts_with_account_nullifier_incl_odd_y() {
        let odd = (1..=20u8).map(sk_bytes).find(odd_y).expect("an odd-Y key");
        let even = (1..=20u8).map(sk_bytes).find(|k| !odd_y(k)).expect("an even-Y key");
        for sk in [odd, even, [0x42; 32]] {
            let acct = acct_of(&sk);
            let v = LezAllowlistVector.verify(&request(&sk, vec![acct.clone()])).unwrap();
            assert!(v.ok, "{:?}", v.reason);
            assert_eq!(v.nullifier.as_deref(), Some(acct.as_str()));
        }
    }

    #[test]
    fn hex_and_base58_allowlist_forms_match() {
        let sk = [0x42; 32];
        let acct = account_id(&lee_xonly(&sk));
        for entry in [hex::encode(acct), format!("0x{}", hex::encode(acct).to_uppercase()), acct.to_base58()] {
            let v = LezAllowlistVector.verify(&request(&sk, vec![entry.clone()])).unwrap();
            assert!(v.ok, "{entry}: {:?}", v.reason);
        }
    }

    #[test]
    fn base58_of_33_bytes_is_an_operator_error() {
        let b58 = [0x01u8; 33].to_base58();
        assert!(parse_account_id(&b58).unwrap_err().contains("33 bytes"));
        let req = request(&[0x42; 32], vec![b58]);
        assert!(LezAllowlistVector.verify(&req).unwrap_err().contains("33 bytes"));
    }

    #[test]
    fn flipped_signature_or_key_or_idc_rejects() {
        let sk = [0x42; 32];
        let base = request(&sk, vec![acct_of(&sk)]);
        let bytes = hex::decode(&base.payload_hex).unwrap();
        for i in [0usize, 31, 32, 63, 64, 95] {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            let mut req = base.clone();
            req.payload_hex = hex::encode(b);
            assert!(!LezAllowlistVector.verify(&req).unwrap().ok, "flip at {i}");
        }
        let mut req = base.clone();
        req.id_commitment_hex = hex::encode([0x12u8; 32]);
        assert!(!LezAllowlistVector.verify(&req).unwrap().ok);
    }

    #[test]
    fn unlisted_account_rejects_with_its_id() {
        let sk = [0x42; 32];
        let v = LezAllowlistVector.verify(&request(&sk, vec![PK0_ACCT_HEX.into()])).unwrap();
        assert!(!v.ok);
        let reason = v.reason.unwrap();
        assert!(reason.contains("not allowlisted") && reason.contains(&acct_of(&sk)), "{reason}");
    }

    #[test]
    fn bad_payload_lengths_and_hex_reject() {
        let sk = [0x42; 32];
        let base = request(&sk, vec![acct_of(&sk)]);
        for p in ["zz".to_string(), base.payload_hex[..190].to_string(), format!("{}00", base.payload_hex)] {
            let mut req = base.clone();
            req.payload_hex = p;
            assert!(!LezAllowlistVector.verify(&req).unwrap().ok);
        }
        let mut req = base.clone();
        req.id_commitment_hex = "abcd".into();
        assert!(LezAllowlistVector.verify(&req).unwrap().reason.unwrap().contains("32 bytes"));
    }

    #[test]
    fn missing_or_empty_allowlist_is_an_operator_error() {
        let mut req = request(&[0x42; 32], vec![]);
        assert!(LezAllowlistVector.verify(&req).unwrap_err().contains("empty"));
        req.config = None;
        assert!(LezAllowlistVector.verify(&req).unwrap_err().contains("required"));
        req.config = Some(serde_json::json!({ "allowlist": [42] }));
        assert!(LezAllowlistVector.verify(&req).is_err());
    }

    #[test]
    fn dispatch_speaks_the_contract() {
        let sk = [0x42; 32];
        let req = request(&sk, vec![acct_of(&sk)]);
        let out: serde_json::Value =
            serde_json::from_str(&LezAuth::default().verify_auth(serde_json::to_string(&req).unwrap())).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["nullifier"], acct_of(&sk));
    }
}
