// BIP-340 lez-allowlist VERIFIER for gifted RLN registration — the server-side
// half of the LEZ auth vector (the producer half is allowlist-sign-module). The
// payload is a LEZ public-account key (x-only secp256k1, 32 B), its BIP-340
// Schnorr signature (64 B) over
// sha256(DOMAIN || id_commitment || rate_max LE || audience) and that rate_max
// (u64 LE, 8 B). The key's LEZ account id is checked against the operator's
// allowlist and is the nullifier, so each allowlisted account grants one
// membership.
// FEATURE: RLN gifter lez-allowlist auth vector (verify)

use base58::FromBase58;
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use rln_auth_vector::{AuthVector, Verdict, VerifyRequest};
use sha2::{Digest, Sha256};
use zksign_light::strip_0x;

pub const LEZ_ALLOWLIST_AUTH_TYPE: &str = "lez-allowlist";

/// Domain of the signed digest — distinct from LEE's own `/LEE/` prefixes, so
/// a signature made here can never be replayed as a LEZ transaction.
pub const DOMAIN: &[u8] = b"logos/rln/lez-sign/2";
pub const PAYLOAD_LEN: usize = 32 + 64 + 8;
/// Longest accepted `config.audience`, as for pow-claim.
pub const MAX_AUDIENCE_LEN: usize = 255;

/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
pub const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

// payload: x-only public key (32 B) || BIP-340 signature (64 B) over
// sha256("logos/rln/lez-sign/2" || id_commitment || rate_max LE || audience)
// || rate_max u64 LE (8 B); config: `{"allowlist": ["<64 hex or base58
// account id>", …], "audience"?: ""}`. Rejects when the requested rate exceeds
// the signed rate_max. Accepts with the account id (lowercase hex) as the
// nullifier.

pub struct LezAllowlistVector;

/// The digest the producer signs (prehash; BIP-340 signs it as the message):
/// `sha256(DOMAIN || id_commitment || rate_max LE || audience)`.
pub fn digest(id_commitment: &[u8], rate_max: u64, audience: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.update(rate_max.to_le_bytes());
    h.update(audience.as_bytes());
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
    let h = strip_0x(s);
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
        let audience = match req.config.as_ref().and_then(|c| c.get("audience")) {
            None | Some(serde_json::Value::Null) => "",
            Some(serde_json::Value::String(s)) if s.len() <= MAX_AUDIENCE_LEN => s.as_str(),
            Some(serde_json::Value::String(s)) => {
                return Err(format!("config.audience: at most {MAX_AUDIENCE_LEN} bytes, got {}", s.len()))
            }
            Some(v) => return Err(format!("config.audience: expected a string, got {v}")),
        };

        let payload = match hex::decode(strip_0x(&req.payload_hex)) {
            Ok(p) => p,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        if payload.len() != PAYLOAD_LEN {
            return Ok(Verdict::reject(format!(
                "payload must be {PAYLOAD_LEN} bytes (xonly pubkey 32 || BIP-340 sig 64 || rate_max 8), got {}",
                payload.len()
            )));
        }
        let rate_max = u64::from_le_bytes(payload[96..].try_into().unwrap());
        if req.rate > rate_max {
            return Ok(Verdict::reject(format!("rate {} exceeds the signed rate_max {rate_max}", req.rate)));
        }
        let idc = match hex::decode(strip_0x(&req.id_commitment_hex)) {
            Ok(c) if c.len() == 32 => c,
            Ok(c) => return Ok(Verdict::reject(format!("id_commitment must be 32 bytes, got {}", c.len()))),
            Err(e) => return Ok(Verdict::reject(format!("id_commitment hex: {e}"))),
        };
        let vk = match VerifyingKey::from_bytes(&payload[..32]) {
            Ok(k) => k,
            Err(e) => return Ok(Verdict::reject(format!("public key: {e}"))),
        };
        let sig = match Signature::try_from(&payload[32..96]) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("signature: {e}"))),
        };
        if vk.verify_prehash(&digest(&idc, rate_max, audience), &sig).is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AllowlistAuthModule;
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

    /// Known answer shared with allowlist-sign-module's lez.rs: idc
    /// 0x01..0x20, rate_max 100, audience "".
    const DIGEST_KAT: &str = "3b5bcfabef3fef4858767259de7a02b44f9e0d2bf076447e492e55cdb0e87f61";

    fn payload_for(sk: &[u8; 32], rate_max: u64, audience: &str) -> Vec<u8> {
        let key = SigningKey::from_bytes(sk).unwrap();
        let sig = key.sign_prehash_with_aux_rand(&digest(&IDC, rate_max, audience), &[0x55; 32]).unwrap();
        let mut payload = lee_xonly(sk).to_vec();
        payload.extend_from_slice(&sig.to_bytes());
        payload.extend_from_slice(&rate_max.to_le_bytes());
        payload
    }

    fn request(sk: &[u8; 32], allow: Vec<String>) -> VerifyRequest {
        let payload = payload_for(sk, 100, "");
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
        for i in [0usize, 31, 32, 63, 64, 95, 96] {
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
        for p in ["zz".to_string(), base.payload_hex[..192].to_string(), format!("{}00", base.payload_hex)] {
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
    fn digest_known_answer() {
        let idc: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        assert_eq!(hex::encode(digest(&idc, 100, "")), DIGEST_KAT);
    }

    #[test]
    fn rate_is_bounded_by_the_signed_rate_max() {
        let sk = [0x42; 32];
        let mut req = request(&sk, vec![acct_of(&sk)]);
        req.rate = 101;
        let v = LezAllowlistVector.verify(&req).unwrap();
        assert!(!v.ok);
        assert_eq!(v.reason.unwrap(), "rate 101 exceeds the signed rate_max 100");
        req.rate = 100;
        assert!(LezAllowlistVector.verify(&req).unwrap().ok);
        // A forged larger rate_max breaks the signature.
        let mut p = hex::decode(&req.payload_hex).unwrap();
        p[96..].copy_from_slice(&1000u64.to_le_bytes());
        req.payload_hex = hex::encode(p);
        req.rate = 500;
        assert!(LezAllowlistVector.verify(&req).unwrap().reason.unwrap().contains("signature verification failed"));
    }

    #[test]
    fn audience_comes_from_the_verifier_config() {
        let sk = [0x42; 32];
        let mut req = request(&sk, vec![acct_of(&sk)]);
        req.payload_hex = hex::encode(payload_for(&sk, 100, "gifter-a"));
        assert!(!LezAllowlistVector.verify(&req).unwrap().ok, "signed for gifter-a, config audience is \"\"");
        req.config = Some(serde_json::json!({ "allowlist": [acct_of(&sk)], "audience": "gifter-a" }));
        assert!(LezAllowlistVector.verify(&req).unwrap().ok);
        req.config = Some(serde_json::json!({ "allowlist": [acct_of(&sk)], "audience": 7 }));
        assert!(LezAllowlistVector.verify(&req).unwrap_err().contains("config.audience"));
    }

    #[test]
    fn base58_with_leading_zero_bytes_round_trips() {
        let mut acct = [0x5au8; 32];
        acct[0] = 0;
        acct[1] = 0;
        let b58 = acct.to_base58();
        assert!(b58.starts_with("11") && !b58.starts_with("111"), "{b58}");
        assert_eq!(parse_account_id(&b58).unwrap(), hex::encode(acct));
    }

    #[test]
    fn single_case_insensitive_0x_prefix() {
        let sk = [0x42; 32];
        let mut req = request(&sk, vec![acct_of(&sk)]);
        req.payload_hex = format!("0X{}", req.payload_hex);
        req.id_commitment_hex = format!("0X{}", req.id_commitment_hex);
        assert!(LezAllowlistVector.verify(&req).unwrap().ok);
        req.payload_hex = format!("0x0x{}", &req.payload_hex[2..]);
        assert!(LezAllowlistVector.verify(&req).unwrap().reason.unwrap().contains("payload hex"));
    }

    #[test]
    fn dispatch_speaks_the_contract() {
        let sk = [0x42; 32];
        let req = request(&sk, vec![acct_of(&sk)]);
        let out: serde_json::Value =
            serde_json::from_str(&crate::AllowlistAuth::default().verify_auth(serde_json::to_string(&req).unwrap())).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["nullifier"], acct_of(&sk));
    }
}
