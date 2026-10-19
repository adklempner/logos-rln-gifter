// BIP-340 lez-allowlist PRODUCER: signs sha256("logos/rln/lez-sign/2" ||
// id_commitment || rate_max LE || audience) with a secp256k1 key used as a LEZ
// public-account key (untweaked, x-only), exactly what allowlist-auth-module's
// lez.rs verifies. The payload is `xonly(32) || sig(64) || rate_max LE(8)`.
// Importing the same private key into a LEZ wallet yields the same account id.
// FEATURE: RLN gifter lez-allowlist auth vector (produce)

use base58::ToBase58;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::SecretKey;
use rand_core::RngCore;
use rln_auth_vector::{AuthVector, ProduceReply, ProduceRequest};
use serde_json::json;
use sha2::{Digest, Sha256};
use zksign_light::strip_0x;

use crate::args::Binding;

pub const LEZ_ALLOWLIST_AUTH_TYPE: &str = "lez-allowlist";
/// Byte-for-byte the verifier's `DOMAIN`.
pub const DOMAIN: &[u8] = b"logos/rln/lez-sign/2";
/// `xonly(32) || BIP-340 sig(64) || rate_max u64 LE(8)`.
pub const PAYLOAD_LEN: usize = 32 + 64 + 8;
/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
pub const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

/// A private key as given (not BIP-340-normalised), so what is persisted and
/// imported elsewhere is the caller's own scalar.
#[derive(Clone)]
pub struct LezKey(pub(crate) [u8; 32]);

/// `sha256(DOMAIN || id_commitment || rate_max LE || audience)`.
pub fn digest(id_commitment: &[u8], rate_max: u64, audience: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
    h.update(rate_max.to_le_bytes());
    h.update(audience.as_bytes());
    h.finalize().into()
}

pub fn account_id_of(xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEE_ACCOUNT_ID_PREFIX);
    h.update(xonly);
    h.finalize().into()
}

impl LezKey {
    pub fn parse(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(strip_0x(hex_str))
            .map_err(|e| format!("private key hex: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| format!("private key must be 32 bytes, got {}", b.len()))?;
        SigningKey::from_bytes(&arr).map_err(|e| format!("private key: {e}"))?;
        Ok(LezKey(arr))
    }

    pub fn random() -> Self {
        LezKey(SecretKey::random(&mut rand_core::OsRng).to_bytes().into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// LEE's x-only key: the x coordinate of the public point (identical
    /// whether or not BIP-340 normalises the scalar to even Y).
    pub fn xonly(&self) -> [u8; 32] {
        let pk = SecretKey::from_slice(&self.0).expect("validated").public_key();
        (*pk.to_encoded_point(false).x().expect("not identity")).into()
    }

    /// `{"account_id","account_id_base58","public_key"}`.
    pub fn identity(&self) -> serde_json::Value {
        let xonly = self.xonly();
        let acct = account_id_of(&xonly);
        json!({
            "account_id": hex::encode(acct),
            "account_id_base58": acct.to_base58(),
            "public_key": hex::encode(xonly),
        })
    }

    pub fn sign_commitment(&self, id_commitment_hex: &str, binding: &Binding) -> Result<String, String> {
        let idc = hex::decode(strip_0x(id_commitment_hex))
            .map_err(|e| format!("id_commitment hex: {e}"))?;
        if idc.len() != 32 {
            return Err(format!("id_commitment must be 32 bytes, got {}", idc.len()));
        }
        let sk = SigningKey::from_bytes(&self.0).map_err(|e| format!("private key: {e}"))?;
        let mut aux = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut aux);
        let sig = sk
            .sign_prehash_with_aux_rand(&digest(&idc, binding.rate_max, &binding.audience), &aux)
            .map_err(|e| format!("sign: {e}"))?;
        let mut out = self.xonly().to_vec();
        out.extend_from_slice(&sig.to_bytes());
        out.extend_from_slice(&binding.rate_max.to_le_bytes());
        Ok(hex::encode(out))
    }
}

/// One produce call's vector: borrows the key chosen for this request (None
/// when the request is for another auth type, so no key was resolved).
pub struct LezSignVector<'a> {
    pub key: Option<&'a LezKey>,
}

impl AuthVector for LezSignVector<'_> {
    fn auth_type(&self) -> &'static str {
        LEZ_ALLOWLIST_AUTH_TYPE
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        let key = self.key.ok_or("lez-allowlist: no signing key resolved")?;
        let binding = Binding::parse(req.args.as_ref())?;
        Ok(ProduceReply { payload_hex: key.sign_commitment(&req.id_commitment_hex, &binding)? })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::schnorr::signature::hazmat::PrehashVerifier;
    use k256::schnorr::{Signature, VerifyingKey};

    // BIP-340 test vector 0 (sk = 3) and its LEZ account id (python3:
    // sha256(b"/LEE/v0.3/AccountId/Public/" + b"\0"*5 + pk), base58 Bitcoin alphabet).
    pub(crate) const SK3: &str = "0x0000000000000000000000000000000000000000000000000000000000000003";
    const PK3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    pub(crate) const ACCT3_HEX: &str = "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
    pub(crate) const ACCT3_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";
    pub(crate) const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    // The verifier's check, re-implemented so the two crates stay
    // independent: verify, then derive the account id from the x-only key.
    /// Audience "" (the verifier's default config).
    pub(crate) fn verify(idc_hex: &str, payload_hex: &str) -> Result<String, String> {
        let p = hex::decode(payload_hex).unwrap();
        assert_eq!(p.len(), PAYLOAD_LEN);
        let rate_max = u64::from_le_bytes(p[96..].try_into().unwrap());
        let vk = VerifyingKey::from_bytes(&p[..32]).map_err(|e| e.to_string())?;
        let sig = Signature::try_from(&p[32..96]).map_err(|e| e.to_string())?;
        vk.verify_prehash(&digest(&hex::decode(idc_hex).unwrap(), rate_max, ""), &sig).map_err(|e| e.to_string())?;
        Ok(hex::encode(account_id_of(&p[..32].try_into().unwrap())))
    }

    fn odd_y(k: &LezKey) -> bool {
        SecretKey::from_slice(&k.0).unwrap().public_key().to_encoded_point(true).as_bytes()[0] == 0x03
    }

    #[test]
    fn lee_prefix_is_32_bytes() {
        assert_eq!(LEE_ACCOUNT_ID_PREFIX.len(), 32);
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
            let payload = k.sign_commitment(IDC, &Binding::default()).unwrap();
            assert_eq!(verify(IDC, &payload).unwrap(), hex::encode(account_id_of(&k.xonly())), "sk {n}");
        }
        assert!(seen_odd);
    }

    #[test]
    fn flipped_signature_rejects() {
        let k3 = LezKey::parse(SK3).unwrap();
        let mut p = hex::decode(k3.sign_commitment(IDC, &Binding::default()).unwrap()).unwrap();
        p[40] ^= 0x01;
        assert!(verify(IDC, &hex::encode(p)).is_err());
    }

    /// Known answer shared with allowlist-auth-module's lez.rs: idc
    /// 0x01..0x20, rate_max 100, audience "".
    const DIGEST_KAT: &str = "3b5bcfabef3fef4858767259de7a02b44f9e0d2bf076447e492e55cdb0e87f61";

    #[test]
    fn digest_known_answer() {
        assert_eq!(hex::encode(digest(&hex::decode(IDC).unwrap(), 100, "")), DIGEST_KAT);
    }

    #[test]
    fn rate_max_and_audience_are_bound() {
        let k3 = LezKey::parse(SK3).unwrap();
        let b = Binding { rate_max: 7, audience: "gifter-a".into() };
        let p = hex::decode(k3.sign_commitment(IDC, &b).unwrap()).unwrap();
        assert_eq!(p[96..], 7u64.to_le_bytes());
        assert!(verify(IDC, &hex::encode(&p)).is_err(), "signed for audience gifter-a, checked with \"\"");
        let vk = VerifyingKey::from_bytes(&p[..32]).unwrap();
        let sig = Signature::try_from(&p[32..96]).unwrap();
        vk.verify_prehash(&digest(&hex::decode(IDC).unwrap(), 7, "gifter-a"), &sig).unwrap();
    }
}
