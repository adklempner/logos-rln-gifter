// BIP-340 lez-allowlist PRODUCER: signs sha256("logos/rln/lez-sign/1" ||
// id_commitment) with a secp256k1 key used as a LEZ public-account key
// (untweaked, x-only), exactly what allowlist-auth-module's lez.rs verifies.
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

pub const LEZ_ALLOWLIST_AUTH_TYPE: &str = "lez-allowlist";
/// Byte-for-byte the verifier's `DOMAIN`.
pub const DOMAIN: &[u8] = b"logos/rln/lez-sign/1";
/// LEE's public account-id prefix (exactly 32 bytes, zero-padded).
pub const LEE_ACCOUNT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/Public/\x00\x00\x00\x00\x00";

/// A private key as given (not BIP-340-normalised), so what is persisted and
/// imported elsewhere is the caller's own scalar.
#[derive(Clone)]
pub struct LezKey(pub(crate) [u8; 32]);

pub fn digest(id_commitment: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(id_commitment);
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
        let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
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

    pub fn sign_commitment(&self, id_commitment_hex: &str) -> Result<String, String> {
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
        Ok(ProduceReply { payload_hex: key.sign_commitment(&req.id_commitment_hex)? })
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
    pub(crate) fn verify(idc_hex: &str, payload_hex: &str) -> Result<String, String> {
        let p = hex::decode(payload_hex).unwrap();
        assert_eq!(p.len(), 96);
        let vk = VerifyingKey::from_bytes(&p[..32]).map_err(|e| e.to_string())?;
        let sig = Signature::try_from(&p[32..]).map_err(|e| e.to_string())?;
        vk.verify_prehash(&digest(&hex::decode(idc_hex).unwrap()), &sig).map_err(|e| e.to_string())?;
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
            let payload = k.sign_commitment(IDC).unwrap();
            assert_eq!(verify(IDC, &payload).unwrap(), hex::encode(account_id_of(&k.xonly())), "sk {n}");
        }
        assert!(seen_odd);
    }

    #[test]
    fn flipped_signature_rejects() {
        let k3 = LezKey::parse(SK3).unwrap();
        let mut p = hex::decode(k3.sign_commitment(IDC).unwrap()).unwrap();
        p[40] ^= 0x01;
        assert!(verify(IDC, &hex::encode(p)).is_err());
    }
}
