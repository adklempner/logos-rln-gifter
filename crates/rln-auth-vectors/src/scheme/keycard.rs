//! The `keycard` scheme: a Keycard's IDENTIFY_CARD attestation over the
//! binding digest as the challenge. The part is the raw IDENTIFY TLV
//! (`A0 { 8A cert(98), DER sig }`); the identity is the card's manufacturer
//! identity key `ident_pub`, which survives factory reset. The CA signature
//! inside the cert is carried on the identity for the `attestation`
//! authoriser to judge.

use std::any::Any;

#[cfg(feature = "verify")]
use keycard_attest::attest::{parse_attestation, tlv_len, verify_challenge};
use rln_auth_vector::{strip_0x, Identity};
#[cfg(feature = "verify")]
use rln_auth_vector::{Binding, Check, Decoded, Outcome, Scheme, Transport};

pub const NAME: &str = "keycard";

pub struct KeycardIdentity {
    pub ident_pub: [u8; 33],
    pub ca_sig: [u8; 65],
}

impl Identity for KeycardIdentity {
    /// 66 lowercase hex: the compressed identity key.
    fn canonical(&self) -> String {
        hex::encode(self.ident_pub)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A card identity as an operator writes it: 33-byte compressed key hex.
pub fn parse_ident_pub(s: &str) -> Result<String, String> {
    let h = strip_0x(s).to_ascii_lowercase();
    if h.len() != 66
        || !h.bytes().all(|b| b.is_ascii_hexdigit())
        || !(h.starts_with("02") || h.starts_with("03"))
    {
        return Err(format!("config.allowlist entry {s:?}: expected a compressed secp256k1 key (66 hex, 02/03 prefix)"));
    }
    Ok(h)
}

pub struct Keycard;

#[cfg(feature = "verify")]
impl Scheme for Keycard {
    fn name(&self) -> &'static str {
        NAME
    }
    fn identity_noun(&self) -> &'static str {
        "card"
    }
    fn parse_identity(&self, s: &str) -> Result<String, String> {
        parse_ident_pub(s)
    }
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
        let len = match tlv_len(body) {
            Ok(n) => n,
            Err(e) => return Outcome::Reject(format!("attestation parse failed: {e}")),
        };
        let (part, rest) = body.split_at(len);
        let att = match parse_attestation(part) {
            Ok(a) => a,
            Err(e) => return Outcome::Reject(format!("attestation parse failed: {e}")),
        };
        Outcome::Ok(Decoded {
            claimed: Some(Box::new(KeycardIdentity {
                ident_pub: att.ident_pub,
                ca_sig: att.ca_sig,
            })),
            part,
            rest,
        })
    }
    fn verify(
        &self,
        _cfg: &dyn Any,
        _b: &Binding,
        digest: &[u8; 32],
        d: &Decoded<'_>,
        _t: &Transport<'_>,
    ) -> Check<Box<dyn Identity>> {
        let att = match parse_attestation(d.part) {
            Ok(a) => a,
            Err(e) => return Ok(Outcome::Reject(format!("attestation parse failed: {e}"))),
        };
        if let Err(e) = verify_challenge(&att, digest) {
            return Ok(Outcome::Reject(format!(
                "attestation verification failed: {e}"
            )));
        }
        Ok(Outcome::Ok(Box::new(KeycardIdentity {
            ident_pub: att.ident_pub,
            ca_sig: att.ca_sig,
        })))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// keycard-go golden vector (recorded over a v1 challenge; still a valid
    /// attestation over THAT challenge, so it tests parse + verify_challenge).
    pub(crate) const GOLDEN_TLV: &str = "a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e";
    pub(crate) const GOLDEN_CHALLENGE: &str =
        "63acd6e02a8b5783551ff2836a9cbdf237c115c3ff018b943f044e6a69b19fe7";
    pub(crate) const TEST_CA: &str =
        "02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5";
    pub(crate) const IDENT_PUB: &str =
        "0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a";

    #[test]
    fn ident_pub_entries_normalise() {
        assert_eq!(
            parse_ident_pub(&format!("0X{}", IDENT_PUB.to_uppercase())).unwrap(),
            IDENT_PUB
        );
        assert_eq!(
            parse_ident_pub(TEST_CA).unwrap(),
            TEST_CA,
            "a CA key has the same shape"
        );
        assert!(parse_ident_pub(&IDENT_PUB[2..]).is_err());
        assert!(parse_ident_pub(&format!("04{}", &IDENT_PUB[2..])).is_err());
    }

    #[cfg(feature = "verify")]
    #[test]
    fn golden_tlv_decodes_and_verifies_its_challenge() {
        let tlv = hex::decode(GOLDEN_TLV).unwrap();
        let mut body = tlv.clone();
        body.extend_from_slice(b"rest");
        let Outcome::Ok(d) = Keycard.decode(&body) else {
            panic!()
        };
        assert_eq!(d.rest, b"rest");
        assert_eq!(d.claimed.as_ref().unwrap().canonical(), IDENT_PUB);
        let b = Binding {
            id_commitment: [0; 32],
            rate_max: 1,
            audience: String::new(),
        };
        let challenge: [u8; 32] = hex::decode(GOLDEN_CHALLENGE).unwrap().try_into().unwrap();
        let Outcome::Ok(id) = Keycard
            .verify(&(), &b, &challenge, &d, &Transport::default())
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(id.canonical(), IDENT_PUB);
        let Outcome::Reject(r) = Keycard
            .verify(&(), &b, &[9; 32], &d, &Transport::default())
            .unwrap()
        else {
            panic!()
        };
        assert!(r.starts_with("attestation verification failed"), "{r}");
        assert!(
            matches!(Keycard.decode(&tlv[..40]), Outcome::Reject(r) if r.starts_with("attestation parse failed"))
        );
    }
}
