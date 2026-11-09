//! The `attestation` authoriser: the card's identity key is certified by a
//! trusted Keycard CA (the cert signature travels on the keycard identity).
//! Composes with the keycard scheme only. No evidence; the once-per-card
//! nullifier is `keccak256(ident_pub)`.

use std::any::Any;

use keycard_attest::attest::{nullifier, recover_ca};
use rln_auth_vector::{
    downcast_identity, parse_audience, strip_0x, Authoriser, Cfg, Check, Evidence, Identity,
    Outcome, Scheme,
};
use serde_json::Value;

use crate::scheme::keycard::{KeycardIdentity, NAME as KEYCARD};

pub const NAME: &str = "attestation";

struct Config {
    trusted_cas: Vec<[u8; 33]>,
    audience: String,
}

/// `config.trusted_cas`: 33-byte compressed CA keys, hex.
pub fn parse_trusted_cas(raw: Option<&Value>) -> Result<Vec<[u8; 33]>, String> {
    let arr = raw
        .and_then(|c| c.get("trusted_cas"))
        .and_then(Value::as_array)
        .ok_or("config.trusted_cas (array of 33-byte CA pubkey hex) is required")?;
    let mut cas = Vec::with_capacity(arr.len());
    for e in arr {
        let s = e
            .as_str()
            .ok_or("config.trusted_cas entries must be hex strings")?;
        let bytes =
            hex::decode(strip_0x(s)).map_err(|e| format!("config.trusted_cas entry {s:?}: {e}"))?;
        let ca: [u8; 33] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("config.trusted_cas entry {s:?}: must be 33 bytes"))?;
        cas.push(ca);
    }
    if cas.is_empty() {
        return Err("config.trusted_cas is empty — nothing can verify".into());
    }
    Ok(cas)
}

pub struct Attestation;

impl Authoriser for Attestation {
    fn name(&self) -> &'static str {
        NAME
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == KEYCARD
    }
    fn config(&self, _scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
        Ok(Box::new(Config {
            trusted_cas: parse_trusted_cas(raw)?,
            audience: parse_audience(raw.and_then(|c| c.get("audience")), "config.audience")?,
        }))
    }
    fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str {
        cfg.downcast_ref::<Config>()
            .map(|c| c.audience.as_str())
            .unwrap_or("")
    }
    fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
        Outcome::Ok((Box::new(()), rest))
    }
    fn extra(&self, _ev: &dyn Any) -> Vec<u8> {
        Vec::new()
    }
    fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, _ev: &dyn Any) -> Check<()> {
        let cfg = cfg
            .downcast_ref::<Config>()
            .ok_or("attestation: config is not an attestation config")?;
        let card = downcast_identity::<KeycardIdentity>(id)
            .ok_or("attestation: identity is not a keycard identity")?;
        let ca = match recover_ca(&card.ident_pub, &card.ca_sig) {
            Ok(ca) => ca,
            Err(e) => {
                return Ok(Outcome::Reject(format!(
                    "attestation verification failed: {e}"
                )))
            }
        };
        if !cfg.trusted_cas.contains(&ca) {
            return Ok(Outcome::Reject(
                "attestation verification failed: attestation CA is not trusted".into(),
            ));
        }
        Ok(Outcome::Ok(()))
    }
    fn nullifier(&self, id: &dyn Identity, _ev: &dyn Any) -> String {
        match downcast_identity::<KeycardIdentity>(id) {
            Some(card) => hex::encode(nullifier(&card.ident_pub)),
            None => id.canonical(),
        }
    }
}
