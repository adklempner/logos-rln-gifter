//! The keycard signer: drive the physical card over PC/SC in-process —
//! connect → select → IDENTIFY_CARD with the binding digest as the
//! challenge. IDENTIFY_CARD is a public plain-channel command (no pairing,
//! no PIN); `select()` leaves the secure channel closed, so the APDU travels
//! in the clear. The part is the raw IDENTIFY TLV.

use keycard_attest::attest::parse_attestation;
use keycard_client::Keycard;
use rln_auth_vector::{Binding, Identity, Signer};
use serde_json::Value;

use crate::scheme::keycard::{KeycardIdentity, NAME};

pub struct KeycardSigner;

fn identify(challenge: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut kc = Keycard::connect()?;
    kc.select()?;
    if !kc.initialized {
        return Err("card is not initialized".into());
    }
    kc.identify(challenge)
}

impl Signer for KeycardSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    fn sign(
        &self,
        _b: &Binding,
        digest: &[u8; 32],
        _args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let tlv = identify(digest)?;
        // Sanity: the card answered a parseable attestation for this challenge.
        parse_attestation(&tlv).map_err(|e| format!("parse attestation: {e}"))?;
        Ok(tlv)
    }
    /// The card's identity key, read through an IDENTIFY over a zero challenge.
    fn identity(&self, _args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        let tlv = identify(&[0u8; 32])?;
        let att = parse_attestation(&tlv).map_err(|e| format!("parse attestation: {e}"))?;
        Ok(Box::new(KeycardIdentity {
            ident_pub: att.ident_pub,
            ca_sig: att.ca_sig,
        }))
    }
}
