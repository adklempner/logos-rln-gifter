//! Claimants: the produce halves of the authorisers — the evidence to bind.

pub mod pow_claim;

use rln_auth_vector::{Binding, Claimant};
use serde_json::Value;

pub use pow_claim::PowClaimant;

use crate::scheme::keycard::NAME as KEYCARD;

/// An authoriser that binds no evidence: `allowlist` (any scheme).
pub struct AllowlistClaimant;

impl Claimant for AllowlistClaimant {
    fn authoriser(&self) -> &'static str {
        "allowlist"
    }
    fn accepts(&self, _scheme: &str) -> bool {
        true
    }
    fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

/// `attestation` binds no evidence either (the CA cert travels in the
/// keycard part), and composes with the keycard scheme only.
pub struct AttestationClaimant;

impl Claimant for AttestationClaimant {
    fn authoriser(&self) -> &'static str {
        "attestation"
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == KEYCARD
    }
    fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}
