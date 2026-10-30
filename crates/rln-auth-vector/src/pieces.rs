//! The pieces a vector is composed of. Verify side: a [`Scheme`] proves an
//! [`Identity`] from a signature over the binding digest; an [`Authoriser`]
//! accepts that identity (and binds any evidence it needs). Produce side: a
//! [`Signer`] makes the scheme part, a [`Claimant`] gathers the evidence.
//!
//! Two failure channels everywhere: [`Outcome::Reject`] is the requester's
//! problem and becomes a `Verdict` (or, on the produce side, an error the
//! requester caused); `Err(String)` is the operator's or the host's problem
//! and becomes the `{"error"}` envelope.

use std::any::Any;

use serde_json::Value;

use crate::binding::Binding;

/// A decision about untrusted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T> {
    Ok(T),
    Reject(String),
}

/// `Err` = operator/host error (envelope); `Ok(Reject)` = refused input.
pub type Check<T> = Result<Outcome<T>, String>;

/// Operator configuration an authoriser parsed, opaque to the flow.
pub type Cfg = Box<dyn Any + Send + Sync>;
/// Evidence an authoriser decoded from the payload, opaque to the flow.
pub type Evidence = Box<dyn Any + Send + Sync>;

/// Who signed. `canonical` is the lowercase form an operator writes in an
/// allowlist and the default nullifier.
pub trait Identity: Any + Send + Sync {
    fn canonical(&self) -> String;
    fn as_any(&self) -> &dyn Any;
}

pub fn downcast_identity<T: 'static>(id: &dyn Identity) -> Option<&T> {
    id.as_any().downcast_ref::<T>()
}

/// A scheme part split off the front of the payload body.
pub struct Decoded<'a> {
    /// The identity the part names, when it carries one (a public key); the
    /// flow checks it against the identity the signature proves. `None` when
    /// the signature itself yields the identity (recovery).
    pub claimed: Option<Box<dyn Identity>>,
    /// The scheme part's bytes.
    pub part: &'a [u8],
    /// What follows the part: the authoriser's evidence.
    pub rest: &'a [u8],
}

/// How a binding digest gets signed, and which identity that proves.
pub trait Scheme: Send + Sync {
    fn name(&self) -> &'static str;
    /// An identity as an operator writes it → its canonical form (`Err` names
    /// the entry).
    fn parse_identity(&self, s: &str) -> Result<String, String>;
    /// Split this scheme's part off the front of `body`.
    fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>>;
    /// The identity the part's signature proves over `digest` (a scheme that
    /// signs something else, such as eth's EIP-191 message over the bare
    /// commitment, derives it from `b` here).
    fn verify(&self, b: &Binding, digest: &[u8; 32], d: &Decoded<'_>) -> Check<Box<dyn Identity>>;
}

/// The produce half of a scheme: holds (or reaches) the key.
pub trait Signer: Send + Sync {
    fn scheme(&self) -> &'static str;
    /// The scheme part for this binding and digest.
    fn sign(&self, b: &Binding, digest: &[u8; 32]) -> Result<Vec<u8>, String>;
    /// The identity this signer proves.
    fn identity(&self) -> Result<Box<dyn Identity>, String>;
}

/// How an identity gets accepted, and what evidence that takes.
pub trait Authoriser: Send + Sync {
    fn name(&self) -> &'static str;
    /// Which schemes' identities this authoriser can judge.
    fn accepts(&self, scheme: &str) -> bool;
    /// Parse the operator's `config` for a composition with `scheme`.
    fn config(&self, scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String>;
    /// The audience the operator configured ("" when none).
    fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str;
    /// Split this authoriser's evidence off the front of `rest`.
    fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])>;
    /// The evidence bytes bound into the digest.
    fn extra(&self, ev: &dyn Any) -> Vec<u8>;
    /// Judge the identity the part CLAIMS before the signature is checked
    /// (cheap membership tests first); the proven identity is then only
    /// compared to the claim.
    fn before_sig(&self) -> bool {
        false
    }
    fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, ev: &dyn Any) -> Check<()>;
    fn nullifier(&self, id: &dyn Identity, ev: &dyn Any) -> String {
        let _ = ev;
        id.canonical()
    }
}

/// The produce half of an authoriser: gathers the evidence to bind.
pub trait Claimant: Send + Sync {
    fn authoriser(&self) -> &'static str;
    fn accepts(&self, scheme: &str) -> bool;
    /// The evidence bytes for this binding (empty for most authorisers).
    fn gather(&self, b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String>;
    /// The part of the evidence bound into the digest (must equal the
    /// verifier's [`Authoriser::extra`] for the same evidence).
    fn extra(&self, evidence: &[u8]) -> Vec<u8>;
}
