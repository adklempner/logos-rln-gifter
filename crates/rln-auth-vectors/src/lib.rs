//! The RLN gifter's auth-vector pieces, composed by `rln_auth_vector`'s
//! registries: an `auth_type` is `<scheme>-<authoriser>`.
//!
//! Schemes ([`scheme`]): how a binding digest gets signed and which identity
//! that proves — `eth` (EIP-191 over the bare commitment, any wallet),
//! `lez` (BIP-340 by a LEZ account key), `logos` (a node's zkSign key),
//! `keycard` (a Keycard's identity key over IDENTIFY_CARD), `peer` (no
//! signature: the libp2p peer id the transport authenticated).
//!
//! Authorisers ([`authoriser`]): how an identity gets accepted — `allowlist`
//! (operator list, any scheme), `any` (every identity, once each, any
//! scheme), `attestation` (a trusted Keycard CA, keycard only), `pow-claim`
//! (a settled PoW reward claim on chain, logos only).
//!
//! Feature `sign` adds the produce halves: [`signer`] and [`claimant`].

#[cfg(feature = "verify")]
pub mod authoriser;
#[cfg(feature = "sign")]
pub mod claimant;
pub mod scheme;
#[cfg(feature = "sign")]
pub mod signer;
