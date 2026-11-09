//! Logos blockchain zkSign helpers shared by RLN gifter auth vectors.
//!
//! A node signs with `POST /wallet/sign/zk {"tx_hash":"<64 hex>","pks":[K…]}`:
//! a 128-byte compressed Groth16 proof (`pi_a(32)‖pi_b(64)‖pi_c(32)`) over
//! BN254 that the holder of the listed keys signed
//! `Fr::from_le_bytes_mod_order(tx_hash)` — no hashing or domain inside, so
//! callers bind their own domain into the 32 digest bytes. Keys are 32-byte
//! little-endian Fr hex (`/pow/status auto_claim.targets[].public_key`).
//!
//! - feature `verify`: offline verification against the bundled v0.5.7 VK or
//!   an operator-supplied one ([`verify::PreparedVk`], [`verify::verify_sig`],
//!   [`verify::vk_from_config`]).
//! - feature `client`: plain-http client for a local node
//!   ([`client::pow_status`], [`client::sign_zk`], [`client::parse_sig_reply`])
//!   and the [`client::ZkNode`] seam over it.
//! - always: the hex helpers, re-exported from `rln_auth_vector::hex`.

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "verify")]
pub mod verify;

#[cfg(feature = "client")]
pub use client::{parse_sig_reply, pow_status, sign_zk, HttpZkNode, ZkNode, SIGN_MIN_TIMEOUT_MS};
pub use rln_auth_vector::hex::{hex32_bytes, norm_hex32, strip_0x};
#[cfg(feature = "verify")]
pub use verify::{
    default_vk, is_canonical_fr, verify_sig, vk_from_config, vk_from_path_cached, zero_pk,
    zero_pk_le, PreparedVk, VkSource, DEFAULT_VK_JSON,
};
