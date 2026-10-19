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
//!   an operator-supplied one ([`verify::PreparedVk`], [`verify::verify_sig`]).
//! - feature `client`: plain-http client for a local node
//!   ([`client::pow_status`], [`client::sign_zk`], [`client::parse_sig_reply`]).
//! - always: [`strip_0x`], [`norm_hex32`], [`hex32_bytes`].

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "verify")]
pub mod verify;

#[cfg(feature = "client")]
pub use client::{parse_sig_reply, pow_status, sign_zk, SIGN_MIN_TIMEOUT_MS};
#[cfg(feature = "verify")]
pub use verify::{default_vk, is_canonical_fr, verify_sig, zero_pk, zero_pk_le, PreparedVk, DEFAULT_VK_JSON};

/// `s` trimmed, with at most ONE leading `0x`/`0X` removed (unlike
/// `trim_start_matches("0x")`, which eats `0x0x…` and misses `0X`).
pub fn strip_0x(s: &str) -> &str {
    let t = s.trim();
    t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t)
}

/// Normalise a 32-byte hex field: strip optional `0x`/`0X`, lowercase,
/// require exactly 64 hex chars. `field` names the value in the error.
pub fn norm_hex32(field: &str, s: &str) -> Result<String, String> {
    let t = strip_0x(s).to_ascii_lowercase();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{field}: expected 64 hex chars (32 bytes), got {s:?}"));
    }
    Ok(t)
}

/// [`norm_hex32`] decoded to bytes (no byte-order change).
pub fn hex32_bytes(field: &str, s: &str) -> Result<[u8; 32], String> {
    let h = norm_hex32(field, s)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(&h, &mut out).map_err(|e| format!("{field}: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_normalises_and_names_field() {
        let up = format!("0X{}", "AB".repeat(32));
        assert_eq!(norm_hex32("k", &up).unwrap(), "ab".repeat(32));
        assert_eq!(norm_hex32("k", &format!(" 0x{} ", "cd".repeat(32))).unwrap(), "cd".repeat(32));
        assert_eq!(hex32_bytes("k", &"01".repeat(32)).unwrap(), [1u8; 32]);
        for bad in ["abc".to_string(), "zz".repeat(32), "aa".repeat(33)] {
            assert!(norm_hex32("public_key", &bad).unwrap_err().starts_with("public_key:"));
        }
        assert!(norm_hex32("k", &format!("0x0x{}", "ab".repeat(31))).is_err(), "only one prefix is stripped");
    }

    #[test]
    fn strip_0x_removes_one_prefix_of_either_case() {
        assert_eq!(strip_0x(" 0xab "), "ab");
        assert_eq!(strip_0x("0XAB"), "AB");
        assert_eq!(strip_0x("0x0xab"), "0xab");
        assert_eq!(strip_0x("ab"), "ab");
    }
}
