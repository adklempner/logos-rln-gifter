//! The reject reasons and operator-error messages the pieces share, so the
//! wording is written once and suites can match it.

use std::fmt::Display;

use crate::authtype::AuthType;

pub const SIG_FAILED: &str = "signature verification failed";
pub const ALLOWLIST_EMPTY: &str = "config.allowlist is empty — nothing can verify";
pub const ENTRIES_NOT_STRINGS: &str = "config.allowlist entries must be strings";
/// The host's libp2p bridge did not report the requester's peer id.
pub const TRANSPORT_PEER_UNKNOWN: &str =
    "transport peer id unavailable: the host's libp2p bridge reports none";

pub fn sig_failed(detail: impl Display) -> String {
    format!("{SIG_FAILED}: {detail}")
}
pub fn payload_hex(e: impl Display) -> String {
    format!("payload hex: {e}")
}
pub fn idc_hex(e: impl Display) -> String {
    format!("id_commitment hex: {e}")
}
pub fn idc_len(got: usize) -> String {
    format!("id_commitment must be 32 bytes, got {got}")
}
pub fn rate_exceeds(rate: u64, rate_max: u64) -> String {
    format!("rate {rate} exceeds the signed rate_max {rate_max}")
}
pub fn not_allowlisted(what: &str, id: &str) -> String {
    format!("{what} not allowlisted: {id}")
}
pub fn allowlist_required(what: &str) -> String {
    format!("config.allowlist (array of {what}) is required")
}
pub fn trailing_bytes(n: usize) -> String {
    format!("payload has {n} trailing bytes")
}
pub fn identity_mismatch(claimed: &str, proven: &str) -> String {
    format!("payload names {claimed} but the signature proves {proven}")
}
/// An `auth_type` this registry cannot serve (error envelope, not a reject).
pub fn unknown_composition(t: &AuthType, why: impl Display) -> String {
    format!("unknown auth_type '{t}': {why}")
}
