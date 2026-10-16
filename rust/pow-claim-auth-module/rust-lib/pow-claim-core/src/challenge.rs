//! Challenge digest (§3.2).

use blake2::{digest::consts::U32, Blake2b, Digest as _};

pub const DOMAIN: &[u8] = b"logos:rln:gifter:pow-claim:v1\0";

/// `Blake2b-256(DOMAIN ‖ u8 len(audience) ‖ audience ‖ idc ‖ rate_max LE ‖ pow_nullifier)`.
///
/// `pow_nullifier` is the hex-decoded node JSON value, i.e. already the Fr in
/// little-endian bytes. Panics if `audience` exceeds 255 bytes (args parsing
/// rejects that earlier).
pub fn digest(
    audience: &str,
    id_commitment: &[u8; 32],
    rate_max: u64,
    pow_nullifier: &[u8; 32],
) -> [u8; 32] {
    let a = audience.as_bytes();
    let len = u8::try_from(a.len()).expect("audience <= 255 bytes");
    let mut h = Blake2b::<U32>::new();
    h.update(DOMAIN);
    h.update([len]);
    h.update(a);
    h.update(id_commitment);
    h.update(rate_max.to_le_bytes());
    h.update(pow_nullifier);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KAT: &str = "dd833fb8b6f9fd02cdac550dd73fab22329f7ca34a010ae2b4d46e92b8d89e39";

    #[test]
    fn known_answer_and_layout() {
        let idc = [0x01u8; 32];
        let nul = [0x02u8; 32];
        let d = digest("poc", &idc, 100, &nul);

        // Independent layout: one manually concatenated buffer.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"logos:rln:gifter:pow-claim:v1");
        buf.push(0);
        buf.push(3);
        buf.extend_from_slice(b"poc");
        buf.extend_from_slice(&[1u8; 32]);
        buf.extend_from_slice(&[100, 0, 0, 0, 0, 0, 0, 0]);
        buf.extend_from_slice(&[2u8; 32]);
        assert_eq!(buf.len(), 30 + 1 + 3 + 32 + 8 + 32);
        let ind: [u8; 32] = Blake2b::<U32>::digest(&buf).into();
        assert_eq!(d, ind);

        assert_eq!(hex::encode(d), KAT);
    }

    #[test]
    fn every_field_matters() {
        let base = digest("", &[1; 32], 100, &[2; 32]);
        assert_ne!(base, digest("x", &[1; 32], 100, &[2; 32]));
        assert_ne!(base, digest("", &[3; 32], 100, &[2; 32]));
        assert_ne!(base, digest("", &[1; 32], 101, &[2; 32]));
        assert_ne!(base, digest("", &[1; 32], 100, &[3; 32]));
    }
}
