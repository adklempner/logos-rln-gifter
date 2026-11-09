//! The payload frame every composed vector uses:
//! `version(1) ‖ scheme part ‖ authoriser evidence ‖ rate_max u64 LE(8)`.
//! The scheme part and the evidence are each sized by their own decoder.

use crate::pieces::Outcome;

pub const PAYLOAD_VERSION: u8 = 2;

pub fn frame(scheme_part: &[u8], evidence: &[u8], rate_max: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + scheme_part.len() + evidence.len() + 8);
    v.push(PAYLOAD_VERSION);
    v.extend_from_slice(scheme_part);
    v.extend_from_slice(evidence);
    v.extend_from_slice(&rate_max.to_le_bytes());
    v
}

/// The body (`scheme part ‖ evidence`) and `rate_max` of a framed payload.
pub fn unframe(bytes: &[u8]) -> Outcome<(&[u8], u64)> {
    if bytes.len() < 9 {
        return Outcome::Reject(format!("payload too short: {} bytes", bytes.len()));
    }
    if bytes[0] != PAYLOAD_VERSION {
        return Outcome::Reject(format!(
            "payload version {}, want {PAYLOAD_VERSION}",
            bytes[0]
        ));
    }
    let (body, tail) = bytes[1..].split_at(bytes.len() - 9);
    Outcome::Ok((body, u64::from_le_bytes(tail.try_into().expect("8 bytes"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trips_and_pins_the_version() {
        let p = frame(b"part", b"ev", 300);
        assert_eq!(p[0], 2);
        assert_eq!(p.len(), 1 + 4 + 2 + 8);
        let Outcome::Ok((body, rate_max)) = unframe(&p) else {
            panic!()
        };
        assert_eq!((body, rate_max), (&b"partev"[..], 300));
        let empty = frame(b"", b"", 0);
        let Outcome::Ok((body, _)) = unframe(&empty) else {
            panic!()
        };
        assert!(body.is_empty());
        assert!(matches!(unframe(&p[..8]), Outcome::Reject(r) if r.contains("too short")));
        let mut old = p.clone();
        old[0] = 1;
        assert!(matches!(unframe(&old), Outcome::Reject(r) if r == "payload version 1, want 2"));
    }
}
