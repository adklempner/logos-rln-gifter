//! A PoW reward claim as the authoriser sees it: the owning key `K` (from the
//! logos scheme part) plus the evidence the payload carries, little-endian:
//! `flags(1) | claim_block_id(32) | pow_nullifier(32) | [spend_block_id(32) | spend_tx_hash(32)]`.

pub const FLAG_SPEND_LOCATOR: u8 = 0x01;
pub const EVIDENCE_BASE: usize = 65;
pub const EVIDENCE_WITH_SPEND: usize = 129;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub claim_block_id: [u8; 32],
    pub pow_nullifier: [u8; 32],
    /// `(spend_block_id, spend_tx_hash)`; present iff `flags & 1`.
    pub spend: Option<([u8; 32], [u8; 32])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The zkSign key that owns the claim (32-byte LE Fr).
    pub k: [u8; 32],
    pub evidence: Evidence,
}

fn take32(b: &[u8], off: &mut usize) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&b[*off..*off + 32]);
    *off += 32;
    o
}

impl Evidence {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(EVIDENCE_WITH_SPEND);
        v.push(if self.spend.is_some() { FLAG_SPEND_LOCATOR } else { 0 });
        v.extend_from_slice(&self.claim_block_id);
        v.extend_from_slice(&self.pow_nullifier);
        if let Some((b, t)) = &self.spend {
            v.extend_from_slice(b);
            v.extend_from_slice(t);
        }
        v
    }

    /// The evidence at the front of `b`, and what follows it.
    pub fn decode(b: &[u8]) -> Result<(Evidence, &[u8]), String> {
        let flags = *b.first().ok_or("evidence: empty")?;
        if flags & !FLAG_SPEND_LOCATOR != 0 {
            return Err(format!("evidence: unknown flags 0x{flags:02x}"));
        }
        let has_spend = flags & FLAG_SPEND_LOCATOR != 0;
        let want = if has_spend { EVIDENCE_WITH_SPEND } else { EVIDENCE_BASE };
        if b.len() < want {
            return Err(format!("evidence: {} bytes, want {want} for flags 0x{flags:02x}", b.len()));
        }
        let mut off = 1;
        let claim_block_id = take32(b, &mut off);
        let pow_nullifier = take32(b, &mut off);
        let spend = has_spend.then(|| {
            let sb = take32(b, &mut off);
            let st = take32(b, &mut off);
            (sb, st)
        });
        Ok((Evidence { claim_block_id, pow_nullifier, spend }, &b[off..]))
    }
}

impl Claim {
    /// Human-readable summary (hex fields).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "k": hex::encode(self.k),
            "claim_block_id": hex::encode(self.evidence.claim_block_id),
            "pow_nullifier": hex::encode(self.evidence.pow_nullifier),
            "spend_block_id": self.evidence.spend.map(|s| hex::encode(s.0)),
            "spend_tx_hash": self.evidence.spend.map(|s| hex::encode(s.1)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(spend: bool) -> Evidence {
        Evidence {
            claim_block_id: [0x22; 32],
            pow_nullifier: [0x33; 32],
            spend: spend.then_some(([0x44; 32], [0x55; 32])),
        }
    }

    #[test]
    fn round_trip_and_lengths() {
        for spend in [false, true] {
            let ev = sample(spend);
            let e = ev.encode();
            assert_eq!(e.len(), if spend { 129 } else { 65 });
            assert_eq!(e[0], u8::from(spend));
            assert_eq!(&e[1..33], &[0x22; 32]);
            assert_eq!(&e[33..65], &[0x33; 32]);
            if spend {
                assert_eq!(&e[65..97], &[0x44; 32]);
                assert_eq!(&e[97..129], &[0x55; 32]);
            }
            let mut framed = e.clone();
            framed.extend_from_slice(b"rest");
            let (back, rest) = Evidence::decode(&framed).unwrap();
            assert_eq!(back, ev);
            assert_eq!(rest, b"rest");
        }
    }

    #[test]
    fn decode_errors() {
        let mut e = sample(false).encode();
        assert!(Evidence::decode(&e[..64]).unwrap_err().contains("want 65"));
        e[0] = 1;
        assert!(Evidence::decode(&e).unwrap_err().contains("want 129"));
        e[0] = 2;
        assert!(Evidence::decode(&e).unwrap_err().contains("flags"));
        assert!(Evidence::decode(&[]).is_err());
    }
}
