//! Wire payload (§3.3), little-endian:
//! `version(1)=1 | flags(1) | K(32) | claim_block_id(32) | pow_nullifier(32) |
//! rate_max u64 LE(8) | [spend_block_id(32) | spend_tx_hash(32)] | zksig(128)`.

pub const VERSION: u8 = 1;
pub const FLAG_SPEND_LOCATOR: u8 = 0x01;
pub const LEN_BASE: usize = 234;
pub const LEN_WITH_SPEND: usize = 298;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub version: u8,
    pub flags: u8,
    pub k: [u8; 32],
    pub claim_block_id: [u8; 32],
    pub pow_nullifier: [u8; 32],
    pub rate_max: u64,
    /// `(spend_block_id, spend_tx_hash)`; present iff `flags & 1`.
    pub spend: Option<([u8; 32], [u8; 32])>,
    /// `pi_a(32) ‖ pi_b(64) ‖ pi_c(32)` (compressed Groth16).
    pub zksig: [u8; 128],
}

fn take32(b: &[u8], off: &mut usize) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&b[*off..*off + 32]);
    *off += 32;
    o
}

impl Payload {
    /// Encodes; bit0 of `flags` is derived from `spend` (the stored bit is ignored).
    pub fn encode(&self) -> Vec<u8> {
        let mut flags = self.flags & !FLAG_SPEND_LOCATOR;
        if self.spend.is_some() {
            flags |= FLAG_SPEND_LOCATOR;
        }
        let mut v = Vec::with_capacity(LEN_WITH_SPEND);
        v.push(self.version);
        v.push(flags);
        v.extend_from_slice(&self.k);
        v.extend_from_slice(&self.claim_block_id);
        v.extend_from_slice(&self.pow_nullifier);
        v.extend_from_slice(&self.rate_max.to_le_bytes());
        if let Some((b, t)) = &self.spend {
            v.extend_from_slice(b);
            v.extend_from_slice(t);
        }
        v.extend_from_slice(&self.zksig);
        v
    }

    pub fn decode(b: &[u8]) -> Result<Payload, String> {
        if b.len() < 2 {
            return Err(format!("payload too short: {} bytes", b.len()));
        }
        if b[0] != VERSION {
            return Err(format!("unsupported payload version {}", b[0]));
        }
        let flags = b[1];
        if flags & !FLAG_SPEND_LOCATOR != 0 {
            return Err(format!("unknown payload flags 0x{flags:02x}"));
        }
        let has_spend = flags & FLAG_SPEND_LOCATOR != 0;
        let want = if has_spend { LEN_WITH_SPEND } else { LEN_BASE };
        if b.len() != want {
            return Err(format!(
                "payload length {} != {want} for flags 0x{flags:02x}",
                b.len()
            ));
        }
        let mut off = 2;
        let k = take32(b, &mut off);
        let claim_block_id = take32(b, &mut off);
        let pow_nullifier = take32(b, &mut off);
        let rate_max = u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        off += 8;
        let spend = if has_spend {
            let sb = take32(b, &mut off);
            let st = take32(b, &mut off);
            Some((sb, st))
        } else {
            None
        };
        let mut zksig = [0u8; 128];
        zksig.copy_from_slice(&b[off..off + 128]);
        Ok(Payload {
            version: VERSION,
            flags,
            k,
            claim_block_id,
            pow_nullifier,
            rate_max,
            spend,
            zksig,
        })
    }

    /// Human-readable summary (hex fields).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "flags": self.flags,
            "k": hex::encode(self.k),
            "claim_block_id": hex::encode(self.claim_block_id),
            "pow_nullifier": hex::encode(self.pow_nullifier),
            "rate_max": self.rate_max,
            "spend_block_id": self.spend.map(|s| hex::encode(s.0)),
            "spend_tx_hash": self.spend.map(|s| hex::encode(s.1)),
            "zksig": {
                "pi_a": hex::encode(&self.zksig[..32]),
                "pi_b": hex::encode(&self.zksig[32..96]),
                "pi_c": hex::encode(&self.zksig[96..]),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(spend: bool) -> Payload {
        let mut zksig = [0u8; 128];
        for (i, b) in zksig.iter_mut().enumerate() {
            *b = i as u8;
        }
        Payload {
            version: VERSION,
            flags: u8::from(spend),
            k: [0x11; 32],
            claim_block_id: [0x22; 32],
            pow_nullifier: [0x33; 32],
            rate_max: 0x0102_0304_0506_0708,
            spend: spend.then_some(([0x44; 32], [0x55; 32])),
            zksig,
        }
    }

    #[test]
    fn round_trip_and_lengths() {
        for spend in [false, true] {
            let p = sample(spend);
            let e = p.encode();
            assert_eq!(e.len(), if spend { 298 } else { 234 });
            assert_eq!(e[0], 1);
            assert_eq!(e[1], u8::from(spend));
            assert_eq!(&e[2..34], &[0x11; 32]);
            assert_eq!(&e[34..66], &[0x22; 32]);
            assert_eq!(&e[66..98], &[0x33; 32]);
            assert_eq!(&e[98..106], &[8, 7, 6, 5, 4, 3, 2, 1]);
            if spend {
                assert_eq!(&e[106..138], &[0x44; 32]);
                assert_eq!(&e[138..170], &[0x55; 32]);
            }
            assert_eq!(&e[e.len() - 128..], &p.zksig[..]);
            assert_eq!(Payload::decode(&e).unwrap(), p);
        }
    }

    #[test]
    fn decode_errors() {
        let mut e = sample(false).encode();
        assert!(Payload::decode(&e[..233]).unwrap_err().contains("length"));
        let mut long = e.clone();
        long.push(0);
        assert!(Payload::decode(&long).is_err());
        // flag says spend but length is base
        e[1] = 1;
        assert!(Payload::decode(&e).unwrap_err().contains("length"));
        e[1] = 2;
        assert!(Payload::decode(&e).unwrap_err().contains("flags"));
        e[1] = 0;
        e[0] = 2;
        assert!(Payload::decode(&e).unwrap_err().contains("version"));
        assert!(Payload::decode(&[]).is_err());
    }
}
