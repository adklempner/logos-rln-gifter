use pow_claim_verify::*;
use sha2::{Digest, Sha256};

#[test]
fn vk_asset() {
    assert_eq!(
        hex::encode(Sha256::digest(DEFAULT_VK_JSON.as_bytes())),
        "b6f8a7861308f0df1a7ead87f4d8158f59104738bb24a24b18904f0bbbbe0df9"
    );
    let v: serde_json::Value = serde_json::from_str(DEFAULT_VK_JSON).unwrap();
    assert_eq!(v["nPublic"], 33);
    // VK parses into a prepared key: the failure (if any) must come from proof decode, not VK.
    if let Err(e) = verify_sig(DEFAULT_VK_JSON, &[0; 32], &[0; 32], &[0; 128]) {
        assert!(!e.starts_with("vk"), "{e}");
    }
}

fn mk(flags: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    v[0] = 1;
    v[1] = flags;
    v
}

#[test]
fn decode_ok_and_errors() {
    let p = decode_payload(&mk(0, 234)).unwrap();
    assert!(p.spend_block_id.is_none());
    let mut b = mk(1, 298);
    b[2] = 7;
    b[98..106].copy_from_slice(&42u64.to_le_bytes());
    b[106] = 9;
    b[138] = 8;
    let p = decode_payload(&b).unwrap();
    assert_eq!(p.k[0], 7);
    assert_eq!(p.rate_max, 42);
    assert_eq!(p.spend_block_id.unwrap()[0], 9);
    assert_eq!(p.spend_tx_hash.unwrap()[0], 8);
    assert!(decode_payload(&mk(0, 298)).is_err());
    assert!(decode_payload(&mk(1, 234)).is_err());
    let mut bad = mk(0, 234);
    bad[0] = 2;
    assert!(decode_payload(&bad).is_err());
    assert!(decode_payload(&mk(2, 234)).is_err());
    assert!(decode_payload(&[]).is_err());
}

#[test]
fn digest_kat() {
    let (idc, n) = ([1u8; 32], [2u8; 32]);
    let d = challenge_digest("poc", &idc, 100, &n);
    let mut m = b"logos:rln:gifter:pow-claim:v1\0".to_vec();
    m.push(3);
    m.extend_from_slice(b"poc");
    m.extend_from_slice(&idc);
    m.extend_from_slice(&100u64.to_le_bytes());
    m.extend_from_slice(&n);
    use blake2::{digest::consts::U32, Blake2b};
    assert_eq!(d.as_slice(), Blake2b::<U32>::digest(&m).as_slice());
    assert_eq!(hex::encode(d), "dd833fb8b6f9fd02cdac550dd73fab22329f7ca34a010ae2b4d46e92b8d89e39");
}

#[test]
fn zero_pk_pinned() {
    use ark_ff::{BigInteger, PrimeField};
    let h = hex::encode(zero_pk().into_bigint().to_bytes_le());
    // Poseidon2::compress([KDF=0x46444B, 0]), LE bytes.
    assert_eq!(h, "2b63b28bf67e435571f69fd684a317c3afed69b46f786d04f7d8e254c144e824");
}

#[test]
fn random_proof_no_panic() {
    let mut z = [0u8; 128];
    let mut x = 0x9e3779b97f4a7c15u64;
    for b in z.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let r = verify_sig(DEFAULT_VK_JSON, &[1; 32], &[2; 32], &z);
    assert!(matches!(r, Ok(false) | Err(_)));
}
