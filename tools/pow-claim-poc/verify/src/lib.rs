//! Offline verifier for pow-claim payloads. Deliberately independent of
//! `pow-claim-core`: payload decode and challenge digest are re-implemented.
use ark_ff::PrimeField;
use blake2::{digest::consts::U32, Blake2b, Digest as _};
use logos_blockchain_groth16::{
    fr_from_bytes, fr_from_bytes_unchecked, groth16_verify, CompressedGroth16Proof, Fr,
    Groth16Proof, Groth16VerificationKey, Groth16VerificationKeyJsonDeser,
};
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};

pub const DEFAULT_VK_JSON: &str = include_str!("../assets/zksign_vk_v0.5.7.json");
pub const DOMAIN: &[u8] = b"logos:rln:gifter:pow-claim:v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub version: u8,
    pub flags: u8,
    pub k: [u8; 32],
    pub claim_block_id: [u8; 32],
    pub pow_nullifier: [u8; 32],
    pub rate_max: u64,
    pub spend_block_id: Option<[u8; 32]>,
    pub spend_tx_hash: Option<[u8; 32]>,
    pub zksig: [u8; 128],
}

fn take32(bytes: &[u8], o: &mut usize) -> [u8; 32] {
    let v: [u8; 32] = bytes[*o..*o + 32].try_into().expect("32 bytes");
    *o += 32;
    v
}

pub fn decode_payload(bytes: &[u8]) -> Result<Payload, String> {
    if bytes.len() < 2 {
        return Err(format!("payload too short: {} bytes", bytes.len()));
    }
    let (version, flags) = (bytes[0], bytes[1]);
    if version != 1 {
        return Err(format!("unsupported version {version}"));
    }
    if flags & !1 != 0 {
        return Err(format!("unknown flag bits 0x{flags:02x}"));
    }
    let spend = flags & 1 == 1;
    let want = if spend { 298 } else { 234 };
    if bytes.len() != want {
        return Err(format!(
            "bad length {}, expected {want} for flags {flags}",
            bytes.len()
        ));
    }
    let mut o = 2;
    let k = take32(bytes, &mut o);
    let claim_block_id = take32(bytes, &mut o);
    let pow_nullifier = take32(bytes, &mut o);
    let rate_max = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    o += 8;
    let (spend_block_id, spend_tx_hash) = if spend {
        let a = take32(bytes, &mut o);
        let b = take32(bytes, &mut o);
        (Some(a), Some(b))
    } else {
        (None, None)
    };
    let zksig: [u8; 128] = bytes[o..]
        .try_into()
        .map_err(|_| "bad zksig length".to_string())?;
    Ok(Payload {
        version,
        flags,
        k,
        claim_block_id,
        pow_nullifier,
        rate_max,
        spend_block_id,
        spend_tx_hash,
        zksig,
    })
}

pub fn challenge_digest(
    audience: &str,
    idc: &[u8; 32],
    rate_max: u64,
    pow_nullifier: &[u8; 32],
) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(DOMAIN);
    h.update([audience.len() as u8]);
    h.update(audience.as_bytes());
    h.update(idc);
    h.update(rate_max.to_le_bytes());
    h.update(pow_nullifier);
    h.finalize().into()
}

/// Public key of the zero secret key: `Poseidon2::compress([KDF, 0])`,
/// `KDF = Fr::from_le_bytes(b"KDF") = 0x46444B` (kms/keys zk/private.rs @ rc.5).
pub fn zero_pk() -> Fr {
    let kdf = fr_from_bytes_unchecked(b"KDF");
    <Poseidon2Bn254Hasher as logos_blockchain_poseidon2::Digest>::compress(&[kdf, Fr::from(0u64)])
}

pub fn verify_sig(
    vk_json: &str,
    k_le: &[u8; 32],
    digest: &[u8; 32],
    zksig: &[u8; 128],
) -> Result<bool, String> {
    let de: Groth16VerificationKeyJsonDeser =
        serde_json::from_str(vk_json).map_err(|e| format!("vk json: {e}"))?;
    let vk = Groth16VerificationKey::try_from(de).map_err(|e| format!("vk convert: {e:?}"))?;
    let pvk = vk.into_prepared();
    let comp = CompressedGroth16Proof::from_bytes(zksig);
    let proof = Groth16Proof::try_from(&comp).map_err(|e| format!("proof decode: {e:?}"))?;
    let k = fr_from_bytes(k_le).map_err(|e| format!("k: {e}"))?;
    let mut inputs = vec![k];
    inputs.extend(std::iter::repeat(zero_pk()).take(31));
    inputs.push(Fr::from_le_bytes_mod_order(digest));
    groth16_verify(&pvk, &proof, &inputs).map_err(|e| format!("verify: {e}"))
}
