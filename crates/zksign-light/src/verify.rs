//! Offline zkSign (Groth16 over BN254) verification. Semantics are those of
//! the pow-claim verifier's `sig.rs` (itself from `tools/pow-claim-poc`): the
//! public inputs are `[K, zero_pk × 31, Fr::from_le_bytes_mod_order(digest)]`,
//! i.e. a single-key signature with the 31 unused slots holding the zero key.

use std::sync::OnceLock;

use ark_ff::PrimeField as _;
use logos_blockchain_groth16::{
    fr_from_bytes, fr_from_bytes_unchecked, groth16_verify, CompressedGroth16Proof, Fr,
    Groth16PreparedVerificationKey, Groth16Proof, Groth16VerificationKey,
    Groth16VerificationKeyJsonDeser,
};
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};

/// zkSign verification key bundled with the node at 0.3.0-rc.5 (circuits v0.5.7).
pub const DEFAULT_VK_JSON: &str = include_str!("../assets/zksign_vk_v0.5.7.json");

pub struct PreparedVk(Groth16PreparedVerificationKey);

impl PreparedVk {
    pub fn from_json(vk_json: &str) -> Result<PreparedVk, String> {
        let de: Groth16VerificationKeyJsonDeser =
            serde_json::from_str(vk_json).map_err(|e| format!("zkSign vk json: {e}"))?;
        let vk = Groth16VerificationKey::try_from(de)
            .map_err(|e| format!("zkSign vk convert: {e:?}"))?;
        Ok(PreparedVk(vk.into_prepared()))
    }

    pub fn from_path(path: &str) -> Result<PreparedVk, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("config.zksign_vk_path {path}: {e}"))?;
        Self::from_json(&s).map_err(|e| format!("config.zksign_vk_path {path}: {e}"))
    }
}

static DEFAULT_VK: OnceLock<Result<PreparedVk, String>> = OnceLock::new();

/// The bundled VK, prepared on first use.
pub fn default_vk() -> Result<&'static PreparedVk, String> {
    DEFAULT_VK
        .get_or_init(|| PreparedVk::from_json(DEFAULT_VK_JSON))
        .as_ref()
        .map_err(Clone::clone)
}

/// Public key of the zero secret key: `Poseidon2::compress([KDF, 0])`,
/// `KDF = Fr::from_le_bytes(b"KDF")` (kms/keys zk/private.rs @ rc.5). zkSign
/// fixes 32 key slots; unused slots carry this key.
pub fn zero_pk() -> Fr {
    static Z: OnceLock<Fr> = OnceLock::new();
    *Z.get_or_init(|| {
        let kdf = fr_from_bytes_unchecked(b"KDF");
        Poseidon2Bn254Hasher::compress(&[kdf, Fr::from(0u64)])
    })
}

/// [`zero_pk`] as the 32-byte little-endian encoding a node would show.
pub fn zero_pk_le() -> [u8; 32] {
    use ark_ff::BigInteger as _;
    let mut out = [0u8; 32];
    out.copy_from_slice(&zero_pk().into_bigint().to_bytes_le());
    out
}

/// `Ok(())` iff `zksig` is a valid zkSign by `K` over `digest`. Every failure
/// (non-canonical K, undecodable proof, invalid proof) is a reject reason.
pub fn verify_sig(
    vk: &PreparedVk,
    k_le: &[u8; 32],
    digest: &[u8; 32],
    zksig: &[u8; 128],
) -> Result<(), String> {
    let k = fr_from_bytes(k_le).map_err(|e| format!("zkSign signature invalid (K: {e})"))?;
    let comp = CompressedGroth16Proof::from_bytes(zksig);
    let proof = Groth16Proof::try_from(&comp)
        .map_err(|e| format!("zkSign signature invalid (proof decode: {e:?})"))?;
    let mut inputs = Vec::with_capacity(33);
    inputs.push(k);
    inputs.extend(std::iter::repeat(zero_pk()).take(31));
    inputs.push(Fr::from_le_bytes_mod_order(digest));
    match groth16_verify(&vk.0, &proof, &inputs) {
        Ok(true) => Ok(()),
        Ok(false) => Err("zkSign signature invalid (proof does not verify)".into()),
        Err(e) => Err(format!("zkSign signature invalid (verify: {e})")),
    }
}
