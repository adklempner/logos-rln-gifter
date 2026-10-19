// EIP-191 eth-allowlist PRODUCER: signs the requester's identity commitment
// with a secp256k1 key (the module key, or `args.private_key`), exactly what
// allowlist-auth-module's eth.rs recovers. The message is the bare commitment
// hex (no rate/audience binding, unlike logos/lez) so any wallet can sign it.
// FEATURE: RLN gifter eth-allowlist auth vector (produce)

use k256::ecdsa::{SigningKey, VerifyingKey};
use rln_auth_vector::{AuthVector, ProduceReply, ProduceRequest};
use zksign_light::strip_0x;

pub const ETH_ALLOWLIST_AUTH_TYPE: &str = rln_auth_vector::ETH_ALLOWLIST_AUTH_TYPE;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// The EIP-191 personal_sign digest over the LOWERCASE HEX of the 32-byte
/// commitment — byte-for-byte the verifier's `eip191_digest`, and what
/// `cast wallet sign "<hex>"` signs.
pub fn eip191_digest(id_commitment: &[u8]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

/// Lowercase 0x address of a public key.
pub fn address_of(vk: &VerifyingKey) -> String {
    let enc = vk.to_encoded_point(false);
    let h = keccak256(&enc.as_bytes()[1..]);
    format!("0x{}", hex::encode(&h[12..]))
}

pub fn parse_key(hex_str: &str) -> Result<SigningKey, String> {
    let bytes = hex::decode(strip_0x(hex_str))
        .map_err(|e| format!("private key hex: {e}"))?;
    SigningKey::from_slice(&bytes).map_err(|e| format!("private key: {e}"))
}

/// `hex(r || s || recid)`, recid 0/1.
pub fn sign_commitment(key: &SigningKey, id_commitment_hex: &str) -> Result<String, String> {
    let idc = hex::decode(strip_0x(id_commitment_hex))
        .map_err(|e| format!("id_commitment hex: {e}"))?;
    if idc.len() != 32 {
        return Err(format!("id_commitment must be 32 bytes, got {}", idc.len()));
    }
    let (sig, recid) = key
        .sign_prehash_recoverable(&eip191_digest(&idc))
        .map_err(|e| format!("sign: {e}"))?;
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    Ok(hex::encode(out))
}

/// One produce call's vector: borrows the key chosen for this request (None
/// when the request is for another auth type, so no key was resolved).
pub struct EthSignVector<'a> {
    pub key: Option<&'a SigningKey>,
}

impl AuthVector for EthSignVector<'_> {
    fn auth_type(&self) -> &'static str {
        ETH_ALLOWLIST_AUTH_TYPE
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        let key = self.key.ok_or("eth-allowlist: no signing key resolved")?;
        Ok(ProduceReply { payload_hex: sign_commitment(key, &req.id_commitment_hex)? })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature};

    pub(crate) const PK42: &str = "0x4242424242424242424242424242424242424242424242424242424242424242";
    pub(crate) const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
    pub(crate) const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    // `cast wallet sign --private-key $PK42 "$IDC"` (foundry; EIP-191 over the
    // hex string, v = 27 + recid).
    const CAST_SIG: &str = "84b1aff4c2850be46cefd3e12e22349bc886dea47e7b0e509c2e3059f1035fc1606d3c249c695f72556bd1d12ff301671244780f72177a2e3f89a033a8dd94c81c";

    // The verifier's recovery, re-implemented so the two crates stay
    // independent: 65-byte r||s||recid (0/1 or 27/28) over the EIP-191 envelope.
    pub(crate) fn recover(idc_hex: &str, sig_hex: &str) -> String {
        let sig = hex::decode(sig_hex).unwrap();
        assert_eq!(sig.len(), 65);
        let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
        let recid = RecoveryId::from_byte(recid_byte).unwrap();
        let signature = Signature::from_slice(&sig[0..64]).unwrap();
        let digest = eip191_digest(&hex::decode(idc_hex).unwrap());
        let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).unwrap();
        address_of(&vk)
    }

    #[test]
    fn matches_foundry_cast_vector() {
        let key = parse_key(PK42).unwrap();
        let ours = sign_commitment(&key, IDC).unwrap();
        assert_eq!(&ours[..128], &CAST_SIG[..128], "r||s differs from cast");
        let v = u8::from_str_radix(&CAST_SIG[128..], 16).unwrap();
        assert_eq!(u8::from_str_radix(&ours[128..], 16).unwrap(), v - 27);
        assert_eq!(recover(IDC, &ours), ADDR42);
        assert_eq!(recover(IDC, CAST_SIG), ADDR42);
    }
}
