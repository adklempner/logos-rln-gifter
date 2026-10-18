// EIP-191 eth-allowlist VERIFIER. The producer half signs with a wallet or
// allowlist-sign-module; requesters pass the signature via authPayload /
// auth_payload. The recovered address is the nullifier.
// FEATURE: RLN gifter eth-allowlist auth vector (verify)
//
// payload: 65-byte recoverable EIP-191 personal_sign signature (r||s||recid)
// over the lowercase hex of the 32-byte identity commitment; config:
// `{"allowlist": ["0x…", …]}`.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rln_auth_vector::{AuthVector, Verdict, VerifyRequest};

pub const ETH_ALLOWLIST_AUTH_TYPE: &str = rln_auth_vector::ETH_ALLOWLIST_AUTH_TYPE;

pub struct EthAllowlistVector;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// The EIP-191 personal_sign digest: keccak256 over the envelope wrapping the
/// LOWERCASE HEX of the 32-byte commitment — the signed message is the
/// human-readable hex string a wallet displays, not raw bytes.
pub fn eip191_digest(id_commitment: &[u8]) -> [u8; 32] {
    let hexs = hex::encode(id_commitment);
    let mut msg = format!("\x19Ethereum Signed Message:\n{}", hexs.len()).into_bytes();
    msg.extend_from_slice(hexs.as_bytes());
    keccak256(&msg)
}

/// Lowercase 0x address of a secp256k1 public key.
pub fn address_of(vk: &VerifyingKey) -> String {
    let enc = vk.to_encoded_point(false);
    let raw = &enc.as_bytes()[1..]; // 64 bytes: X || Y
    let h = keccak256(raw);
    format!("0x{}", hex::encode(&h[12..]))
}

/// Recover the signer's lowercase 0x address from a 65-byte recoverable
/// signature (r||s||recid; recid raw 0/1 or 27/28-offset) over the EIP-191
/// envelope of `id_commitment`.
pub fn recover_signer(id_commitment: &[u8], sig: &[u8]) -> Result<String, String> {
    if sig.len() != 65 {
        return Err(format!("signature must be 65 bytes, got {}", sig.len()));
    }
    let digest = eip191_digest(id_commitment);
    let recid_byte = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let recid = RecoveryId::from_byte(recid_byte).ok_or("invalid recovery id")?;
    let signature = Signature::from_slice(&sig[0..64]).map_err(|e| format!("sig: {e}"))?;
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| format!("recovery failed: {e}"))?;
    Ok(address_of(&vk))
}

impl AuthVector for EthAllowlistVector {
    fn auth_type(&self) -> &'static str {
        ETH_ALLOWLIST_AUTH_TYPE
    }

    // Malformed config is an Err (operator mistake, error envelope); a
    // signature that doesn't recover or an unlisted signer is a REJECT
    // verdict (untrusted input, normal flow).
    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        let allowlist = req
            .config
            .as_ref()
            .and_then(|c| c.get("allowlist"))
            .and_then(|v| v.as_array())
            .ok_or("config.allowlist (array of 0x addresses) is required")?;
        let allowlist: Vec<String> = allowlist
            .iter()
            .map(|e| e.as_str().map(str::to_lowercase).ok_or("allowlist entries must be strings"))
            .collect::<Result<_, _>>()?;
        if allowlist.is_empty() {
            return Err("config.allowlist is empty — nothing can verify".into());
        }

        let sig = match hex::decode(req.payload_hex.trim_start_matches("0x")) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        let id_commitment = match hex::decode(req.id_commitment_hex.trim_start_matches("0x")) {
            Ok(c) => c,
            Err(e) => return Ok(Verdict::reject(format!("id_commitment hex: {e}"))),
        };
        let signer = match recover_signer(&id_commitment, &sig) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("signature verification failed: {e}"))),
        };
        if !allowlist.contains(&signer) {
            return Ok(Verdict::reject(format!("address not allowlisted: {signer}")));
        }
        Ok(Verdict::accept(Some(signer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn signed_request(recid_offset: u8) -> (VerifyRequest, String) {
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let commitment = [0x11u8; 32];
        let digest = eip191_digest(&commitment);
        let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut payload = sig.to_bytes().to_vec();
        payload.push(recid.to_byte() + recid_offset);

        let vk = sk.verifying_key();
        let enc = vk.to_encoded_point(false);
        let h = keccak256(&enc.as_bytes()[1..]);
        let address = format!("0x{}", hex::encode(&h[12..]));

        let req = VerifyRequest {
            auth_type: ETH_ALLOWLIST_AUTH_TYPE.into(),
            payload_hex: hex::encode(payload),
            id_commitment_hex: hex::encode(commitment),
            rate: 100,
            config: Some(serde_json::json!({ "allowlist": [address.clone()] })),
        };
        (req, address)
    }

    #[test]
    fn allowlisted_signature_accepts_with_address_nullifier() {
        for offset in [0u8, 27] {
            let (req, address) = signed_request(offset);
            let v = EthAllowlistVector.verify(&req).unwrap();
            assert!(v.ok, "offset {offset}: {:?}", v.reason);
            assert_eq!(v.nullifier.as_deref(), Some(address.as_str()));
        }
    }

    #[test]
    fn unlisted_signer_is_rejected_not_errored() {
        let (mut req, _) = signed_request(0);
        req.config = Some(serde_json::json!({ "allowlist": ["0x0000000000000000000000000000000000000001"] }));
        let v = EthAllowlistVector.verify(&req).unwrap();
        assert!(!v.ok);
        assert!(v.reason.unwrap().contains("not allowlisted"));
    }

    #[test]
    fn garbage_payload_is_rejected_not_errored() {
        let (mut req, _) = signed_request(0);
        req.payload_hex = "zz".into();
        assert!(!EthAllowlistVector.verify(&req).unwrap().ok);
        req.payload_hex = "aa".repeat(10);
        let v = EthAllowlistVector.verify(&req).unwrap();
        assert!(!v.ok);
        assert!(v.reason.unwrap().contains("65 bytes"));
    }

    #[test]
    fn missing_or_empty_allowlist_is_an_operator_error() {
        let (mut req, _) = signed_request(0);
        req.config = None;
        assert!(EthAllowlistVector.verify(&req).unwrap_err().contains("required"));
        req.config = Some(serde_json::json!({ "allowlist": [] }));
        assert!(EthAllowlistVector.verify(&req).unwrap_err().contains("empty"));
    }

    #[test]
    fn checksummed_allowlist_entries_still_match() {
        let (mut req, address) = signed_request(0);
        req.config = Some(serde_json::json!({ "allowlist": [address.to_uppercase().replace("0X", "0x")] }));
        assert!(EthAllowlistVector.verify(&req).unwrap().ok);
    }
}
