// EIP-191 eth-allowlist VERIFIER. The producer half signs with a wallet or
// allowlist-sign-module; requesters pass the signature via authPayload /
// auth_payload. The recovered address is the nullifier.
// FEATURE: RLN gifter eth-allowlist auth vector (verify)
//
// payload: 65-byte recoverable EIP-191 personal_sign signature (r||s||recid)
// over the lowercase hex of the 32-byte identity commitment; config:
// `{"allowlist": ["0x…", …]}`. Unlike logos/lez, rate and audience are NOT
// bound into the signed message: it stays the plain commitment hex so any
// wallet (`personal_sign`, `cast wallet sign`) can produce it.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rln_auth_vector::{AuthVector, Verdict, VerifyRequest};
use zksign_light::strip_0x;

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
    // EIP-2: only low-S signatures; (r, n-s) with the flipped recid would
    // otherwise be a second valid encoding of the same signature.
    if signature.normalize_s().is_some() {
        return Err("high-S signature (EIP-2 requires s <= n/2)".into());
    }
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid)
        .map_err(|e| format!("recovery failed: {e}"))?;
    Ok(address_of(&vk))
}

/// An allowlist entry normalised to lowercase `0x` + 40 hex (a bare 40-hex
/// address gets the `0x`); anything else is an operator error naming it.
pub fn normalize_address(entry: &str) -> Result<String, String> {
    let t = entry.trim().to_ascii_lowercase();
    let h = t.strip_prefix("0x").unwrap_or(&t);
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("config.allowlist entry {entry:?}: expected a 0x address (40 hex chars)"));
    }
    Ok(format!("0x{h}"))
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
            .map(|e| e.as_str().ok_or_else(|| "allowlist entries must be strings".to_string()).and_then(normalize_address))
            .collect::<Result<_, _>>()?;
        if allowlist.is_empty() {
            return Err("config.allowlist is empty — nothing can verify".into());
        }

        let sig = match hex::decode(strip_0x(&req.payload_hex)) {
            Ok(s) => s,
            Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
        };
        let id_commitment = match hex::decode(strip_0x(&req.id_commitment_hex)) {
            Ok(c) if c.len() == 32 => c,
            Ok(c) => return Ok(Verdict::reject(format!("id_commitment must be 32 bytes, got {}", c.len()))),
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
        // Bare 40 hex, surrounding whitespace and an uppercase 0X are normalised too.
        for entry in [address[2..].to_string(), format!("  {address} "), address.to_uppercase()] {
            req.config = Some(serde_json::json!({ "allowlist": [entry.clone()] }));
            assert!(EthAllowlistVector.verify(&req).unwrap().ok, "{entry:?}");
        }
    }

    #[test]
    fn malformed_allowlist_entry_is_an_operator_error_naming_it() {
        let (mut req, address) = signed_request(0);
        for bad in ["0x1234", "not-an-address", &format!("{address}00"), &format!("0x0x{}", &address[4..])] {
            req.config = Some(serde_json::json!({ "allowlist": [address.clone(), bad] }));
            let e = EthAllowlistVector.verify(&req).unwrap_err();
            assert!(e.contains(&format!("{bad:?}")), "{e}");
        }
    }

    #[test]
    fn commitment_must_be_32_bytes_and_0x_is_case_insensitive() {
        let (mut req, _) = signed_request(0);
        let full = req.id_commitment_hex.clone();
        req.id_commitment_hex = full[..62].to_string();
        let v = EthAllowlistVector.verify(&req).unwrap();
        assert!(!v.ok && v.reason.unwrap().contains("32 bytes, got 31"));
        req.id_commitment_hex = format!("0X{full}");
        req.payload_hex = format!("0X{}", req.payload_hex);
        assert!(EthAllowlistVector.verify(&req).unwrap().ok);
        req.id_commitment_hex = format!("0x0x{full}");
        assert!(!EthAllowlistVector.verify(&req).unwrap().ok, "only one prefix is stripped");
    }

    #[test]
    fn high_s_signature_rejects() {
        let (mut req, _) = signed_request(0);
        let mut p = hex::decode(&req.payload_hex).unwrap();
        let low = Signature::from_slice(&p[..64]).unwrap();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        p[..64].copy_from_slice(&high.to_bytes());
        p[64] ^= 1; // the flipped recid recovers the same key from (r, n-s)
        req.payload_hex = hex::encode(p);
        let v = EthAllowlistVector.verify(&req).unwrap();
        assert!(!v.ok);
        assert!(v.reason.unwrap().contains("high-S"));
    }

    #[test]
    fn foundry_cast_signature_recovers() {
        // `cast wallet sign --private-key 0x42…42 "$IDC"`, copied from
        // allowlist-sign-module's eth.rs (v = 27 + recid).
        const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
        const CAST_SIG: &str = "84b1aff4c2850be46cefd3e12e22349bc886dea47e7b0e509c2e3059f1035fc1606d3c249c695f72556bd1d12ff301671244780f72177a2e3f89a033a8dd94c81c";
        let req = VerifyRequest {
            auth_type: ETH_ALLOWLIST_AUTH_TYPE.into(),
            payload_hex: format!("0x{CAST_SIG}"),
            id_commitment_hex: IDC.into(),
            rate: 100,
            config: Some(serde_json::json!({ "allowlist": [ADDR42] })),
        };
        let v = EthAllowlistVector.verify(&req).unwrap();
        assert!(v.ok, "{:?}", v.reason);
        assert_eq!(v.nullifier.as_deref(), Some(ADDR42));
    }
}
