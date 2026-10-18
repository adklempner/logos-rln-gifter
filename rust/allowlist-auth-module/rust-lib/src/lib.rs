// Allowlist VERIFIERS for gifted RLN registration — the server-side half of
// the three allowlist auth vectors in one module (the producer half is
// allowlist-sign-module):
//   eth-allowlist   EIP-191 personal_sign by an allowlisted 0x address (eth.rs)
//   logos-allowlist zkSign by an allowlisted logos-blockchain key      (logos.rs)
//   lez-allowlist   BIP-340 by an allowlisted LEZ public account       (lez.rs)
// Each signer identity is the nullifier, so each allowlisted identity grants
// one membership through the gifter's shared, persisted replay store.
// FEATURE: RLN gifter allowlist auth vectors (verify)

use rln_auth_vector::dispatch_verify;

pub mod eth;
pub mod lez;
pub mod logos;

pub trait AllowlistAuthModule: Send + 'static {
    /// rln_auth_vector VERIFY_METHOD for auth_type "eth-allowlist",
    /// "logos-allowlist" and "lez-allowlist". One JSON-string arg
    /// (VerifyRequest), routed by `auth_type`; payload and config per vector
    /// (see eth.rs / logos.rs / lez.rs and the README). Accepts with the
    /// signer identity as the nullifier. `{"ok", "reason"?, "nullifier"?}` or
    /// `{"error"}` (malformed request, unknown auth_type, bad config).
    fn verify_auth(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

#[cfg(not(test))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

// The unit tests never cross the C ABI; they only need the context shape.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct RustModuleContext {
    pub module_path: String,
    pub instance_id: String,
    pub instance_persistence_path: String,
}

#[derive(Default)]
struct AllowlistAuth {}

impl AllowlistAuthModule for AllowlistAuth {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn verify_auth(&mut self, args_json: String) -> String {
        dispatch_verify(
            &args_json,
            &[&eth::EthAllowlistVector, &logos::LogosAllowlistVector, &lez::LezAllowlistVector],
        )
    }
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<AllowlistAuth>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn call(req: Value) -> Value {
        serde_json::from_str(&AllowlistAuth::default().verify_auth(req.to_string())).unwrap()
    }

    #[test]
    fn each_auth_type_routes_to_its_vector() {
        let idc = "11".repeat(32);
        let cases = [
            // Each config is valid only for its own vector, and each payload
            // is garbage, so the reject reason names the vector that ran.
            ("eth-allowlist", json!({ "allowlist": ["0x0000000000000000000000000000000000000001"] }), "65 bytes"),
            ("logos-allowlist", json!({ "allowlist": ["22".repeat(32)] }), "160 bytes"),
            ("lez-allowlist", json!({ "allowlist": ["33".repeat(32)] }), "96 bytes"),
        ];
        for (auth_type, config, needle) in cases {
            let out = call(json!({
                "auth_type": auth_type,
                "payload_hex": "aa".repeat(10),
                "id_commitment_hex": idc,
                "rate": 100,
                "config": config,
            }));
            assert_eq!(out["ok"], false, "{auth_type}: {out}");
            let reason = out["reason"].as_str().unwrap_or_else(|| panic!("{auth_type}: {out}"));
            assert!(reason.contains(needle), "{auth_type}: {reason}");
        }
    }

    #[test]
    fn each_vector_accepts_through_the_module() {
        // eth: key 0x42.., EIP-191 over the commitment hex.
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let idc = [0x11u8; 32];
        let (sig, recid) = sk.sign_prehash_recoverable(&eth::eip191_digest(&idc)).unwrap();
        let mut payload = sig.to_bytes().to_vec();
        payload.push(recid.to_byte());
        let addr = eth::address_of(sk.verifying_key());
        let out = call(json!({
            "auth_type": "eth-allowlist", "payload_hex": hex::encode(payload),
            "id_commitment_hex": hex::encode(idc), "rate": 100, "config": { "allowlist": [addr] },
        }));
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["nullifier"], addr);

        // lez: BIP-340 by key 0x42...
        let lk = k256::schnorr::SigningKey::from_bytes(&[0x42u8; 32]).unwrap();
        let ls = lk.sign_prehash_with_aux_rand(&lez::digest(&idc), &[0x55; 32]).unwrap();
        let xonly: [u8; 32] = lk.verifying_key().to_bytes().into();
        let mut payload = xonly.to_vec();
        payload.extend_from_slice(&ls.to_bytes());
        let acct = hex::encode(lez::account_id(&xonly));
        let out = call(json!({
            "auth_type": "lez-allowlist", "payload_hex": hex::encode(payload),
            "id_commitment_hex": hex::encode(idc), "rate": 100, "config": { "allowlist": [acct] },
        }));
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["nullifier"], acct);

        // logos: the recorded node signature.
        let real: Value = serde_json::from_str(include_str!("../tests/fixtures/logos_sign_real.json")).unwrap();
        let out = call(json!({
            "auth_type": "logos-allowlist", "payload_hex": real["payload_hex"],
            "id_commitment_hex": real["idc"], "rate": 100, "config": { "allowlist": [real["k"]] },
        }));
        assert_eq!(out["ok"], true, "{out}");
        assert_eq!(out["nullifier"], real["k"]);
    }

    #[test]
    fn unknown_auth_type_is_an_error_envelope() {
        let out = call(json!({
            "auth_type": "keycard-attestation",
            "payload_hex": "00",
            "id_commitment_hex": "11".repeat(32),
            "rate": 100,
        }));
        assert!(out.get("ok").is_none(), "{out}");
        assert!(out["error"].as_str().unwrap().contains("unknown auth_type"), "{out}");
    }
}
