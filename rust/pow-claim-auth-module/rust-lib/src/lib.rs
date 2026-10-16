// pow-claim auth VERIFIER for gifted RLN registration (PoC): the gifter-side
// half of the pow-claim vector. Checks the payload's zkSign signature, then
// the claim against the gifter's own node (see pow-claim-verifier).
// FEATURE: RLN membership gifter pow-claim auth module

use rln_auth_vector::{dispatch_verify, AuthVector, Verdict, VerifyRequest};

pub trait PowClaimAuthModule: Send + 'static {
    /// rln_auth_vector VERIFY_METHOD for auth_type "pow-claim". One
    /// JSON-string arg (VerifyRequest); config: `{"node_url", "audience",
    /// "min_payout"?, "allow_direct_ownership"?, "allow_spend_locator"?,
    /// "http_timeout_ms"?, "zksign_vk_path"?, "audit_log"?}`.
    /// `{"ok", "reason"?, "nullifier"?}` or `{"error"}`.
    fn verify_auth(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct PowClaimAuth;

struct PowClaimVector;

impl AuthVector for PowClaimVector {
    fn auth_type(&self) -> &'static str {
        pow_claim_verifier::AUTH_TYPE
    }

    fn verify(&self, req: &VerifyRequest) -> Result<Verdict, String> {
        pow_claim_verifier::verify_request(req)
    }
}

impl PowClaimAuthModule for PowClaimAuth {
    // Plain String (not Result): codegen maps Result to LogosResult, which the
    // host nulls through the UI bridge; errors travel as {"error":...}.
    fn verify_auth(&mut self, args_json: String) -> String {
        dispatch_verify(&args_json, &[&PowClaimVector])
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<PowClaimAuth>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const IDC: &str = "115f8d7a24636f56dae6665aec26f8ea4e3ce99840e2fe2cab2056750a1218c2";
    // Real golden payload (pow-claim-core/tests/fixtures/real/meta.json).
    const PAYLOAD: &str = "0100e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce077f75381ba1613693212cff6490d850fb41d625961bb46c6213ed0ab0a9756992efcd48f40a04d764b408f89a74f9a216bd849ffef7fff75196e65985067d241064000000000000003481cedf3433c76b2d37f199f26f249bd8b3fd4ad66c5cd699adf1417dfe51a54ba8953fcfa9d2c3eac5d80324abb120ac632202b5d8d989b499a80415e5bf0b3e6b246f591f0c1e33b01fcc6bf186eb53afb24dd2a7a18f421c5196cf1c0ca4536c7483158d893dfb8b9f71992fbce7f4f9e1619db6d5723a58246ee0c40794";

    fn call(req: Value) -> Value {
        serde_json::from_str(&dispatch_verify(&req.to_string(), &[&PowClaimVector])).unwrap()
    }

    fn req(payload: &str, cfg: Value) -> Value {
        json!({"auth_type": "pow-claim", "payload_hex": payload, "id_commitment_hex": IDC,
               "rate": 100, "config": cfg})
    }

    fn unreachable_cfg() -> Value {
        json!({"node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 500})
    }

    #[test]
    fn wrong_auth_type_is_error_envelope() {
        let mut r = req(PAYLOAD, unreachable_cfg());
        r["auth_type"] = json!("nope");
        let out = call(r);
        assert!(out["error"].as_str().unwrap().contains("unknown auth_type"), "{out}");
    }

    #[test]
    fn missing_node_url_is_error() {
        let out = call(req(PAYLOAD, json!({"audience": "poc"})));
        assert!(out["error"].as_str().unwrap().contains("node_url"), "{out}");
    }

    #[test]
    fn real_payload_reaches_node_and_unreachable_is_error() {
        let out = call(req(PAYLOAD, unreachable_cfg()));
        assert!(out["error"].as_str().unwrap().contains("unreachable"), "{out}");
    }

    #[test]
    fn tampered_payload_is_reject_without_http() {
        let mut b: Vec<u8> = (0..PAYLOAD.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&PAYLOAD[i..i + 2], 16).unwrap())
            .collect();
        b[106 + 5] ^= 1;
        let hexs: String = b.iter().map(|x| format!("{x:02x}")).collect();
        let t0 = std::time::Instant::now();
        let out = call(req(&hexs, unreachable_cfg()));
        assert_eq!(out["ok"], false, "{out}");
        assert!(out["reason"].as_str().unwrap().contains("signature"), "{out}");
        assert!(out.get("error").is_none());
        assert!(t0.elapsed().as_millis() < 400, "should not have attempted HTTP");
    }

    #[test]
    fn config_as_json_string() {
        let out = call(req(PAYLOAD, json!(unreachable_cfg().to_string())));
        assert!(out["error"].as_str().unwrap().contains("unreachable"), "{out}");
    }
}
