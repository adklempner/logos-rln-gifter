// pow-claim auth producer for gifted RLN registration (PoC): proves ownership
// of a settled PoW reward claim via the in-process node's HTTP API.
// FEATURE: RLN membership gifter pow-claim capture module

use rln_auth_vector::{dispatch_produce, AuthVector, ProduceReply, ProduceRequest};

pub trait PowClaimCaptureModule: Send + 'static {
    /// rln_auth_vector PRODUCE_METHOD for auth_type "pow-claim".
    /// One JSON-string arg (ProduceRequest) -> `{"payload_hex"}` or `{"error"}`.
    fn produce_auth(&mut self, args_json: String) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct PowClaimCapture;

struct PowClaimVector;

impl AuthVector for PowClaimVector {
    fn auth_type(&self) -> &'static str {
        "pow-claim"
    }

    fn produce(&self, req: &ProduceRequest) -> Result<ProduceReply, String> {
        pow_claim_core::produce_http(&req.id_commitment_hex, req.args.as_ref())
            .map(|payload_hex| ProduceReply { payload_hex })
    }
}

impl PowClaimCaptureModule for PowClaimCapture {
    // Plain String return (not Result): see keycard-capture-module. Errors are {"error":...}.
    fn produce_auth(&mut self, args_json: String) -> String {
        dispatch_produce(&args_json, &[&PowClaimVector])
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<PowClaimCapture>();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_of(out: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(out).unwrap();
        v["error"].as_str().unwrap_or_else(|| panic!("no error: {out}")).to_string()
    }

    #[test]
    fn bad_commitment_is_validation_error() {
        let out = dispatch_produce(
            r#"{"auth_type":"pow-claim","id_commitment_hex":"00"}"#,
            &[&PowClaimVector],
        );
        let e = err_of(&out).to_lowercase();
        assert!(e.contains("commitment") || e.contains("hex"), "{out}");
    }

    const C64: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    #[test]
    fn wiring_reaches_http_client() {
        let req = serde_json::json!({"auth_type":"pow-claim","id_commitment_hex":C64,
            "args":{"node_url":"http://127.0.0.1:1"}});
        let out = dispatch_produce(&req.to_string(), &[&PowClaimVector]);
        let e = err_of(&out).to_lowercase();
        assert!(e.contains("pow/status") || e.contains("connect") || e.contains("refused"), "{out}");
    }

    #[test]
    fn args_as_json_string() {
        let req = serde_json::json!({"auth_type":"pow-claim","id_commitment_hex":C64,
            "args":"{\"node_url\":\"http://127.0.0.1:1\"}"});
        let out = dispatch_produce(&req.to_string(), &[&PowClaimVector]);
        let e = err_of(&out).to_lowercase();
        assert!(e.contains("pow/status") || e.contains("connect") || e.contains("refused"), "{out}");
    }

    #[test]
    fn unknown_auth_type_errors() {
        let out = dispatch_produce(
            r#"{"auth_type":"nope","id_commitment_hex":"00"}"#,
            &[&PowClaimVector],
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        println!("{out}");
        assert!(v["error"].as_str().unwrap().to_lowercase().contains("unknown"), "{out}");
    }
}
