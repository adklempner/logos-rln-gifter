// PoC stub for `liblogos_lez_rln_module` (R2 contingency, tools/pow-claim-poc).
//
// The gifter opens its LEZ client lazily: with no module of this name loaded,
// its register_member call waits on a deferred subscription (no fast failure).
// Loading this stub makes the target exist, and register_member answers at once
// with plain NON-JSON text, which the gifter's call_module_json fails to parse ->
// Err("register_member: reply parse: …") -> RegisterError::NotSubmitted (nullifier
// released). Measured traps:
//   - leaving register_member OUT does not fail fast: the host answers an
//     unknown method with OK/null, the gifter treats that as submitted and
//     polls get_membership for its 150 s confirm budget -> Unconfirmed
//     (and an authorized nullifier is persisted as spent);
//   - an EMPTY string is no better: lp::parse_ok maps "" to Null -> Ok(Null);
//   - never return JSON (object or "{...}" string) here, same reason.
//   - param types must match what the gifter sends ([str, str, str, NUMBER]):
//     a String `rate` makes the dispatcher answer OK with a
//     {"code":"dispatch_failed",…} OBJECT -> confirm loop again. So rate: i64.

pub trait LiblogosLezRlnModule: Send + 'static {
    /// Liveness probe; returns "pong".
    fn ping(&mut self) -> String;
    /// Always non-JSON text -> the gifter reports NotSubmitted ("register_member: reply parse: …").
    fn register_member(&mut self, config: String, wallet: String, id_commitment: String, rate: i64) -> String;
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct StubLezRln {}

impl LiblogosLezRlnModule for StubLezRln {
    fn ping(&mut self) -> String {
        "pong".to_string()
    }

    fn register_member(&mut self, _config: String, _wallet: String, _id_commitment: String, _rate: i64) -> String {
        eprintln!("liblogos_lez_rln_module STUB: register_member -> non-JSON reply (NotSubmitted)");
        "stub: no LEZ registry".to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<StubLezRln>();
}
