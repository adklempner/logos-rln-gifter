//! Against a real node (ignored by default; lives in the lib because the
//! generated C-ABI scaffold is absent outside the builder):
//!
//! ```sh
//! LOGOS_NODE_URL=http://127.0.0.1:18080 cargo test --lib -- --ignored --nocapture
//! ```
//!
//! Produces for a fixed commitment (default rate_max 100, audience ""),
//! verifies the zkSign offline with
//! `zksign_light::verify` and the vendored VK, and records the result as
//! allowlist-auth-module's logos-allowlist accept fixture
//! (`../../allowlist-auth-module/rust-lib/tests/fixtures/logos_sign_real.json`).

use super::*;

/// Fixed commitment for the recorded fixture. With rate_max 100 and audience
/// "" its digest is >= p, which the verifier's fixture test relies on.
const FIXTURE_IDC: &str = "2a1f0b6c9d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8";

#[test]
#[ignore = "needs a logos-blockchain node: set LOGOS_NODE_URL (e.g. http://127.0.0.1:18080)"]
fn real_node_signature_verifies_offline_and_records_fixture() {
    let url = std::env::var("LOGOS_NODE_URL").expect("LOGOS_NODE_URL");
    let args = Args::parse(Some(&json!({ "node_url": url }))).unwrap();
    let Binding { rate_max, audience } = args.binding.clone();
    let node = args.node();
    let (k_hex, source) = resolve_key(&node, &args).unwrap();
    eprintln!("K = {k_hex} (from {source}); signing (rate_max {rate_max}, audience {audience:?})…");

    let started = std::time::Instant::now();
    let payload_hex = produce(&node, FIXTURE_IDC, &args).unwrap();
    eprintln!("signed in {:?}", started.elapsed());

    let payload = hex::decode(&payload_hex).unwrap();
    assert_eq!(payload.len(), PAYLOAD_LEN);
    let k: [u8; 32] = payload[..32].try_into().unwrap();
    let sig: [u8; 128] = payload[32..160].try_into().unwrap();
    assert_eq!(u64::from_le_bytes(payload[160..].try_into().unwrap()), rate_max);
    assert_eq!(hex::encode(k), k_hex);
    let d = digest(&hex32_bytes("idc", FIXTURE_IDC).unwrap(), rate_max, &audience);
    assert!(!zksign_light::is_canonical_fr(&d), "fixture digest should be >= p");
    let vk = zksign_light::default_vk().unwrap();
    zksign_light::verify_sig(vk, &k, &d, &sig)
        .unwrap_or_else(|e| panic!("node signature does not verify against the vendored v0.5.7 VK: {e}"));
    eprintln!("verified against the vendored v0.5.7 VK");

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../allowlist-auth-module/rust-lib/tests/fixtures/logos_sign_real.json");
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    let rec = json!({
        "idc": FIXTURE_IDC,
        "k": k_hex,
        "rate_max": rate_max,
        "audience": audience,
        "payload_hex": payload_hex,
    });
    std::fs::write(&out, serde_json::to_string_pretty(&rec).unwrap() + "\n").unwrap();
    eprintln!("wrote {}", out.display());
}
