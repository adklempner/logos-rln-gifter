//! The compositions a module ships, end to end through the registries:
//! produce → verify for every scheme × authoriser this crate has, plus the
//! refusals that prove the composition rules.

use rln_auth_vector::{
    binding_digest, dispatch_produce, dispatch_verify, frame, reason, AuthType, Authoriser, Binding, Identity,
    Outcome, ProduceRegistry, VerifyRegistry,
};
use rln_auth_vectors::authoriser::{Allowlist, Attestation, PowClaim};
use rln_auth_vectors::claimant::{AllowlistClaimant, AttestationClaimant, PowClaimant};
use rln_auth_vectors::scheme::keycard::KeycardIdentity;
use rln_auth_vectors::scheme::{Eth, Keycard, Lez, Logos};
use rln_auth_vectors::signer::{EthSigner, LezSigner, LogosSigner, StaticKey};
use serde_json::{json, Value};
use zksign_light::ZkNode;

const IDC: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const PK42: [u8; 32] = [0x42; 32];
const ADDR42: &str = "0x17c5185167401ed00cf5f5b2fc97d9bbfdb7d025";
const CAST_SIG: &str = "84b1aff4c2850be46cefd3e12e22349bc886dea47e7b0e509c2e3059f1035fc1606d3c249c695f72556bd1d12ff301671244780f72177a2e3f89a033a8dd94c81c";
// BIP-340 vector 0 (sk = 3) → LEE account.
const PK0_ACCT_HEX: &str = "ec2cbcd4488075c4b30678c30351327fdf99f3fe703edc2999b68f8fd12bdbc8";
const PK0_ACCT_B58: &str = "GtvnQVLsv8V34E3X9hMBR9hsUokapUgiE4o7vCU4VMB5";
const K: &str = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07";
const GOLDEN_TLV: &str = "a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e";
const TEST_CA: &str = "02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5";
const IDENT_PUB: &str = "0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a";

struct FakeZk;
impl ZkNode for FakeZk {
    fn pow_status(&self) -> Result<Value, String> {
        Ok(json!({ "auto_claim": { "targets": [{ "public_key": K }] } }))
    }
    fn sign_zk(&self, _digest: &[u8; 32], _pk_hex: &str) -> Result<[u8; 128], String> {
        Ok([0x11; 128])
    }
}

fn sk3() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 3;
    b
}

fn verifiers() -> VerifyRegistry {
    VerifyRegistry::new()
        .scheme(Eth)
        .scheme(Lez)
        .scheme(Logos)
        .scheme(Keycard)
        .authoriser(Allowlist)
        .authoriser(Attestation)
        .authoriser(PowClaim)
}

fn producers() -> ProduceRegistry {
    ProduceRegistry::new()
        .signer(EthSigner(Box::new(StaticKey(PK42))))
        .signer(LezSigner(Box::new(StaticKey(sk3()))))
        .signer(LogosSigner { node: Some(Box::new(FakeZk)) })
        .claimant(AllowlistClaimant)
        .claimant(AttestationClaimant)
        .claimant(PowClaimant::http())
}

fn produce(auth_type: &str, args: Value) -> Value {
    let req = json!({ "auth_type": auth_type, "id_commitment_hex": IDC, "args": args });
    serde_json::from_str(&dispatch_produce(&req.to_string(), &producers())).unwrap()
}

fn verify(auth_type: &str, payload_hex: &str, rate: u64, config: Value) -> Value {
    let req = json!({
        "auth_type": auth_type, "payload_hex": payload_hex,
        "id_commitment_hex": IDC, "rate": rate, "config": config
    });
    serde_json::from_str(&dispatch_verify(&req.to_string(), &verifiers())).unwrap()
}

fn reason_of(v: &Value) -> &str {
    v["reason"].as_str().unwrap_or_else(|| panic!("no reason: {v}"))
}

#[test]
fn the_registries_compose_exactly_the_six_vectors() {
    let want = ["eth-allowlist", "lez-allowlist", "logos-allowlist", "logos-pow-claim", "keycard-allowlist", "keycard-attestation"];
    assert_eq!(verifiers().auth_types(), want);
    // The producers here lack the keycard signer (PC/SC), so no keycard-* types.
    assert_eq!(producers().auth_types(), &want[..4]);
}

#[test]
fn eth_allowlist_round_trips_and_matches_foundry() {
    let p = produce("eth-allowlist", json!({ "rate_max": 100 }));
    let payload = p["payload_hex"].as_str().unwrap_or_else(|| panic!("{p}"));
    let v = verify("eth-allowlist", payload, 100, json!({ "allowlist": [ADDR42.to_uppercase().replace("0X", "0x")] }));
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["nullifier"], ADDR42);

    // A wallet signature made outside the pipeline frames the same way.
    let framed = frame(&hex::decode(CAST_SIG).unwrap(), &[], 100);
    let v = verify("eth-allowlist", &format!("0x{}", hex::encode(framed)), 100, json!({ "allowlist": [ADDR42] }));
    assert_eq!(v["ok"], true, "{v}");

    let v = verify("eth-allowlist", payload, 100, json!({ "allowlist": ["0x0000000000000000000000000000000000000001"] }));
    assert_eq!(reason_of(&v), format!("address not allowlisted: {ADDR42}"));
    let v = verify("eth-allowlist", payload, 100, json!({ "allowlist": [] }));
    assert_eq!(v["error"], reason::ALLOWLIST_EMPTY);
    let v = verify("eth-allowlist", payload, 100, json!({}));
    assert!(v["error"].as_str().unwrap().contains("required"), "{v}");
    let v = verify("eth-allowlist", payload, 100, json!({ "allowlist": ["0x1234"] }));
    assert!(v["error"].as_str().unwrap().contains("\"0x1234\""), "{v}");
}

#[test]
fn lez_allowlist_round_trips_with_hex_or_base58_entries() {
    let p = produce("lez-allowlist", json!({ "rate_max": 10, "audience": "gifter-1" }));
    let payload = p["payload_hex"].as_str().unwrap_or_else(|| panic!("{p}"));
    for entry in [PK0_ACCT_HEX, PK0_ACCT_B58] {
        let v = verify("lez-allowlist", payload, 10, json!({ "allowlist": [entry], "audience": "gifter-1" }));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], PK0_ACCT_HEX);
    }
    let v = verify("lez-allowlist", payload, 11, json!({ "allowlist": [PK0_ACCT_HEX], "audience": "gifter-1" }));
    assert_eq!(reason_of(&v), "rate 11 exceeds the signed rate_max 10");
    let v = verify("lez-allowlist", payload, 10, json!({ "allowlist": [PK0_ACCT_HEX], "audience": "other" }));
    assert_eq!(reason_of(&v), reason::SIG_FAILED);
    let v = verify("lez-allowlist", payload, 10, json!({ "allowlist": ["00".repeat(32)], "audience": "gifter-1" }));
    assert!(reason_of(&v).starts_with("account not allowlisted"), "{v}");
}

#[test]
fn logos_allowlist_checks_membership_before_the_proof() {
    let p = produce("logos-allowlist", json!({}));
    let payload = p["payload_hex"].as_str().unwrap_or_else(|| panic!("{p}"));
    assert_eq!(&payload[2..66], K, "K leads the part");
    // Listed: the fake proof then fails verification.
    let v = verify("logos-allowlist", payload, 100, json!({ "allowlist": [K] }));
    assert!(reason_of(&v).contains("zkSign signature invalid"), "{v}");
    // Unlisted: refused before any proof work.
    let v = verify("logos-allowlist", payload, 100, json!({ "allowlist": [hex::encode(zksign_light::zero_pk_le())] }));
    assert_eq!(reason_of(&v), format!("public key not allowlisted: {K}"));
    // A big-endian key in the allowlist is an operator mistake.
    let v = verify("logos-allowlist", payload, 100, json!({ "allowlist": ["ff".repeat(32)] }));
    assert!(v["error"].as_str().unwrap().contains("big-endian paste"), "{v}");
    let v = verify("logos-allowlist", payload, 100, json!({ "allowlist": [K], "zksign_vk_path": "/nonexistent/vk.json" }));
    assert!(v["error"].as_str().unwrap().contains("zksign_vk_path"), "{v}");
}

#[test]
fn logos_pow_claim_binds_the_claim_nullifier_and_needs_the_logos_scheme() {
    // Evidence from the synthetic chain, the part from the fake zkSign.
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pow-claim/tests/fixtures/synthetic");
    let node = pow_claim::node::testing::FakeNode::from_dir(fixtures).unwrap();
    let args = pow_claim::ProduceArgs::parse(Some(&json!({ "audience": "poc" }))).unwrap();
    let claim = pow_claim::gather(&node, &args).unwrap();
    assert_eq!(hex::encode(claim.k), K);
    let evidence = claim.evidence.encode();

    let t = AuthType::parse("logos-pow-claim").unwrap();
    let b = Binding { id_commitment: hex::decode(IDC).unwrap().try_into().unwrap(), rate_max: 100, audience: "poc".into() };
    let digest = binding_digest(&t, &b, &claim.evidence.pow_nullifier);
    let mut part = claim.k.to_vec();
    part.extend_from_slice(&FakeZk.sign_zk(&digest, K).unwrap());
    let payload = hex::encode(frame(&part, &evidence, 100));

    let cfg = json!({ "node_url": "http://127.0.0.1:1", "audience": "poc", "http_timeout_ms": 300 });
    let v = verify("logos-pow-claim", &payload, 100, cfg.clone());
    assert!(reason_of(&v).contains("zkSign signature invalid"), "evidence decoded, digest bound, proof refused: {v}");
    let v = verify("logos-pow-claim", &payload, 100, json!({ "audience": "poc" }));
    assert!(v["error"].as_str().unwrap().contains("node_url"), "{v}");
    let short = hex::encode(frame(&part, &evidence[..10], 100));
    let v = verify("logos-pow-claim", &short, 100, cfg);
    assert!(reason_of(&v).starts_with("evidence:"), "{v}");

    let v = verify("eth-pow-claim", &payload, 100, json!({}));
    assert!(v["error"].as_str().unwrap().contains("does not accept the eth scheme"), "{v}");
    let req = json!({ "auth_type": "lez-pow-claim", "id_commitment_hex": IDC });
    let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &producers())).unwrap();
    assert!(out["error"].as_str().unwrap().contains("does not accept the lez scheme"), "{out}");
}

#[test]
fn keycard_allowlist_judges_the_card_before_its_signature() {
    let payload = hex::encode(frame(&hex::decode(GOLDEN_TLV).unwrap(), &[], 100));
    let v = verify("keycard-allowlist", &payload, 100, json!({ "allowlist": [TEST_CA] }));
    assert_eq!(reason_of(&v), format!("card not allowlisted: {IDENT_PUB}"));
    // Listed: the golden attestation signed a v1 challenge, not this binding.
    let v = verify("keycard-allowlist", &payload, 100, json!({ "allowlist": [IDENT_PUB] }));
    assert!(reason_of(&v).starts_with("attestation verification failed"), "{v}");
    let v = verify("keycard-allowlist", "a0", 100, json!({ "allowlist": [IDENT_PUB] }));
    assert!(reason_of(&v).contains("too short") || reason_of(&v).starts_with("attestation parse failed"), "{v}");
}

#[test]
fn attestation_trusts_the_ca_that_signed_the_card_key() {
    let att = keycard_attest::attest::parse_attestation(&hex::decode(GOLDEN_TLV).unwrap()).unwrap();
    let id = KeycardIdentity { ident_pub: att.ident_pub, ca_sig: att.ca_sig };
    let cfg = Attestation.config(&Keycard, Some(&json!({ "trusted_cas": [TEST_CA], "audience": "x" }))).unwrap();
    assert_eq!(Attestation.audience(cfg.as_ref()), "x");
    assert!(matches!(Attestation.authorise(cfg.as_ref(), &id, &()).unwrap(), Outcome::Ok(())));
    assert_eq!(Attestation.nullifier(&id, &()), hex::encode(keycard_attest::attest::nullifier(&att.ident_pub)));
    let other = Attestation.config(&Keycard, Some(&json!({ "trusted_cas": [format!("02{}", "11".repeat(32))] }))).unwrap();
    let Outcome::Reject(r) = Attestation.authorise(other.as_ref(), &id, &()).unwrap() else { panic!() };
    assert!(r.contains("CA is not trusted"), "{r}");
    assert!(Attestation.config(&Keycard, Some(&json!({ "trusted_cas": [] }))).unwrap_err().contains("empty"));
    assert!(Attestation.config(&Keycard, None).unwrap_err().contains("required"));
    assert!(!Attestation.accepts("eth") && Attestation.accepts("keycard"));
    let v = verify("keycard-attestation", &hex::encode(frame(&hex::decode(GOLDEN_TLV).unwrap(), &[], 100)), 100, json!({ "trusted_cas": [TEST_CA] }));
    assert!(reason_of(&v).starts_with("attestation verification failed"), "{v}");
    let v = verify("eth-attestation", "00", 100, json!({ "trusted_cas": [TEST_CA] }));
    assert!(v["error"].as_str().unwrap().contains("does not accept the eth scheme"), "{v}");
    assert_eq!(id.canonical(), IDENT_PUB);
}

#[test]
#[ignore = "the recorded node zkSign (crates/pow-claim/tests/fixtures/real) signs the v1 digest; re-record on the miner node with tools/pow-claim-poc"]
fn logos_pow_claim_accepts_the_recorded_real_claim() {
    unimplemented!("needs a zkSign over binding_digest(logos-pow-claim, …) by the claim key");
}
