//! The one pipeline every composed vector runs.

use crate::authtype::AuthType;
use crate::binding::{binding_digest, Binding};
use crate::frame::{frame, unframe};
use crate::hex::strip_0x;
use crate::pieces::Outcome;
use crate::reason;
use crate::registry::{ProduceRegistry, VerifyRegistry};
use crate::types::{ProduceReply, ProduceRequest, Verdict, VerifyRequest};

macro_rules! reject_on {
    ($e:expr) => {
        match $e {
            Outcome::Ok(v) => v,
            Outcome::Reject(r) => return Ok(Verdict::reject(r)),
        }
    };
}

/// config → hex → unframe → scheme part → evidence → binding → rate →
/// [authorise the claim] → digest → signature → [authorise the proof] →
/// nullifier. `Err` is an operator/host problem (the envelope); every
/// requester problem is a reject verdict.
pub fn verify_flow(r: &VerifyRegistry, req: &VerifyRequest) -> Result<Verdict, String> {
    let t = AuthType::parse(&req.auth_type)?;
    let (scheme, auth) = r.resolve(&t)?;
    let scfg = scheme.config(req.config.as_ref())?;
    let cfg = auth.config(scheme, req.config.as_ref())?;

    let bytes = match hex::decode(strip_0x(&req.payload_hex)) {
        Ok(b) => b,
        Err(e) => return Ok(Verdict::reject(reason::payload_hex(e))),
    };
    let (body, rate_max) = reject_on!(unframe(&bytes));
    let d = reject_on!(scheme.decode(body));
    let (ev, rest) = reject_on!(auth.decode_evidence(d.rest));
    if !rest.is_empty() {
        return Ok(Verdict::reject(reason::trailing_bytes(rest.len())));
    }
    let b = reject_on!(Binding::for_verify(req, rate_max, auth.audience(cfg.as_ref())));
    if req.rate > rate_max {
        return Ok(Verdict::reject(reason::rate_exceeds(req.rate, rate_max)));
    }

    let judged_claim = match (&d.claimed, auth.before_sig()) {
        (Some(claimed), true) => {
            reject_on!(auth.authorise(cfg.as_ref(), claimed.as_ref(), ev.as_ref())?);
            true
        }
        _ => false,
    };

    let digest = binding_digest(&t, &b, &auth.extra(ev.as_ref()));
    let proven = reject_on!(scheme.verify(scfg.as_ref(), &b, &digest, &d)?);
    if let Some(claimed) = &d.claimed {
        let (c, p) = (claimed.canonical(), proven.canonical());
        if c != p {
            return Ok(Verdict::reject(reason::identity_mismatch(&c, &p)));
        }
    }
    if !judged_claim {
        reject_on!(auth.authorise(cfg.as_ref(), proven.as_ref(), ev.as_ref())?);
    }
    Ok(Verdict::accept(Some(auth.nullifier(proven.as_ref(), ev.as_ref()))))
}

/// binding → evidence → digest → scheme part → frame.
pub fn produce_flow(r: &ProduceRegistry, req: &ProduceRequest) -> Result<ProduceReply, String> {
    let t = AuthType::parse(&req.auth_type)?;
    let (signer, claimant) = r.resolve(&t)?;
    let b = Binding::from_produce(req)?;
    let evidence = claimant.gather(&b, req.args.as_ref())?;
    let digest = binding_digest(&t, &b, &claimant.extra(&evidence));
    let part = signer.sign(&b, &digest, req.args.as_ref())?;
    Ok(ProduceReply { payload_hex: hex::encode(frame(&part, &evidence, b.rate_max)) })
}

#[cfg(test)]
mod tests {
    //! A toy scheme (part = 32-byte id ‖ 1-byte "signature" = digest[0]) and
    //! two toy authorisers prove the composition and the step order.
    use std::any::Any;

    use serde_json::{json, Value};

    use super::*;
    use crate::pieces::{Authoriser, Cfg, Check, Claimant, Decoded, Evidence, Identity, Scheme, Signer};
    use crate::registry::{dispatch_produce, dispatch_verify};

    struct ToyId(String);
    impl Identity for ToyId {
        fn canonical(&self) -> String {
            self.0.clone()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct Toy(&'static str);
    impl Scheme for Toy {
        fn name(&self) -> &'static str {
            self.0
        }
        fn parse_identity(&self, s: &str) -> Result<String, String> {
            crate::norm_hex32("config.allowlist entry", s)
        }
        fn decode<'a>(&self, body: &'a [u8]) -> Outcome<Decoded<'a>> {
            if body.len() < 33 {
                return Outcome::Reject(format!("toy part must be 33 bytes, got {}", body.len()));
            }
            let (part, rest) = body.split_at(33);
            Outcome::Ok(Decoded { claimed: Some(Box::new(ToyId(hex::encode(&part[..32])))), part, rest })
        }
        fn verify(&self, _cfg: &dyn Any, _b: &Binding, digest: &[u8; 32], d: &Decoded<'_>) -> Check<Box<dyn Identity>> {
            if d.part[32] != digest[0] {
                return Ok(Outcome::Reject(reason::SIG_FAILED.into()));
            }
            Ok(Outcome::Ok(Box::new(ToyId(hex::encode(&d.part[..32])))))
        }
    }

    struct ToySigner(&'static str, [u8; 32]);
    impl Signer for ToySigner {
        fn scheme(&self) -> &'static str {
            self.0
        }
        fn sign(&self, _b: &Binding, digest: &[u8; 32], _args: Option<&Value>) -> Result<Vec<u8>, String> {
            let mut v = self.1.to_vec();
            v.push(digest[0]);
            Ok(v)
        }
        fn identity(&self, _args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
            Ok(Box::new(ToyId(hex::encode(self.1))))
        }
    }

    /// Allowlist of toy ids; judges the claim before the signature.
    struct List;
    struct ListCfg(Vec<String>, String);
    impl Authoriser for List {
        fn name(&self) -> &'static str {
            "list"
        }
        fn accepts(&self, _scheme: &str) -> bool {
            true
        }
        fn config(&self, scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
            let entries = raw
                .and_then(|c| c.get("allowlist"))
                .and_then(Value::as_array)
                .ok_or_else(|| reason::allowlist_required("toy ids"))?;
            let list = entries
                .iter()
                .map(|e| e.as_str().ok_or(reason::ENTRIES_NOT_STRINGS.to_string()).and_then(|s| scheme.parse_identity(s)))
                .collect::<Result<Vec<_>, _>>()?;
            let aud = raw.and_then(|c| c.get("audience")).and_then(Value::as_str).unwrap_or("").to_string();
            Ok(Box::new(ListCfg(list, aud)))
        }
        fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str {
            &cfg.downcast_ref::<ListCfg>().unwrap().1
        }
        fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
            Outcome::Ok((Box::new(()), rest))
        }
        fn extra(&self, _ev: &dyn Any) -> Vec<u8> {
            Vec::new()
        }
        fn before_sig(&self) -> bool {
            true
        }
        fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, _ev: &dyn Any) -> Check<()> {
            let cfg = cfg.downcast_ref::<ListCfg>().unwrap();
            if cfg.0.contains(&id.canonical()) {
                Ok(Outcome::Ok(()))
            } else {
                Ok(Outcome::Reject(reason::not_allowlisted("toy id", &id.canonical())))
            }
        }
    }
    struct NoClaim(&'static str);
    impl Claimant for NoClaim {
        fn authoriser(&self) -> &'static str {
            self.0
        }
        fn accepts(&self, _scheme: &str) -> bool {
            true
        }
        fn gather(&self, _b: &Binding, _args: Option<&Value>) -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
        fn extra(&self, _evidence: &[u8]) -> Vec<u8> {
            Vec::new()
        }
    }

    /// Binds 4 bytes of evidence, only for the `toy` scheme, after the signature.
    struct Stamp;
    impl Authoriser for Stamp {
        fn name(&self) -> &'static str {
            "stamp"
        }
        fn accepts(&self, scheme: &str) -> bool {
            scheme == "toy"
        }
        fn config(&self, _scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
            if raw.and_then(|c| c.get("broken")).is_some() {
                return Err("config.broken: operator mistake".into());
            }
            Ok(Box::new(()))
        }
        fn audience<'a>(&self, _cfg: &'a dyn Any) -> &'a str {
            "stamped"
        }
        fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
            if rest.len() < 4 {
                return Outcome::Reject("stamp evidence must be 4 bytes".into());
            }
            let (ev, rest) = rest.split_at(4);
            Outcome::Ok((Box::new(ev.to_vec()), rest))
        }
        fn extra(&self, ev: &dyn Any) -> Vec<u8> {
            ev.downcast_ref::<Vec<u8>>().unwrap().clone()
        }
        fn authorise(&self, _cfg: &dyn Any, _id: &dyn Identity, ev: &dyn Any) -> Check<()> {
            if ev.downcast_ref::<Vec<u8>>().unwrap() == b"stmp" {
                Ok(Outcome::Ok(()))
            } else {
                Ok(Outcome::Reject("bad stamp".into()))
            }
        }
        fn nullifier(&self, id: &dyn Identity, _ev: &dyn Any) -> String {
            format!("{}:stamped", id.canonical())
        }
    }
    struct StampClaim;
    impl Claimant for StampClaim {
        fn authoriser(&self) -> &'static str {
            "stamp"
        }
        fn accepts(&self, scheme: &str) -> bool {
            scheme == "toy"
        }
        fn gather(&self, _b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String> {
            Ok(args.and_then(|a| a.get("stamp")).and_then(Value::as_str).unwrap_or("stmp").as_bytes().to_vec())
        }
        fn extra(&self, evidence: &[u8]) -> Vec<u8> {
            evidence.to_vec()
        }
    }

    const KEY: [u8; 32] = [0x42; 32];
    fn verify_registry() -> VerifyRegistry {
        VerifyRegistry::new().scheme(Toy("toy")).scheme(Toy("alt")).authoriser(List).authoriser(Stamp)
    }
    fn produce_registry() -> ProduceRegistry {
        ProduceRegistry::new()
            .signer(ToySigner("toy", KEY))
            .signer(ToySigner("alt", KEY))
            .claimant(NoClaim("list"))
            .claimant(StampClaim)
    }
    fn produce(auth_type: &str, args: Value) -> String {
        let req = json!({ "auth_type": auth_type, "id_commitment_hex": "11".repeat(32), "args": args });
        let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap();
        out["payload_hex"].as_str().unwrap_or_else(|| panic!("{out}")).to_string()
    }
    fn verify(auth_type: &str, payload_hex: &str, rate: u64, config: Value) -> Value {
        let req = json!({
            "auth_type": auth_type, "payload_hex": payload_hex,
            "id_commitment_hex": "11".repeat(32), "rate": rate, "config": config
        });
        serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap()
    }
    fn listed() -> Value {
        json!({ "allowlist": [hex::encode(KEY)] })
    }

    #[test]
    fn registries_list_only_the_compositions_that_exist() {
        assert_eq!(verify_registry().auth_types(), ["toy-list", "toy-stamp", "alt-list"]);
        assert_eq!(produce_registry().auth_types(), ["toy-list", "toy-stamp", "alt-list"]);
    }

    #[test]
    fn produce_then_verify_round_trips_both_authorisers() {
        let p = produce("toy-list", json!({ "rate_max": 50 }));
        let v = verify("toy-list", &p, 50, listed());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], hex::encode(KEY));

        let p = produce("toy-stamp", json!({ "audience": "stamped" }));
        let v = verify("toy-stamp", &format!("0x{p}"), 100, json!({}));
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["nullifier"], format!("{}:stamped", hex::encode(KEY)));
        let p = produce("alt-list", json!({}));
        assert_eq!(verify("alt-list", &p, 1, listed())["ok"], true);
    }

    #[test]
    fn refused_and_unknown_compositions_use_the_error_envelope() {
        let req = json!({ "auth_type": "alt-stamp", "payload_hex": "00", "id_commitment_hex": "11".repeat(32) });
        let out: Value = serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().contains("does not accept the alt scheme"), "{out}");
        let req = json!({ "auth_type": "nope-list", "payload_hex": "00", "id_commitment_hex": "11".repeat(32) });
        let out: Value = serde_json::from_str(&dispatch_verify(&req.to_string(), &verify_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().contains("unknown auth_type 'nope-list'"), "{out}");
        let req = json!({ "auth_type": "alt-stamp", "id_commitment_hex": "11".repeat(32) });
        let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().contains("unknown auth_type"), "{out}");
        let req = json!({ "auth_type": "toylist", "id_commitment_hex": "11".repeat(32) });
        let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().contains("<scheme>-<authoriser>"), "{out}");
    }

    #[test]
    fn operator_mistakes_are_errors_requester_mistakes_are_rejects() {
        let p = produce("toy-list", json!({}));
        let v = verify("toy-list", &p, 1, json!({}));
        assert!(v["error"].as_str().unwrap().contains("config.allowlist"), "{v}");
        let v = verify("toy-stamp", &p, 1, json!({ "broken": 1 }));
        assert!(v["error"].as_str().unwrap().contains("operator mistake"), "{v}");

        let v = verify("toy-list", "zz", 1, listed());
        assert!(v["reason"].as_str().unwrap().starts_with("payload hex:"), "{v}");
        let v = verify("toy-list", "02", 1, listed());
        assert!(v["reason"].as_str().unwrap().contains("too short"), "{v}");
        let mut old = hex::decode(&p).unwrap();
        old[0] = 1;
        let v = verify("toy-list", &hex::encode(&old), 1, listed());
        assert_eq!(v["reason"], "payload version 1, want 2");
        let mut long = hex::decode(&p).unwrap();
        long.insert(34, 0);
        let v = verify("toy-list", &hex::encode(&long), 1, listed());
        assert_eq!(v["reason"], "payload has 1 trailing bytes");
    }

    #[test]
    fn rate_above_the_signed_rate_max_is_rejected() {
        let p = produce("toy-list", json!({ "rate_max": 10 }));
        assert_eq!(verify("toy-list", &p, 10, listed())["ok"], true);
        let v = verify("toy-list", &p, 11, listed());
        assert_eq!(v["reason"], "rate 11 exceeds the signed rate_max 10");
    }

    #[test]
    fn a_wrong_signature_audience_or_evidence_is_rejected() {
        let p = produce("toy-list", json!({ "audience": "a" }));
        let v = verify("toy-list", &p, 1, json!({ "allowlist": [hex::encode(KEY)], "audience": "b" }));
        assert_eq!(v["reason"], reason::SIG_FAILED, "{v}");
        let mut tampered = hex::decode(&p).unwrap();
        tampered[33] ^= 0xff;
        let v = verify("toy-list", &hex::encode(&tampered), 1, json!({ "allowlist": [hex::encode(KEY)], "audience": "a" }));
        assert_eq!(v["reason"], reason::SIG_FAILED);

        let p = produce("toy-stamp", json!({ "audience": "stamped", "stamp": "xxxx" }));
        let v = verify("toy-stamp", &p, 1, json!({}));
        assert_eq!(v["reason"], "bad stamp", "the evidence verified (it is bound) but is refused");
    }

    #[test]
    fn before_sig_judges_the_claim_first_otherwise_the_proof() {
        // list (before_sig): an unlisted claim is refused before the bad signature is noticed.
        let p = produce("toy-list", json!({}));
        let mut tampered = hex::decode(&p).unwrap();
        tampered[33] ^= 0xff;
        let v = verify("toy-list", &hex::encode(&tampered), 1, json!({ "allowlist": ["00".repeat(32)] }));
        assert!(v["reason"].as_str().unwrap().contains("not allowlisted"), "{v}");
        // stamp (after): the signature is checked first.
        let p = produce("toy-stamp", json!({ "audience": "stamped", "stamp": "xxxx" }));
        let mut tampered = hex::decode(&p).unwrap();
        tampered[33] ^= 0xff;
        let v = verify("toy-stamp", &hex::encode(&tampered), 1, json!({}));
        assert_eq!(v["reason"], reason::SIG_FAILED);
    }

    #[test]
    fn produce_errors_name_the_callers_problem() {
        let req = json!({ "auth_type": "toy-list", "id_commitment_hex": "11".repeat(31) });
        let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().starts_with("id_commitment_hex"), "{out}");
        let req = json!({ "auth_type": "toy-list", "id_commitment_hex": "11".repeat(32), "args": { "rate_max": "x" } });
        let out: Value = serde_json::from_str(&dispatch_produce(&req.to_string(), &produce_registry())).unwrap();
        assert!(out["error"].as_str().unwrap().starts_with("rate_max"), "{out}");
    }
}
