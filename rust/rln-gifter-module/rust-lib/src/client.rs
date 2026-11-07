// Allocator client: request a gifted membership for an identity commitment from
// an allocator — discovered through libp2p service discovery, else the
// configured peer — over libp2p_module's generic protocolRequest bridge. The
// commitment is normally supplied by the caller (the RLN membership module,
// which keeps the identity secret). Auth is vector-agnostic: the payload is
// supplied raw or produced by an rln_auth_vector provider module named in the
// request — this module knows no vector by name.

use rln_auth_vector::ProduceRequest;
use serde_json::{json, Value};

use crate::lp::{self, b64, b64_decode};
use crate::wire::{
    service_data_lists, MembershipAllocationSuccess, RlnGifterRequest, RlnGifterResponse, RLN_GIFTER_CODEC,
    RLN_GIFTER_SERVICE_ID,
};

// The gifter round trip (dial + on-chain register on the server) can run up
// to ~3 minutes.
const REQUEST_TIMEOUT_MS: i64 = 190_000;
const REQUEST_CALL_TIMEOUT_MS: i32 = 205_000;
// Producer plugins may drive hardware (keycard capture covers
// connect+select+IDENTIFY plus a slow tap), so the budget is generous.
const PRODUCE_TIMEOUT_MS: i32 = 120_000;

/// How long after each of the first lookups the next one waits: discovery
/// answers from what the registrars hold, and an allocator that advertised
/// moments ago may not be placed yet. ~14 s in all.
const LOOKUP_WAITS_S: [u64; 4] = [0, 2, 4, 8];
const DISCO_TIMEOUT_MS: i32 = 30_000;

/// An allocator a discovery record names.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub peer_id: String,
    pub addrs: Vec<String>,
}

impl Candidate {
    fn json(&self) -> Value {
        json!({ "peerId": self.peer_id, "addrs": self.addrs })
    }
}

/// The allocators in a lookup reply that advertise this (registry, auth
/// type) pair, in reply order. The reply is libp2p's record array
/// `[{peerId, addrs, services:[{id, data(base64)}]}]`.
fn candidates_in(reply: &Value, registry_hex: &str, auth_type: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for rec in reply.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(peer_id) = rec.get("peerId").and_then(Value::as_str) else { continue };
        let listed = rec
            .get("services")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter(|svc| svc.get("id").and_then(Value::as_str) == Some(RLN_GIFTER_SERVICE_ID))
            .filter_map(|svc| svc.get("data").and_then(Value::as_str))
            .filter_map(|d| b64_decode(d).ok())
            .any(|data| service_data_lists(&data, registry_hex, auth_type));
        if !listed {
            continue;
        }
        let addrs: Vec<String> = rec
            .get("addrs")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if addrs.is_empty() || out.iter().any(|c: &Candidate| c.peer_id == peer_id) {
            continue;
        }
        out.push(Candidate { peer_id: peer_id.to_string(), addrs });
    }
    out
}

/// Look the allocators serving this pair up through libp2p service
/// discovery, polling until one answers or the budget ends. `Err` is a
/// node that cannot discover at all (no discovery mounted, libp2p down).
fn lookup(registry_hex: &str, auth_type: &str) -> Result<Vec<Candidate>, String> {
    // Interest first: it builds the per-service routing table the lookups
    // query; a repeat is harmless.
    let _ = lp::call_libp2p(
        "discoRegisterInterest",
        &json!([RLN_GIFTER_SERVICE_ID]),
        DISCO_TIMEOUT_MS,
    );
    for wait in LOOKUP_WAITS_S {
        if wait > 0 {
            std::thread::sleep(std::time::Duration::from_secs(wait));
        }
        let reply = lp::call_libp2p("discoLookup", &json!([RLN_GIFTER_SERVICE_ID, ""]), DISCO_TIMEOUT_MS)?;
        let found = candidates_in(&reply, registry_hex, auth_type);
        if !found.is_empty() {
            return Ok(found);
        }
    }
    Ok(Vec::new())
}

/// The trait's `discover`: args `{config, authType?}` → the allocators
/// currently advertising that (registry, auth type) pair,
/// `{serviceId, candidates:[{peerId, addrs}]}`; `config` names the registry
/// (the advertisement digests are per registry), `authType` absent means an
/// open allocator.
pub fn discover(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("discover args: {e}"))?;
    let registry = a
        .get("config")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or("discover needs config (the registry)")?;
    let registry = crate::wire::canonical_account(registry)?;
    let auth_type = a.get("authType").and_then(Value::as_str).unwrap_or("");
    let candidates = lookup(&registry, auth_type)?;
    Ok(json!({
        "serviceId": RLN_GIFTER_SERVICE_ID,
        "candidates": candidates.iter().map(Candidate::json).collect::<Vec<_>>(),
    }))
}

/// Why one allocator did not grant: before it read the request (another
/// may), or after (the registration may have happened; stop).
enum Attempt {
    Next(String),
    Stop(String),
}

impl Attempt {
    fn message(self) -> String {
        match self {
            Attempt::Next(m) | Attempt::Stop(m) => m,
        }
    }
}

/// One request→response with one allocator over the generic libp2p bridge,
/// to the caller's grant shape.
fn ask(peer_id: &str, addrs: &[String], req: &RlnGifterRequest, config: Option<&str>) -> Result<Value, Attempt> {
    let pr_args = json!({
        "peerId": peer_id,
        "multiaddrs": addrs,
        "proto": RLN_GIFTER_CODEC,
        "requestB64": b64(&req.encode()),
        "timeoutMs": REQUEST_TIMEOUT_MS,
    });
    let pr = match lp::call_libp2p("protocolRequest", &json!([pr_args.to_string()]), REQUEST_CALL_TIMEOUT_MS) {
        Ok(v) => v,
        // Nothing reached the allocator: the dial or the write failed.
        Err(e) if e.contains("dial failed") || e.contains("dial returned no stream") || e.contains("write failed") => {
            return Err(Attempt::Next(e))
        }
        Err(e) => return Err(Attempt::Stop(e)),
    };
    let resp_b64 = pr
        .get("responseB64")
        .and_then(Value::as_str)
        .ok_or_else(|| Attempt::Stop(format!("protocolRequest: no responseB64 in {pr}")))?;
    let resp = RlnGifterResponse::decode(&b64_decode(resp_b64).map_err(Attempt::Stop)?).map_err(Attempt::Stop)?;

    if resp.request_id != req.request_id {
        return Err(Attempt::Stop("gifter response requestId mismatch".into()));
    }
    judge(resp, config).map(|success| grant_json(peer_id, &req.identity_commitment, success))
}

/// The grant, or why not and whether another allocator may be asked: a
/// refusal before registration (`auth_success` false: registry not served,
/// unsupported or rejected vector, spent credential) and a registration the
/// allocator never submitted (`not submitted: …`) move on; anything after
/// the request was acted on stops.
fn judge(resp: RlnGifterResponse, config: Option<&str>) -> Result<MembershipAllocationSuccess, Attempt> {
    if !resp.auth_success {
        return Err(Attempt::Next(
            resp.error
                .or_else(|| resp.failure.as_ref().map(|f| f.error_message.clone()))
                .unwrap_or_else(|| "gifter authentication failed".into()),
        ));
    }
    let success = resp.success.ok_or_else(|| {
        let why = resp
            .failure
            .as_ref()
            .map(|f| f.error_message.clone())
            .or(resp.error.clone())
            .unwrap_or_else(|| "gifter returned no membership".into());
        if why.starts_with(crate::wire::NOT_SUBMITTED_PREFIX) {
            Attempt::Next(why)
        } else {
            Attempt::Stop(why)
        }
    })?;

    // The membership is only useful on the registry the caller polls; a
    // allocator that registered it elsewhere has spent for nothing.
    if let (Some(want), Some(got)) = (config, &success.config_account_id) {
        if !got.eq_ignore_ascii_case(want) {
            return Err(Attempt::Stop(format!("gifter registered on {got}, not the requested {want}")));
        }
    }
    Ok(success)
}

/// The caller's grant shape.
fn grant_json(peer_id: &str, identity_commitment: &[u8], success: MembershipAllocationSuccess) -> Value {
    let tx_hash = hex::encode(&success.transaction_hash);
    // The gifter membership flow sends no mix-RLN messages, so there is no
    // identity to adopt into a mix/proof subsystem, and the client runs against a
    // PLAIN libp2p node (vanilla upstream) that has no such surface. The app
    // persists the credential to its keystore from its own generate_identity.
    let mut out = json!({
        "leaf_index": success.leaf_index,
        "id_commitment": hex::encode(identity_commitment),
        "auth_success": true,
        "identity_adopted": false,
        "gifterPeerId": peer_id,
    });
    if !tx_hash.is_empty() {
        out["tx_hash"] = json!(tx_hash);
    }
    if let Some(cfg) = success.config_account_id {
        out["config_account"] = json!(cfg);
    }
    out
}

/// Client entry point (the trait's `request`): args
/// `{config?, identityCommitment, rate?, authType?, authPayload?,
///  authProvider?, authArgs?, discover?, gifterPeerId?, gifterMultiaddr?}`.
/// `config` names the registry (ConfigState account) the membership is
/// wanted on; absent, the allocator's default registry. Allocators advertising
/// the (registry, auth type) pair are discovered first (`discover`, default
/// true; needs `config`) and tried in turn while none has read the request;
/// the configured `gifterPeerId`+`gifterMultiaddr` pair comes after them.
/// A grant on another registry is an error.
/// Returns `{leaf_index, id_commitment, auth_success, identity_adopted,
///  gifterPeerId, discovered, tx_hash?, config_account?}`.
pub fn request(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("request args: {e}"))?;
    let gifter_peer_id = a.get("gifterPeerId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let gifter_multiaddr = a.get("gifterMultiaddr").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let configured = match (gifter_peer_id, gifter_multiaddr) {
        (Some(p), Some(m)) => Some((p.to_string(), m.to_string())),
        (None, None) => None,
        _ => return Err("gifterPeerId and gifterMultiaddr go together".into()),
    };
    let discover = match a.get("discover") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("discover must be a boolean".into()),
    };
    if !discover && configured.is_none() {
        return Err("request needs discover or gifterPeerId+gifterMultiaddr".into());
    }
    let config = match a.get("config").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
        Some(c) => Some(crate::wire::canonical_account(c)?),
        None => None,
    };
    if discover && config.is_none() && configured.is_none() {
        return Err("discovery needs config (the registry); name one or configure gifterPeerId+gifterMultiaddr".into());
    }
    let provided_commitment =
        a.get("identityCommitment").and_then(Value::as_str).unwrap_or("");
    let rate = a.get("rate").and_then(Value::as_u64).unwrap_or(0);

    // The commitment comes from the caller — the RLN membership module
    // generates the credential in-module and passes only its commitment, so
    // the identity secret never reaches this module. Lowercased so producer
    // and verifier see the same string for the same commitment (the server
    // side hex-encodes, which is lowercase).
    if provided_commitment.is_empty() {
        return Err("request needs identityCommitment".into());
    }
    let id_commitment_hex = provided_commitment.trim_start_matches("0x").to_lowercase();
    let id_commitment =
        hex::decode(&id_commitment_hex).map_err(|e| format!("id_commitment hex: {e}"))?;
    // The allocator refuses the same values; failing here costs no producer
    // call, no dial and no verifier round-trip on the allocator.
    if let Some(why) = crate::wire::commitment_refusal(&id_commitment) {
        return Err(why.into());
    }

    // Auth vector + payload. `authType` names the vector in the wire's
    //    OPEN authentication_type vocabulary — any type the target allocator is
    //    configured to verify (its authVerifiers modules); this client never
    //    gatekeeps it and knows no vector by name. The payload comes from
    //    `authPayload` (raw hex, verbatim — material the application produced
    //    itself, e.g. an external wallet signature) or from an `authProvider`
    //    module implementing the rln_auth_vector producer contract
    //    (PRODUCE_METHOD, `authArgs` forwarded verbatim — e.g. keycard
    //    capture). No authType at all is an UNAUTHENTICATED request for an
    //    open allocator: empty type, empty payload.
    let auth_type_req = a.get("authType").and_then(Value::as_str).unwrap_or("");
    let auth_payload_hex = a.get("authPayload").and_then(Value::as_str).unwrap_or("");
    let auth_provider = a.get("authProvider").and_then(Value::as_str).unwrap_or("");
    if !auth_payload_hex.is_empty() && !auth_provider.is_empty() {
        return Err("authPayload and authProvider are mutually exclusive".into());
    }
    let auth_payload: Vec<u8> = if auth_type_req.is_empty() {
        if !auth_payload_hex.is_empty() || !auth_provider.is_empty() {
            return Err("authPayload/authProvider need an explicit authType".into());
        }
        Vec::new()
    } else if !auth_payload_hex.is_empty() {
        hex::decode(auth_payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("authPayload hex: {e}"))?
    } else if !auth_provider.is_empty() {
        let prod_req = ProduceRequest {
            auth_type: auth_type_req.to_string(),
            id_commitment_hex: id_commitment_hex.clone(),
            args: a.get("authArgs").cloned(),
        };
        let prod_json =
            serde_json::to_string(&prod_req).map_err(|e| format!("produce request: {e}"))?;
        let reply = lp::call_module_json(
            auth_provider,
            rln_auth_vector::PRODUCE_METHOD,
            &json!([prod_json]),
            PRODUCE_TIMEOUT_MS,
        )?;
        let reply = rln_auth_vector::parse_produce_reply(&reply)
            .map_err(|e| format!("auth provider {auth_provider}: {e}"))?;
        hex::decode(reply.payload_hex.trim_start_matches("0x"))
            .map_err(|e| format!("auth provider payload hex: {e}"))?
    } else {
        return Err(format!("authType '{auth_type_req}' needs authPayload or authProvider"));
    };

    let request_id = format!("gift-{}", &id_commitment_hex[..id_commitment_hex.len().min(16)]);
    let req = RlnGifterRequest {
        request_id,
        authentication_type: auth_type_req.as_bytes().to_vec(),
        authentication_payload: auth_payload,
        identity_commitment: id_commitment,
        rate_limit: if rate > 0 { Some(rate) } else { None },
        config_account_id: config.clone(),
    };

    // Discovered allocators first, rotated by the commitment so clients
    // spread over them; then the configured one.
    let mut tried: Vec<String> = Vec::new();
    if let (true, Some(registry)) = (discover, config.as_deref()) {
        match lookup(registry, auth_type_req) {
            Ok(mut found) => {
                if !found.is_empty() {
                    let at = req.identity_commitment[0] as usize % found.len();
                    found.rotate_left(at);
                }
                for c in &found {
                    match ask(&c.peer_id, &c.addrs, &req, config.as_deref()) {
                        Ok(mut out) => {
                            out["discovered"] = json!(true);
                            return Ok(out);
                        }
                        Err(Attempt::Next(e)) => tried.push(format!("{}: {e}", c.peer_id)),
                        Err(Attempt::Stop(e)) => return Err(format!("{}: {e}", c.peer_id)),
                    }
                }
                if found.is_empty() {
                    tried.push(format!("no allocator advertises {registry}/{auth_type_req}"));
                }
            }
            Err(e) => tried.push(format!("discovery unavailable: {e}")),
        }
    }
    if let Some((peer_id, multiaddr)) = &configured {
        return match ask(peer_id, std::slice::from_ref(multiaddr), &req, config.as_deref()) {
            Ok(mut out) => {
                out["discovered"] = json!(false);
                Ok(out)
            }
            Err(e) => Err(if tried.is_empty() { e.message() } else { format!("{}; before that: {}", e.message(), tried.join("; ")) }),
        };
    }
    Err(format!("no allocator granted and none is configured: {}", tried.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(extra: &str) -> Result<Value, String> {
        request(&format!(
            r#"{{"gifterPeerId":"12D3KooWTest","gifterMultiaddr":"/ip4/127.0.0.1/tcp/1",
                 "identityCommitment":"{}",{extra}"rate":100}}"#,
            canonical()
        ))
    }

    // 0xab repeated reads (little-endian) above r; a 0x0a top byte keeps the
    // value canonical whatever the lower bytes hold.
    fn canonical() -> String { format!("{}0a", "ab".repeat(31)) }
    fn canonical_upper() -> String { format!("{}0A", "AB".repeat(31)) }

    #[test]
    fn non_canonical_commitment_is_refused_before_any_io() {
        for (idc, want) in [("ff".repeat(32), "invalid_commitment: not a BN254"), ("00".repeat(32), "invalid_commitment: zero"), ("ab".repeat(31), "32 bytes")] {
            let e = request(&format!(
                r#"{{"gifterPeerId":"p","gifterMultiaddr":"/m","identityCommitment":"{idc}","rate":100}}"#
            ))
            .unwrap_err();
            assert!(e.contains(want), "{idc}: got {e}");
        }
    }

    #[test]
    fn a_malformed_config_account_is_refused_before_any_io() {
        let e = req(r#""config":"nope","#).unwrap_err();
        assert!(e.contains("config account 'nope'"), "got: {e}");
    }

    #[test]
    fn payload_and_provider_are_mutually_exclusive() {
        let e = req(r#""authType":"voucher-v1","authPayload":"aa","authProvider":"m","#)
            .unwrap_err();
        assert!(e.contains("mutually exclusive"), "got: {e}");
    }

    #[test]
    fn payload_material_needs_an_explicit_auth_type() {
        for extra in [r#""authPayload":"aa","#, r#""authProvider":"m","#] {
            let e = req(extra).unwrap_err();
            assert!(e.contains("need an explicit authType"), "got: {e}");
        }
    }

    #[test]
    fn named_vector_needs_a_payload_source() {
        let e = req(r#""authType":"voucher-v1","#).unwrap_err();
        assert!(e.contains("needs authPayload or authProvider"), "got: {e}");
    }

    #[test]
    fn bad_payload_hex_is_rejected_before_any_io() {
        let e = req(r#""authType":"voucher-v1","authPayload":"zz","#).unwrap_err();
        assert!(e.contains("authPayload hex"), "got: {e}");
    }

    #[test]
    fn a_configured_pair_is_both_or_neither() {
        let e = request(&format!(
            r#"{{"gifterPeerId":"p","identityCommitment":"{}","rate":100}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("go together"), "got: {e}");
    }

    #[test]
    fn without_discovery_a_pair_is_required() {
        let e = request(&format!(
            r#"{{"discover":false,"identityCommitment":"{}","rate":100}}"#,
            canonical()
        ))
        .unwrap_err();
        assert!(e.contains("needs discover or gifterPeerId"), "got: {e}");
        let e = request(&format!(r#"{{"discover":"no","identityCommitment":"{}"}}"#, canonical())).unwrap_err();
        assert!(e.contains("discover must be a boolean"), "got: {e}");
    }

    #[test]
    fn discovery_needs_a_registry_to_match_on() {
        let e = request(&format!(r#"{{"identityCommitment":"{}","rate":100}}"#, canonical())).unwrap_err();
        assert!(e.contains("discovery needs config"), "got: {e}");
        let e = discover("{}").unwrap_err();
        assert!(e.contains("discover needs config"), "got: {e}");
        let e = discover(r#"{"config":"nope"}"#).unwrap_err();
        assert!(e.contains("config account 'nope'"), "got: {e}");
    }

    #[test]
    fn a_lookup_reply_yields_the_allocators_advertising_the_pair() {
        let (d, m) = (hex::encode([0xd; 32]), hex::encode([0xa; 32]));
        let data = crate::wire::service_data(&[(d.clone(), "peer-any".into())]).unwrap();
        let rec = |peer: &str, data: &str, addrs: Value| {
            json!({ "peerId": peer, "seqNo": 1, "addrs": addrs,
                    "services": [{ "id": RLN_GIFTER_SERVICE_ID, "data": b64(data.as_bytes()) }] })
        };
        let reply = json!([
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/1"])),
            rec("B", &data, json!([])),
            rec("A", &data, json!(["/ip4/127.0.0.1/tcp/2"])),
            rec("C", "1zzzz", json!(["/ip4/127.0.0.1/tcp/3"])),
            json!({ "peerId": "D", "addrs": ["/ip4/127.0.0.1/tcp/4"],
                    "services": [{ "id": "/other", "data": b64(data.as_bytes()) }] }),
        ]);
        assert_eq!(
            candidates_in(&reply, &d, "peer-any"),
            [Candidate { peer_id: "A".into(), addrs: vec!["/ip4/127.0.0.1/tcp/1".into()] }]
        );
        assert!(candidates_in(&reply, &m, "peer-any").is_empty());
        assert!(candidates_in(&reply, &d, "eth-allowlist").is_empty());
        assert!(candidates_in(&json!([]), &d, "peer-any").is_empty());
        assert!(candidates_in(&json!(null), &d, "peer-any").is_empty());
    }

    // Which replies let the client ask the next allocator: refusals before
    // registration and registrations the allocator never submitted; a
    // registration that may have landed, or landed elsewhere, stops.
    #[test]
    fn a_reply_says_whether_the_next_allocator_may_be_asked() {
        use crate::wire::{MembershipAllocationFailure, MembershipAllocationSuccess};
        let refused = RlnGifterResponse { request_id: "r".into(), auth_success: false, error: Some("credential already used: x".into()), ..Default::default() };
        assert!(matches!(judge(refused, None), Err(Attempt::Next(m)) if m.contains("already used")));
        let not_submitted = RlnGifterResponse { request_id: "r".into(), auth_success: true,
            failure: Some(MembershipAllocationFailure { error_message: "not submitted: register_member refused: insufficient_balance".into() }), ..Default::default() };
        assert!(matches!(judge(not_submitted, None), Err(Attempt::Next(m)) if m.starts_with("not submitted")));
        let unconfirmed = RlnGifterResponse { request_id: "r".into(), auth_success: true,
            failure: Some(MembershipAllocationFailure { error_message: "unconfirmed: registration submitted (tx ab) but not on chain within 150s".into() }), ..Default::default() };
        assert!(matches!(judge(unconfirmed, None), Err(Attempt::Stop(m)) if m.starts_with("unconfirmed")));
        let elsewhere = RlnGifterResponse { request_id: "r".into(), auth_success: true,
            success: Some(MembershipAllocationSuccess { leaf_index: 1, config_account_id: Some("bb".repeat(32)), ..Default::default() }), ..Default::default() };
        assert!(matches!(judge(elsewhere, Some(&"aa".repeat(32))), Err(Attempt::Stop(m)) if m.contains("registered on")));
        let granted = RlnGifterResponse { request_id: "r".into(), auth_success: true,
            success: Some(MembershipAllocationSuccess { leaf_index: 4, config_account_id: Some("aa".repeat(32)), ..Default::default() }), ..Default::default() };
        assert_eq!(judge(granted, Some(&"aa".repeat(32))).map(|s| s.leaf_index).ok(), Some(4));
    }

    #[test]
    fn commitment_is_lowercased_for_the_producer_contract() {
        // Uppercase commitment + provider: fails at the lp stub, but the arg
        // shape is accepted — the identity path must not be the error.
        let e = request(&format!(
            r#"{{"gifterPeerId":"p","gifterMultiaddr":"/m",
                 "identityCommitment":"{}","authType":"t","authProvider":"m"}}"#,
            canonical_upper()
        ))
        .unwrap_err();
        assert!(!e.contains("id_commitment hex"), "got: {e}");
    }
}
