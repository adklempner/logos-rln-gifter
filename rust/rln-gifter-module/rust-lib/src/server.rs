// Allocator (server): mount /logos/rln/membership/1.0.0 over libp2p_module's
// generic protocol bridge, authenticate each request through the configured
// vector's verifier module (rln_auth_vector contract — this module ships no
// vector of its own), and register the membership on-chain via
// liblogos_lez_rln_module. A single serialized worker drains inbound streams so
// the funded payer's tx nonce stays ordered.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rln_auth_vector::VerifyRequest;
use serde_json::{json, Value};

use crate::auth;
use crate::lp::{self, b64, b64_decode, lock};
use crate::wire::{
    canonical_account, service_data, MembershipAllocationFailure, MembershipAllocationSuccess,
    RlnGifterRequest, RlnGifterResponse, RLN_GIFTER_CODEC, RLN_GIFTER_SERVICE_ID,
};

// The accept poll blocks libp2p_module's call dispatcher (a condvar wait in
// `protocolAcceptStream`): while one is pending the module answers nothing
// else, from anyone. Short, so the worker can run the discovery calls a
// re-serve asks for between two accepts; a timed-out accept is idle, not an
// error.
const ACCEPT_TIMEOUT_MS: i32 = 2_000;
const ACCEPT_IDLE: &str = "timeout waiting for inbound stream";
// The lp call outlives libp2p's own accept timeout by this much: a caller
// that gives up first while libp2p pops the stream a moment later loses that
// request (the stream is dequeued, nobody reads it).
const ACCEPT_CALL_MARGIN_MS: i32 = 3_000;
const READ_TIMEOUT_MS: i32 = 60_000;
const WRITE_TIMEOUT_MS: i32 = 30_000;
const REGISTER_TIMEOUT_MS: i32 = 190_000;
/// How long a submitted registration may take to show up on chain before the
/// request is answered as unconfirmed, and how often the registry is read
/// meanwhile. The client allows REQUEST_TIMEOUT_MS (190 s) for the whole
/// exchange; one registration fits per block.
const CONFIRM_BUDGET: std::time::Duration = std::time::Duration::from_secs(150);
const CONFIRM_POLL: std::time::Duration = std::time::Duration::from_secs(2);
const GET_MEMBERSHIP_TIMEOUT_MS: i32 = 30_000;
const MOUNT_TIMEOUT_MS: i32 = 30_000;
const ADVERTISE_TIMEOUT_MS: i32 = 30_000;
// Verifier modules may do their own IO (chain reads, HTTP), so the budget
// is generous.
const AUTH_VERIFY_TIMEOUT_MS: i32 = 30_000;
const DEFAULT_MAX_RATE: u64 = 100;
const MAX_RPC_SIZE: u64 = 4096;

#[derive(Clone, Debug)]
struct RegistryCfg {
    max_rate_limit: u64,
}

#[derive(Clone)]
struct ServerCfg {
    /// The registry a request naming none is served on.
    default_config: String,
    /// Every served registry (ConfigState account, lowercase) with its own
    /// rate cap; the default one included.
    registries: HashMap<String, RegistryCfg>,
    wallet: String,
    /// Vector verifiers: authentication_type → (module, opaque per-vector
    /// config). Every vector — the reference keycard/eth modules included —
    /// is a plugin implementing the rln_auth_vector verifier contract; this
    /// module ships none of its own, so a new allocation-auth strategy needs
    /// zero changes here. Empty map = open allocator (auth skipped entirely).
    auth_verifiers: HashMap<String, (String, Option<Value>)>,
    nullifiers_path: String,
}

impl ServerCfg {
    /// The registry a request asks for (its field 100, else the default) and
    /// that registry's rate cap; `Err` names a registry this allocator does not
    /// serve.
    fn resolve_registry(&self, requested: Option<&str>) -> Result<(String, u64), String> {
        let registry = match requested.map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => canonical_account(r).map_err(|e| format!("registry: {e}"))?,
            None => self.default_config.clone(),
        };
        match self.registries.get(&registry) {
            Some(r) => Ok((registry, r.max_rate_limit)),
            None => Err(format!("registry not served: {registry}")),
        }
    }
}

/// `serve`'s registries: the default `config` plus each `registries` entry
/// (`"<config>"` with the global cap, or `{"config", "maxRateLimit"?}`), as
/// canonical accounts, in order; a repeated one is an operator mistake.
fn parse_registries(a: &Value, default_config: &str, global_cap: u64) -> Result<(HashMap<String, RegistryCfg>, Vec<String>), String> {
    let mut map = HashMap::new();
    let mut order = Vec::new();
    let mut add = |config: &str, cap: u64| -> Result<(), String> {
        let key = canonical_account(config).map_err(|e| format!("registries: {e}"))?;
        if map.insert(key.clone(), RegistryCfg { max_rate_limit: cap }).is_some() {
            return Err(format!("registries: {key} is listed twice"));
        }
        order.push(key);
        Ok(())
    };
    add(default_config, global_cap)?;
    match a.get("registries") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(s) => add(s, global_cap)?,
                    Value::Object(o) => {
                        let config = o.get("config").and_then(Value::as_str).ok_or("registries: an object entry needs a config")?;
                        let cap = match o.get("maxRateLimit") {
                            None | Some(Value::Null) => global_cap,
                            Some(v) => v.as_u64().ok_or("registries: maxRateLimit must be an unsigned integer")?,
                        };
                        add(config, cap)?;
                    }
                    _ => return Err(r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#.into()),
                }
            }
        }
        Some(_) => return Err(r#"registries must be an array of "<config>" | {config, maxRateLimit?}"#.into()),
    }
    Ok((map, order))
}

static SERVER: Mutex<Option<ServerCfg>> = Mutex::new(None);
static CONSUMED_NULLIFIERS: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static MOUNTED: AtomicBool = AtomicBool::new(false);
/// Whether the serve worker runs; from then on only it may call libp2p_module.
static SERVING: AtomicBool = AtomicBool::new(false);
/// The service data this node should advertise (None = nothing), and what it
/// currently advertises.
static WANTED_AD: Mutex<Option<String>> = Mutex::new(None);
static ADVERTISED: Mutex<Option<String>> = Mutex::new(None);

fn blob(v: Value) -> Value {
    // Single JSON-blob arg wrapped in a positional args array, as the
    // JSON-blob methods on libp2p_module expect.
    json!([v.to_string()])
}

/// The (registry, auth type) pairs a configuration serves, in the order
/// `serve` lists its registries; an open allocator serves the empty type.
fn served_pairs(served: &[String], auth_verifiers: &HashMap<String, (String, Option<Value>)>) -> Vec<(String, String)> {
    let mut types: Vec<&str> = auth_verifiers.keys().map(String::as_str).collect();
    types.sort_unstable();
    if types.is_empty() {
        types.push("");
    }
    served
        .iter()
        .flat_map(|r| types.iter().map(move |t| (r.clone(), t.to_string())))
        .collect()
}

/// Bring the advertisement in line with `WANTED_AD`: the one service id,
/// the served pairs in its data. A changed data stops the previous
/// advertisement first (libp2p refuses to replace one in place); unchanged
/// data is left alone. Called where libp2p_module can answer: by `serve`
/// before the worker exists, by the worker between accepts afterwards.
fn reconcile_advertisement() -> Result<(), String> {
    let wanted = lock(&WANTED_AD).clone();
    let mut current = lock(&ADVERTISED);
    if *current == wanted {
        return Ok(());
    }
    if current.is_some() {
        lp::call_libp2p("discoStopAdvertising", &json!([RLN_GIFTER_SERVICE_ID]), ADVERTISE_TIMEOUT_MS)
            .map_err(|e| format!("discoStopAdvertising: {e}"))?;
        *current = None;
    }
    if let Some(data) = wanted {
        lp::call_libp2p(
            "discoStartAdvertising",
            &json!([RLN_GIFTER_SERVICE_ID, data.as_str(), ""]),
            ADVERTISE_TIMEOUT_MS,
        )
        .map_err(|e| format!("discoStartAdvertising: {e}"))?;
        *current = Some(data);
    }
    Ok(())
}

/// Server entry point (the trait's `serve`): args
/// `{config, wallet, registries?, authVerifiers?, consumedNullifiersPath?,
///  maxRateLimit?, advertise?}`.
/// `config` is the registry a request naming none is served on; `registries`
/// adds further served ones (`"<config>"`, or `{"config", "maxRateLimit"?}`
/// for a cap of its own) — a request names its registry on the wire and one
/// this allocator does not serve is refused before any verifier runs.
/// `authVerifiers` maps each accepted authentication_type to its verifier
/// module — `{"<type>": {"module": "<logos module>", "config"?: {…}}}` —
/// an rln_auth_vector VERIFY_METHOD implementor, called per request with the
/// operator's opaque `config` riding along and the requester's transport peer
/// id. A verdict nullifier gets shared reserve/rollback/persist replay
/// protection, scoped per registry. No authVerifiers = an OPEN allocator (every
/// request registers).
/// `advertise` (default true) publishes the served (registry, auth type)
/// pairs through libp2p service discovery under `RLN_GIFTER_SERVICE_ID` so
/// clients find this allocator without a configured peer id; the node must
/// have discovery mounted (`mountServiceDiscovery`) and a registrar peer in
/// its routing table. Left to its default, a node without discovery serves
/// unadvertised and the reply says why; an explicit `true` makes that an
/// error. At most 8 pairs fit an advertisement. While the worker serves,
/// libp2p_module answers only it, so a re-serve that changes the
/// advertisement hands the change to the worker (`advertisePending`).
/// Mounts the protocol and starts the serialized serve worker. Returns
/// `{mounted:true, registries:[…], advertised:bool, advertisePending?,
///  serviceId?, serviceData?, advertiseError?}`.
pub fn serve(args_json: &str) -> Result<Value, String> {
    let a: Value = serde_json::from_str(args_json).map_err(|e| format!("serve args: {e}"))?;
    let config = a.get("config").and_then(Value::as_str).ok_or("missing config")?.to_string();
    let wallet = a.get("wallet").and_then(Value::as_str).ok_or("missing wallet")?.to_string();
    let max_rate_limit = a.get("maxRateLimit").and_then(Value::as_u64).unwrap_or(DEFAULT_MAX_RATE);
    let nullifiers_path =
        a.get("consumedNullifiersPath").and_then(Value::as_str).unwrap_or("").to_string();
    let advertise_wanted = match a.get("advertise") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err("advertise must be a boolean".into()),
    };
    let (registries, served) = parse_registries(&a, &config, max_rate_limit)?;
    let default_config = served[0].clone();

    // A present-but-malformed authVerifiers must fail serve, never silently
    // degrade to an open allocator.
    let mut auth_verifiers: HashMap<String, (String, Option<Value>)> = HashMap::new();
    match a.get("authVerifiers") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (atype, v) in map {
                let module = v.get("module").and_then(Value::as_str).unwrap_or("");
                if module.is_empty() {
                    return Err(format!("authVerifiers['{atype}'] needs a module"));
                }
                // Open the verifier's lp client HERE, on the owner thread —
                // the serve worker cannot create clients, only use them.
                lp::ensure_client(module).map_err(|e| format!("authVerifiers['{atype}']: {e}"))?;
                auth_verifiers
                    .insert(atype.clone(), (module.to_string(), v.get("config").cloned()));
            }
        }
        Some(_) => return Err("authVerifiers must be an object of {type: {module, config?}}".into()),
    }

    // Refused before anything is configured: an allocator that cannot say
    // what it serves must not serve it half-advertised.
    let data = match advertise_wanted {
        Some(false) => None,
        _ => Some(service_data(&served_pairs(&served, &auth_verifiers))?),
    };

    // Merge, never replace: a re-serve (config refresh) may only ADD replay
    // knowledge, or in-memory reservations would be forgotten. A re-serve
    // that names another file carries the spent set into it, or a restart
    // on the new file would forget everything spent under the old one.
    {
        let mut g = lock(&CONSUMED_NULLIFIERS);
        let set = g.get_or_insert_with(HashSet::new);
        set.extend(auth::load_nullifiers(&nullifiers_path).map_err(|e| format!("nullifier store: {e}"))?);
        let previous_path = lock(&SERVER).as_ref().map(|c| c.nullifiers_path.clone());
        if previous_path.is_some_and(|p| p != nullifiers_path) {
            auth::append_missing(&nullifiers_path, set).map_err(|e| format!("nullifier store: {e}"))?;
        }
    }
    *lock(&SERVER) = Some(ServerCfg {
        default_config,
        registries,
        wallet,
        auth_verifiers,
        nullifiers_path,
    });

    let mut reply = json!({ "mounted": true, "registries": served, "advertised": false });
    if let Some(data) = &data {
        reply["serviceId"] = json!(RLN_GIFTER_SERVICE_ID);
        reply["serviceData"] = json!(data);
    }
    *lock(&WANTED_AD) = data.clone();
    if SERVING.load(Ordering::SeqCst) {
        // The worker owns libp2p_module: it reconciles between accepts.
        if *lock(&ADVERTISED) == data {
            reply["advertised"] = json!(data.is_some());
        } else {
            reply["advertisePending"] = json!(true);
        }
        return Ok(reply);
    }
    // The advertisement BEFORE the mount: a serve an explicit advertise:true
    // fails must leave nothing mounted — a mounted protocol nobody accepts on
    // makes clients wait out their whole budget. The moments between the two
    // calls cost a client at most a refused dial, which it treats as "try the
    // next allocator".
    match reconcile_advertisement() {
        Ok(()) => reply["advertised"] = json!(data.is_some()),
        Err(e) if advertise_wanted == Some(true) => return Err(format!("advertise: {e}")),
        Err(e) => reply["advertiseError"] = json!(e),
    }
    // Mount exactly once; re-calling serve just refreshes the config above
    // (e.g. a new wallet or verifier set) and the advertisement.
    if !MOUNTED.swap(true, Ordering::SeqCst) {
        if let Err(e) = lp::call_libp2p("mountProtocol", &json!([RLN_GIFTER_CODEC]), MOUNT_TIMEOUT_MS) {
            MOUNTED.store(false, Ordering::SeqCst);
            return Err(format!("mountProtocol: {e}"));
        }
    }
    // Spawn the serialized worker exactly once, after the advertisement and
    // the mount: from here on libp2p_module answers only it.
    if !SERVING.swap(true, Ordering::SeqCst) {
        std::thread::spawn(worker_loop);
    }
    Ok(reply)
}

// One serialized worker: accept → read → auth → register → respond, one request
// at a time. Serializing register_member keeps the funded wallet nonce ordered.
// Between accepts it applies the advertisement a re-serve asked for.
fn worker_loop() {
    loop {
        if let Err(e) = reconcile_advertisement() {
            eprintln!("rln_gifter serve: advertisement: {e}");
        }
        // call_libp2p unwraps the StdLogosResult envelope {success,error,value}
        // and returns the inner value ({streamId, proto, peerId}; peerId since
        // libp2p_module 1.1.0 — the requester as the secure channel proved it).
        let accept = lp::call_libp2p(
            "protocolAcceptStream",
            &blob(json!({ "proto": RLN_GIFTER_CODEC, "timeoutMs": ACCEPT_TIMEOUT_MS })),
            ACCEPT_TIMEOUT_MS + ACCEPT_CALL_MARGIN_MS,
        );
        let stream_id = match &accept {
            Ok(v) => v.get("streamId").and_then(Value::as_u64),
            Err(e) if e.contains(ACCEPT_IDLE) => continue,
            Err(_) => None, // transient — poll again
        };
        let Some(stream_id) = stream_id else {
            eprintln!("rln_gifter serve: accept had no streamId: {accept:?}");
            continue;
        };
        let peer_id = accept
            .as_ref()
            .ok()
            .and_then(|v| v.get("peerId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Err(e) = handle_stream(stream_id, peer_id.as_deref()) {
            eprintln!("rln_gifter serve: stream {stream_id}: {e}");
        }
    }
}

fn handle_stream(stream_id: u64, peer_id: Option<&str>) -> Result<(), String> {
    let release = || {
        let _ = lp::call_libp2p("streamReleaseJson", &blob(json!({ "streamId": stream_id })), 10_000);
    };
    // A request that cannot be read still holds a server stream: release it,
    // or every such failure leaks one.
    let req_bytes = (|| -> Result<Vec<u8>, String> {
        let read = lp::call_libp2p(
            "streamReadLpJson",
            &blob(json!({ "streamId": stream_id, "maxSize": MAX_RPC_SIZE, "timeoutMs": READ_TIMEOUT_MS })),
            READ_TIMEOUT_MS + 10_000,
        )?;
        let data_b64 = read.get("dataB64").and_then(Value::as_str).ok_or("streamReadLpJson: no dataB64")?;
        b64_decode(data_b64)
    })()
    .inspect_err(|_| release())?;

    let resp = handle_request(&req_bytes, peer_id);

    // Write the response, then release the server stream. Never send EOF/close
    // from the server side (yamux cleanup races in the FFI host); the client
    // released its side after reading.
    let _ = lp::call_libp2p(
        "streamWriteLpJson",
        &blob(json!({ "streamId": stream_id, "dataB64": b64(&resp.encode()) })),
        WRITE_TIMEOUT_MS + 10_000,
    );
    let _ = lp::call_libp2p(
        "streamReleaseJson",
        &blob(json!({ "streamId": stream_id })),
        10_000,
    );
    Ok(())
}

fn failure_response(request_id: &str, auth_success: bool, message: &str) -> RlnGifterResponse {
    RlnGifterResponse {
        request_id: request_id.to_string(),
        auth_success,
        error: Some(message.to_string()),
        success: None,
        failure: Some(MembershipAllocationFailure { error_message: message.to_string() }),
    }
}

// Handle one decoded request: resolve its registry, authenticate through the
// configured vector's verifier module, register on-chain, and roll back the
// nullifier reservation if registration fails. `peer_id` is the requester as
// the transport authenticated it, for vectors that judge the peer.
fn handle_request(buf: &[u8], peer_id: Option<&str>) -> RlnGifterResponse {
    let req: RlnGifterRequest = match RlnGifterRequest::decode(buf) {
        Ok(r) => r,
        Err(e) => return failure_response("N/A", false, &format!("decode error: {e}")),
    };

    // Length AND field membership: a non-canonical commitment must never
    // reach a verifier (which would spend a nullifier reservation) or the
    // lez module (a non-canonical commitment panics the guest and the fee is
    // charged).
    if let Some(why) = crate::wire::commitment_refusal(&req.identity_commitment) {
        return failure_response(&req.request_id, true, &RegisterError::NotSubmitted(why.to_string()).message());
    }

    let Some(cfg) = lock(&SERVER).clone() else {
        return failure_response(
            &req.request_id,
            true,
            &RegisterError::NotSubmitted("gifter not configured".to_string()).message(),
        );
    };

    // The registry first: a request for one this allocator does not serve costs
    // no verifier round-trip and no nullifier reservation.
    let (registry, max_rate_limit) = match cfg.resolve_registry(req.config_account_id.as_deref()) {
        Ok(r) => r,
        Err(why) => return failure_response(&req.request_id, false, &why),
    };

    let auth_type = String::from_utf8_lossy(&req.authentication_type).to_string();
    let mut authorized_nullifier: Option<String> = None;

    // The effective rate is settled BEFORE verification so the verifier
    // judges the number that will actually be registered. The registry's cap
    // applies to every request, whatever the vector's replay choices.
    let mut rate = req.rate_limit.unwrap_or(DEFAULT_MAX_RATE);
    if rate > max_rate_limit {
        rate = max_rate_limit;
    }

    if !cfg.auth_verifiers.is_empty() {
        // Delegate the decision to the vector's verifier module (an
        // rln_auth_vector VERIFY_METHOD implementor). The operator's opaque
        // per-vector config rides along on every call, so verifiers stay
        // stateless. Payload plausibility is the verifier's business — this
        // module carries bytes, it doesn't judge them.
        let Some((module, verifier_config)) = cfg.auth_verifiers.get(&auth_type) else {
            return failure_response(
                &req.request_id,
                false,
                &format!("unsupported authentication_type: '{auth_type}'"),
            );
        };
        let verify_req = VerifyRequest {
            auth_type: auth_type.clone(),
            payload_hex: hex::encode(&req.authentication_payload),
            id_commitment_hex: hex::encode(&req.identity_commitment),
            rate,
            config: verifier_config.clone(),
            peer_id: peer_id.map(str::to_owned),
        };
        let verify_json = match serde_json::to_string(&verify_req) {
            Ok(s) => s,
            Err(e) => return failure_response(&req.request_id, false, &format!("verify request: {e}")),
        };
        let reply = match lp::call_module_json(
            module,
            rln_auth_vector::VERIFY_METHOD,
            &json!([verify_json]),
            AUTH_VERIFY_TIMEOUT_MS,
        ) {
            Ok(r) => r,
            Err(e) => {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: {e}"),
                )
            }
        };
        let verdict = match rln_auth_vector::parse_verdict(&reply) {
            Ok(v) => v,
            Err(e) => {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: {e}"),
                )
            }
        };
        if !verdict.ok {
            let reason = verdict.reason.as_deref().unwrap_or("verifier rejected the request");
            return failure_response(&req.request_id, false, reason);
        }
        // A verdict nullifier opts in to the shared replay protection:
        // reserve BEFORE the register await so a concurrent request spending
        // the same credential can't also pass, and persist the reservation at
        // once so a restart during the confirmation wait cannot grant it a
        // second membership; a registration nothing on chain saw takes the
        // reservation back. Normalized once at this trust boundary (the load
        // path lowercases too, so restart survives any plugin's casing) and
        // namespaced by registry and vector: a credential buys one membership
        // per registry, and no vector can spend or squat another vector's
        // credentials in the shared store.
        if let Some(nul) = verdict.nullifier {
            let nul = nul.trim().to_lowercase();
            if nul.is_empty() || nul.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("auth verifier {module}: malformed nullifier"),
                );
            }
            let nul = rln_auth_vector::namespaced_nullifier(&registry, &auth_type, &nul);
            let spent = lock(&CONSUMED_NULLIFIERS)
                .as_ref()
                .is_some_and(|set| set.contains(&nul));
            if spent {
                // The credential bought a membership already. If it bought
                // THIS commitment's — a retry after a reply the client never
                // read — the answer is that membership, and nothing new is
                // spent; any other commitment is a replay.
                if let Some(success) = registered_membership(&registry, &req.identity_commitment) {
                    return RlnGifterResponse {
                        request_id: req.request_id,
                        auth_success: true,
                        error: None,
                        success: Some(success),
                        failure: None,
                    };
                }
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("credential already used: {nul}"),
                );
            }
            let mut g = lock(&CONSUMED_NULLIFIERS);
            let set = g.get_or_insert_with(HashSet::new);
            if !set.insert(nul.clone()) {
                return failure_response(
                    &req.request_id,
                    false,
                    &format!("credential already used: {nul}"),
                );
            }
            // A reservation that never reached disk does not survive a
            // restart, so nothing is registered against it.
            if let Err(e) = auth::append_nullifier(&cfg.nullifiers_path, &nul) {
                set.remove(&nul);
                return failure_response(
                    &req.request_id,
                    true,
                    &RegisterError::NotSubmitted(format!("nullifier store: {e}")).message(),
                );
            }
            authorized_nullifier = Some(nul);
        }
    }

    match register(&cfg, &registry, &req.identity_commitment, rate) {
        Ok(success) => {
            RlnGifterResponse {
                request_id: req.request_id,
                auth_success: true,
                error: None,
                success: Some(success),
                failure: None,
            }
        }
        Err(e) => {
            let mut store_note = String::new();
            if let Some(nul) = &authorized_nullifier {
                match e {
                    // Nothing reached the chain: the credential is unspent.
                    RegisterError::NotSubmitted(_) => {
                        if let Some(set) = lock(&CONSUMED_NULLIFIERS).as_mut() {
                            set.remove(nul);
                        }
                        // The release stays in memory either way; a store
                        // that kept the line keeps the credential spent
                        // across a restart, and the reply says so.
                        if let Err(store) = auth::remove_nullifier(&cfg.nullifiers_path, nul) {
                            store_note = format!("; nullifier store: {store}");
                        }
                    }
                    // The registration may still land: the reservation stays,
                    // in memory and on disk.
                    RegisterError::Unconfirmed(_) => {}
                }
            }
            RlnGifterResponse {
                request_id: req.request_id,
                auth_success: true,
                error: None,
                success: None,
                failure: Some(MembershipAllocationFailure {
                    error_message: format!("{}{store_note}", e.message()),
                }),
            }
        }
    }
}

/// Why a gift was not delivered: before anything was submitted, or after a
/// submission the registry did not confirm in time.
enum RegisterError {
    NotSubmitted(String),
    Unconfirmed(String),
}

impl RegisterError {
    fn message(self) -> String {
        match self {
            RegisterError::NotSubmitted(m) => format!("{}{m}", crate::wire::NOT_SUBMITTED_PREFIX),
            RegisterError::Unconfirmed(m) => format!("{}{m}", crate::wire::UNCONFIRMED_PREFIX),
        }
    }
}

/// The usable membership the registry holds for a commitment, as a grant,
/// or None when there is none (not registered, expired, or unreadable).
fn registered_membership(registry: &str, id_commitment: &[u8]) -> Option<MembershipAllocationSuccess> {
    let m = lp::call_module_json(
        lp::LEZ_RLN_MODULE,
        "get_membership",
        &json!([registry, hex::encode(id_commitment)]),
        GET_MEMBERSHIP_TIMEOUT_MS,
    )
    .ok()?;
    Some(MembershipAllocationSuccess {
        leaf_index: confirmed_leaf(&m)?,
        merkle_root: Vec::new(),
        block_number: 0,
        transaction_hash: Vec::new(),
        config_account_id: Some(registry.to_string()),
    })
}

/// The registry module's refusal to submit, `{"error":"<kind>: <reason>"}`.
fn refusal(reply: &Value) -> Option<&str> {
    reply.get("error").and_then(Value::as_str)
}

/// The leaf of a membership the registry shows as usable, from a
/// `get_membership` reply `{"registered":true,"state":…,"leaf_index":N,…}`;
/// None while it is not registered, or registered but expired: a grant of an
/// expired leaf would spend the credential on a membership no proof can use.
fn confirmed_leaf(reply: &Value) -> Option<u64> {
    if reply.get("registered").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    match reply.get("state").and_then(Value::as_str) {
        Some("active") | Some("grace_period") => {}
        _ => return None,
    }
    reply.get("leaf_index").and_then(Value::as_u64)
}

// Delegate the on-chain registration to liblogos_lez_rln_module, paid by the
// account `serve` was given as `wallet`, then wait until the registry shows
// the membership. register_member answers when the transaction is accepted:
// its leaf_index is only a pre-submit estimate (the tree assigns the leaf), and
// a registration whose claims went stale is re-sent by that module under a new
// transaction. So the leaf reported to the client is read back from the chain.
// Runs on the serialized worker thread -> lp_invoke_async.
fn register(cfg: &ServerCfg, registry: &str, id_commitment: &[u8], rate: u64) -> Result<MembershipAllocationSuccess, RegisterError> {
    let idc_hex = hex::encode(id_commitment);
    let reply = lp::call_module_json(
        lp::LEZ_RLN_MODULE,
        "register_member",
        &json!([registry, cfg.wallet, idc_hex, rate]),
        REGISTER_TIMEOUT_MS,
    )
    .map_err(RegisterError::NotSubmitted)?;
    // liblogos_lez_rln_module answers {"error":…} for a registration its
    // program would reject (a commitment that is not a field element, a full
    // registry, a payer that cannot pay) and for a send the sequencer did not
    // accept: nothing will land.
    if let Some(why) = refusal(&reply) {
        return Err(RegisterError::NotSubmitted(format!("register_member refused: {why}")));
    }
    // A commitment already on this registry: the registry module submits
    // nothing and reports the leaf. A usable membership is the grant; an
    // expired one is a refusal, and the credential stays unspent.
    if reply.get("already_registered").and_then(Value::as_bool) == Some(true) {
        let m = lp::call_module_json(
            lp::LEZ_RLN_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        )
        .map_err(RegisterError::NotSubmitted)?;
        return match confirmed_leaf(&m) {
            Some(leaf_index) => Ok(MembershipAllocationSuccess {
                leaf_index,
                merkle_root: Vec::new(),
                block_number: 0,
                transaction_hash: Vec::new(),
                config_account_id: Some(registry.to_string()),
            }),
            None => Err(RegisterError::NotSubmitted(format!(
                "commitment already registered on {registry} with a membership in state {}",
                m.get("state").and_then(Value::as_str).unwrap_or("unknown")
            ))),
        };
    }

    // tx_result is a JSON STRING nesting {tx_hash,...}: the submitted
    // transaction. Absent for an already-registered PDA.
    let mut tx_hash_bytes = Vec::new();
    if let Some(tx_result) = reply.get("tx_result").and_then(Value::as_str) {
        if let Ok(inner) = serde_json::from_str::<Value>(tx_result) {
            if let Some(txh) = inner.get("tx_hash").and_then(Value::as_str) {
                tx_hash_bytes = hex::decode(txh.trim_start_matches("0x")).unwrap_or_default();
            }
        }
    }

    let deadline = std::time::Instant::now() + CONFIRM_BUDGET;
    loop {
        if let Ok(m) = lp::call_module_json(
            lp::LEZ_RLN_MODULE,
            "get_membership",
            &json!([registry, idc_hex]),
            GET_MEMBERSHIP_TIMEOUT_MS,
        ) {
            if let Some(leaf_index) = confirmed_leaf(&m) {
                return Ok(MembershipAllocationSuccess {
                    leaf_index,
                    merkle_root: Vec::new(),
                    block_number: 0,
                    transaction_hash: tx_hash_bytes,
                    config_account_id: Some(registry.to_string()),
                });
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(RegisterError::Unconfirmed(format!(
                "registration submitted (tx {}) but not on chain within {}s; it may still land",
                hex::encode(&tx_hash_bytes),
                CONFIRM_BUDGET.as_secs()
            )));
        }
        std::thread::sleep(CONFIRM_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn served(a: Value) -> ServerCfg {
        let (registries, served) = parse_registries(&a, &acct(0xd).to_uppercase(), 100).unwrap();
        ServerCfg {
            default_config: served[0].clone(),
            registries,
            wallet: String::new(),
            auth_verifiers: HashMap::new(),
            nullifiers_path: String::new(),
        }
    }

    #[test]
    fn registries_are_the_default_plus_each_entry_with_its_own_cap() {
        let (d, m, x) = (acct(0xd), acct(0xab), acct(0xb));
        // The mix account in base58 (32 bytes of 0xab).
        let m_b58 = "CZ8YUVdk7znjrUmnb5n7kgySk9yRAsQDYmyCxzfSky9t";
        let cfg = served(json!({ "registries": [m_b58, { "config": x, "maxRateLimit": 20 }] }));
        assert_eq!(cfg.resolve_registry(None).unwrap(), (d.clone(), 100));
        assert_eq!(cfg.resolve_registry(Some(&format!(" {} ", m.to_uppercase()))).unwrap(), (m.clone(), 100));
        assert_eq!(cfg.resolve_registry(Some(m_b58)).unwrap(), (m.clone(), 100));
        assert_eq!(cfg.resolve_registry(Some(&x)).unwrap(), (x.clone(), 20));
        assert_eq!(cfg.resolve_registry(Some("")).unwrap().0, d);
        let y = acct(0xc);
        assert_eq!(cfg.resolve_registry(Some(&y)).unwrap_err(), format!("registry not served: {y}"));
        assert!(cfg.resolve_registry(Some("nope")).unwrap_err().starts_with("registry: config account 'nope'"));
        let (_, order) = parse_registries(&json!({ "registries": [m_b58] }), &d, 1).unwrap();
        assert_eq!(order, [d.clone(), m]);
        let (_, order) = parse_registries(&json!({}), &d, 1).unwrap();
        assert_eq!(order, [d]);
    }

    #[test]
    fn the_served_pairs_are_every_registry_with_every_verifier_type() {
        let (d, m) = (acct(0xd), acct(0xa));
        let mut verifiers = HashMap::new();
        verifiers.insert("peer-any".to_string(), ("rln_auth_module".to_string(), None));
        verifiers.insert("eth-allowlist".to_string(), ("rln_auth_module".to_string(), None));
        let pairs = served_pairs(&[d.clone(), m.clone()], &verifiers);
        assert_eq!(
            pairs,
            [
                (d.clone(), "eth-allowlist".to_string()),
                (d.clone(), "peer-any".to_string()),
                (m.clone(), "eth-allowlist".to_string()),
                (m.clone(), "peer-any".to_string()),
            ]
        );
        // An open allocator serves the empty type on each registry.
        assert_eq!(served_pairs(&[d.clone()], &HashMap::new()), [(d, String::new())]);
    }

    #[test]
    fn serve_refuses_more_pairs_than_an_advertisement_carries() {
        let regs: Vec<String> = (1..=9u8).map(|i| acct(i)).collect();
        let a = format!(
            r#"{{"config":"{}","wallet":"w","registries":{}}}"#,
            regs[0],
            serde_json::to_string(&regs[1..]).unwrap()
        );
        let e = serve(&a).unwrap_err();
        assert!(e.contains("at most 8"), "got: {e}");
    }

    #[test]
    fn serve_rejects_a_non_boolean_advertise() {
        let e = serve(&format!(r#"{{"config":"{}","wallet":"w","advertise":"yes"}}"#, acct(1))).unwrap_err();
        assert!(e.contains("advertise must be a boolean"), "got: {e}");
    }

    #[test]
    fn malformed_registries_fail_serve() {
        let (d, m) = (acct(0xd), acct(0xa));
        for (a, needle) in [
            (json!({ "registries": [d.to_uppercase()] }), "listed twice"),
            (json!({ "registries": [{ "maxRateLimit": 5 }] }), "needs a config"),
            (json!({ "registries": [{ "config": m, "maxRateLimit": "5" }] }), "unsigned integer"),
            (json!({ "registries": [7] }), "must be an array"),
            (json!({ "registries": m }), "must be an array"),
            (json!({ "registries": [" "] }), "config account ''"),
        ] {
            let e = parse_registries(&a, &d, 1).unwrap_err();
            assert!(e.contains(needle), "{a}: {e}");
        }
        assert!(parse_registries(&json!({}), "D", 1).unwrap_err().contains("config account 'D'"));
    }

    #[test]
    fn an_unserved_registry_is_refused_before_anything_else() {
        *lock(&SERVER) = Some(served(json!({})));
        let mut idc = vec![0xab; 32];
        idc[31] = 0x0a;
        let req = RlnGifterRequest {
            request_id: "r".into(),
            identity_commitment: idc,
            config_account_id: Some(acct(0xe)),
            ..Default::default()
        };
        let resp = handle_request(&req.encode(), None);
        assert!(!resp.auth_success);
        assert_eq!(resp.error.as_deref(), Some(format!("registry not served: {}", acct(0xe)).as_str()));
        *lock(&SERVER) = None;
    }

    #[test]
    fn failure_messages_say_whether_anything_was_submitted() {
        assert_eq!(RegisterError::NotSubmitted("x".into()).message(), "not submitted: x");
        assert_eq!(RegisterError::Unconfirmed("y".into()).message(), "unconfirmed: y");
    }

    #[test]
    fn a_refused_registration_is_recognised() {
        let r = json!({"error": "invalid_commitment: not a BN254 field element"});
        assert_eq!(refusal(&r), Some("invalid_commitment: not a BN254 field element"));
        assert_eq!(refusal(&json!({"leaf_index": 3, "pending": true})), None);
    }

    #[test]
    fn only_a_usable_registered_membership_has_a_confirmed_leaf() {
        assert_eq!(confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "active"})), Some(7));
        assert_eq!(confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "grace_period"})), Some(7));
        assert_eq!(confirmed_leaf(&json!({"registered": true, "leaf_index": 7, "state": "expired"})), None);
        assert_eq!(confirmed_leaf(&json!({"registered": true, "leaf_index": 7})), None);
        assert_eq!(confirmed_leaf(&json!({"registered": false})), None);
        assert_eq!(confirmed_leaf(&json!({"registered": true})), None);
        assert_eq!(confirmed_leaf(&json!("")), None);
    }

    // Under the test FFI stub no lp client can open, which is exactly the
    // shape of a misconfigured verifier: serve must surface it, not defer it
    // to a per-request auth failure.
    #[test]
    fn serve_fails_loudly_when_a_verifier_client_cannot_open() {
        let e = serve(&format!(
            r#"{{"config":"{}","wallet":"w","authVerifiers":{{"t":{{"module":"nope_module"}}}}}}"#,
            acct(1)
        ))
        .unwrap_err();
        assert!(e.contains("authVerifiers['t']"), "got: {e}");
    }

    #[test]
    fn serve_rejects_malformed_auth_verifiers_instead_of_degrading_open() {
        let base = format!(r#""config":"{}","wallet":"w""#, acct(1));
        let e = serve(&format!(r#"{{{base},"authVerifiers":"oops"}}"#)).unwrap_err();
        assert!(e.contains("must be an object"), "got: {e}");
        let e = serve(&format!(r#"{{{base},"authVerifiers":{{"t":{{}}}}}}"#)).unwrap_err();
        assert!(e.contains("needs a module"), "got: {e}");
        let e = serve(r#"{"config":"c","wallet":"w"}"#).unwrap_err();
        assert!(e.contains("config account 'c'"), "got: {e}");
    }
}
