//! Verifier for the RLN gifter `pow-claim` authoriser.
//!
//! `verify_request` checks a payload produced by the `produce` half against
//! the verifier's OWN node: zkSign signature by `K` over the challenge
//! digest, then claim block final + canonical, the `PoWRewardClaimed` event,
//! ticket + op_id recompute, and ownership of the minted note by `K` (direct,
//! or spent to `K` in the claim tx).
//!
//! Operator problems (bad config, unreachable node) are `Err`; anything
//! derived from the payload or chain content is a reject verdict. The
//! modules are built with `panic = "abort"`: nothing here may panic on input.

pub mod audit;
pub mod chain;
pub mod config;
pub mod ticket;

use std::time::Instant;

use crate::{args::hex32_bytes, challenge, node::NodeApi, HttpNode, Payload};
pub use rln_auth_vector::{Verdict, VerifyRequest};
pub use zksign_light::{default_vk, verify_sig, PreparedVk};

pub use chain::{check_claim, spent_to_k, ClaimCheck};
pub use config::Config;
pub use ticket::puzzle_ticket;

pub const AUTH_TYPE: &str = "pow-claim";

/// Full verification over HTTP against `config.node_url`.
pub fn verify_request(req: &VerifyRequest) -> Result<Verdict, String> {
    let t0 = Instant::now();
    let cfg = match Config::parse(req.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            let r = Err(e);
            audit::record(None, &audit::Record::default(), &r, t0.elapsed().as_millis());
            return r;
        }
    };
    let vk = match zksign_light::vk_from_config(cfg.zksign_vk_path.as_deref().map(serde_json::Value::from).as_ref()) {
        Ok(v) => v,
        Err(e) => {
            let r = Err(e);
            let rec = audit::Record { node: cfg.node_url.clone(), ..Default::default() };
            audit::record(cfg.audit_log.as_deref(), &rec, &r, t0.elapsed().as_millis());
            return r;
        }
    };
    let node = HttpNode::new(&cfg.node_url, cfg.http_timeout_ms);
    verify_with(&[&node], req, &cfg, vk.get())
}

/// Verification against the given node(s) with a prepared VK; records the
/// decision (stderr + optional audit log).
pub fn verify_with(
    nodes: &[&dyn NodeApi],
    req: &VerifyRequest,
    cfg: &Config,
    vk: &PreparedVk,
) -> Result<Verdict, String> {
    let t0 = Instant::now();
    let mut rec = audit::Record { node: cfg.node_url.clone(), ..Default::default() };
    let r = verify_inner(nodes, req, cfg, vk, &mut rec);
    audit::record(cfg.audit_log.as_deref(), &rec, &r, t0.elapsed().as_millis());
    r
}

fn verify_inner(
    nodes: &[&dyn NodeApi],
    req: &VerifyRequest,
    cfg: &Config,
    vk: &PreparedVk,
    rec: &mut audit::Record,
) -> Result<Verdict, String> {
    let bytes = match hex::decode(rln_auth_vector::strip_0x(&req.payload_hex)) {
        Ok(b) => b,
        Err(e) => return Ok(Verdict::reject(format!("payload hex: {e}"))),
    };
    let p = match Payload::decode(&bytes) {
        Ok(p) => p,
        Err(e) => return Ok(Verdict::reject(format!("payload: {e}"))),
    };
    rec.nullifier = Some(hex::encode(p.pow_nullifier));
    let idc = match hex32_bytes("id_commitment_hex", &req.id_commitment_hex) {
        Ok(b) => b,
        Err(e) => return Ok(Verdict::reject(e)),
    };
    if req.rate > p.rate_max {
        return Ok(Verdict::reject(rln_auth_vector::reason::rate_exceeds(req.rate, p.rate_max)));
    }
    if p.spend.is_some() {
        return Ok(Verdict::reject(if cfg.allow_spend_locator {
            "spend locator unsupported in this PoC"
        } else {
            "spend locator disallowed by config"
        }));
    }
    // Audience length is capped at 255 B by Config::parse, so digest cannot panic.
    let digest = challenge::digest(&cfg.audience, &idc, p.rate_max, &p.pow_nullifier);
    if let Err(reason) = verify_sig(vk, &p.k, &digest, &p.zksig) {
        return Ok(Verdict::reject(reason));
    }
    let c = check_claim(nodes, &p, cfg)?;
    rec.lib_slot = c.lib_slot;
    match c.outcome {
        Ok(path) => {
            rec.path = Some(path.as_str());
            Ok(Verdict::accept(Some(hex::encode(p.pow_nullifier))))
        }
        Err(reason) => Ok(Verdict::reject(reason)),
    }
}
