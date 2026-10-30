//! The `allowlist` authoriser: the identity is on the operator's list.
//! Composes with every scheme; entries are written in the scheme's own form
//! and normalised through [`Scheme::parse_identity`]. No evidence; the
//! claim is judged before the signature (membership is cheap).

use std::any::Any;

use rln_auth_vector::{parse_audience, reason, Authoriser, Cfg, Check, Evidence, Identity, Outcome, Scheme};
use serde_json::Value;

pub const NAME: &str = "allowlist";

struct Config {
    list: Vec<String>,
    audience: String,
    noun: &'static str,
}

pub struct Allowlist;

impl Authoriser for Allowlist {
    fn name(&self) -> &'static str {
        NAME
    }
    fn accepts(&self, _scheme: &str) -> bool {
        true
    }
    /// `{"allowlist": [<identity>, …], "audience"?: ""}`; an empty list is an
    /// operator error, as is any entry the scheme cannot parse.
    fn config(&self, scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
        let entries = raw
            .and_then(|c| c.get("allowlist"))
            .and_then(Value::as_array)
            .ok_or_else(|| reason::allowlist_required(&format!("{} {}s", scheme.name(), scheme.identity_noun())))?;
        let list = entries
            .iter()
            .map(|e| e.as_str().ok_or_else(|| reason::ENTRIES_NOT_STRINGS.to_string()).and_then(|s| scheme.parse_identity(s)))
            .collect::<Result<Vec<_>, _>>()?;
        if list.is_empty() {
            return Err(reason::ALLOWLIST_EMPTY.into());
        }
        let audience = parse_audience(raw.and_then(|c| c.get("audience")), "config.audience")?;
        Ok(Box::new(Config { list, audience, noun: scheme.identity_noun() }))
    }
    fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str {
        cfg.downcast_ref::<Config>().map(|c| c.audience.as_str()).unwrap_or("")
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
        let cfg = cfg.downcast_ref::<Config>().ok_or("allowlist: config is not an allowlist")?;
        let who = id.canonical();
        if cfg.list.contains(&who) {
            Ok(Outcome::Ok(()))
        } else {
            Ok(Outcome::Reject(reason::not_allowlisted(cfg.noun, &who)))
        }
    }
}
