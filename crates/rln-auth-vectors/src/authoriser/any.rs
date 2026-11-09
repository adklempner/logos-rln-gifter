//! The `any` authoriser: every proven identity is accepted, and each buys
//! one membership (the default nullifier is the identity). Composes with
//! every scheme; what it is worth is what the scheme proves — with `peer`,
//! one membership per libp2p peer id per registry.

use std::any::Any as StdAny;

use rln_auth_vector::{
    parse_audience, Authoriser, Cfg, Check, Evidence, Identity, Outcome, Scheme,
};
use serde_json::Value;

pub const NAME: &str = "any";

struct Config {
    audience: String,
}

pub struct Any;

impl Authoriser for Any {
    fn name(&self) -> &'static str {
        NAME
    }
    fn accepts(&self, _scheme: &str) -> bool {
        true
    }
    /// `{"audience"?: ""}`; nothing else to configure.
    fn config(&self, _scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
        let audience = parse_audience(raw.and_then(|c| c.get("audience")), "config.audience")?;
        Ok(Box::new(Config { audience }))
    }
    fn audience<'a>(&self, cfg: &'a dyn StdAny) -> &'a str {
        cfg.downcast_ref::<Config>()
            .map(|c| c.audience.as_str())
            .unwrap_or("")
    }
    fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
        Outcome::Ok((Box::new(()), rest))
    }
    fn extra(&self, _ev: &dyn StdAny) -> Vec<u8> {
        Vec::new()
    }
    fn authorise(&self, _cfg: &dyn StdAny, _id: &dyn Identity, _ev: &dyn StdAny) -> Check<()> {
        Ok(Outcome::Ok(()))
    }
}
