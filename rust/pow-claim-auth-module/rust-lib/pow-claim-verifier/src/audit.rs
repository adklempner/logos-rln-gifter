//! One record per decision: a stderr line (lands in the host's daemon.log) and,
//! if `audit_log` is configured (PoC), a JSON line appended to that file.

use std::io::Write as _;

use serde_json::json;

#[derive(Debug, Default, Clone)]
pub struct Record {
    pub node: String,
    pub nullifier: Option<String>,
    pub path: Option<&'static str>,
    pub lib_slot: Option<u64>,
}

pub fn record(
    audit_log: Option<&str>,
    rec: &Record,
    result: &Result<rln_auth_vector::Verdict, String>,
    ms: u128,
) {
    let (verdict, reason) = match result {
        Ok(v) if v.ok => ("accept", None),
        Ok(v) => ("reject", v.reason.clone()),
        Err(e) => ("error", Some(e.clone())),
    };
    let nul = rec.nullifier.as_deref().unwrap_or("-");
    let path = rec.path.unwrap_or("-");
    eprintln!(
        "pow_claim_auth: verdict={verdict} node={} nullifier={nul} path={path} reason={} ms={ms}",
        if rec.node.is_empty() { "-" } else { &rec.node },
        reason.as_deref().map(|r| format!("{r:?}")).unwrap_or_else(|| "-".into()),
    );
    let Some(p) = audit_log else { return };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = json!({
        "ts": ts as u64, "verdict": verdict, "node": rec.node, "nullifier": rec.nullifier,
        "path": rec.path, "reason": reason, "ms": ms as u64, "lib_slot": rec.lib_slot,
    });
    let r = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .and_then(|mut f| writeln!(f, "{line}"));
    if let Err(e) = r {
        eprintln!("pow_claim_auth: audit_log {p}: {e}");
    }
}
