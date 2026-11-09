//! The produce half: find the claim `K` owns and turn it into the evidence
//! the payload carries (§4.2 steps 1–3). Signing is the logos scheme's job.

use crate::{
    args::{hex32_bytes, ProduceArgs},
    claim::{Claim, Evidence},
    discover::discover,
    node::NodeApi,
};

/// The redeemable claim for one of the node's keys, as a [`Claim`].
pub fn gather(node: &dyn NodeApi, args: &ProduceArgs) -> Result<Claim, String> {
    let found = discover(node, args)?;
    let spend = match (&args.spend_block_id, &args.spend_tx_hash) {
        (Some(b), Some(t)) => Some((
            hex32_bytes("spend_block_id", b)?,
            hex32_bytes("spend_tx_hash", t)?,
        )),
        (None, None) => None,
        _ => return Err("spend_block_id and spend_tx_hash must be given together".into()),
    };
    Ok(Claim {
        k: hex32_bytes("k", &found.k)?,
        evidence: Evidence {
            claim_block_id: hex32_bytes("claim_block_id", &found.block_id)?,
            pow_nullifier: hex32_bytes("pow_nullifier", &found.nullifier)?,
            spend,
        },
    })
}
