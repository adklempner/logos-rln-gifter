//! Recomputation of the PoW claim op's derived values at rc.5
//! (`core/src/mantle/ops/pow.rs`, `ops/op.rs`).
//!
//! Op JSON (opcode 64): `{"epoch_nonce": hex LE Fr, "block_hash": [32 ints] | hex,
//! "public_key": hex LE Fr}`.

use ark_ff::{BigInteger as _, PrimeField as _};
use blake2::{digest::consts::U32, Blake2b, Digest as _};
use logos_blockchain_poseidon2::{Digest as _, Fr, Poseidon2Bn254Hasher};
use pow_claim_core::ownership::bytes32;
use serde_json::Value;

pub const OPCODE_CLAIM_POW_REWARD: u64 = 64;

pub struct ClaimOp {
    pub epoch_nonce: [u8; 32],
    pub block_hash: [u8; 32],
    pub public_key: [u8; 32],
}

impl ClaimOp {
    pub fn parse(op_payload: &Value) -> Result<ClaimOp, String> {
        Ok(ClaimOp {
            epoch_nonce: bytes32(&op_payload["epoch_nonce"], "op.epoch_nonce")?,
            block_hash: bytes32(&op_payload["block_hash"], "op.block_hash")?,
            public_key: bytes32(&op_payload["public_key"], "op.public_key")?,
        })
    }

    /// `ClaimPowRewardOp::get_puzzle_ticket`:
    /// `Poseidon2::digest([pk, fr_from_mod_bytes(block_hash), epoch_nonce])`,
    /// returned as 32-byte LE (the serde form of `PowNullifier`).
    pub fn puzzle_ticket(&self) -> [u8; 32] {
        let fr = Poseidon2Bn254Hasher::digest(&[
            Fr::from_le_bytes_mod_order(&self.public_key),
            Fr::from_le_bytes_mod_order(&self.block_hash),
            Fr::from_le_bytes_mod_order(&self.epoch_nonce),
        ]);
        let mut out = [0u8; 32];
        for (o, b) in out.iter_mut().zip(fr.into_bigint().to_bytes_le()) {
            *o = b;
        }
        out
    }

    /// `OpId::op_id`: `Blake2b-256("OPERATION_ID_V1" ‖ op_bytes)` with the
    /// canonical encoding `epoch_nonce ‖ block_hash ‖ public_key` (each 32 B LE).
    /// Matches the `op_id` the node reports in the real fixture's event.
    pub fn op_id(&self) -> [u8; 32] {
        let mut h = Blake2b::<U32>::new();
        h.update(b"OPERATION_ID_V1");
        h.update(self.epoch_nonce);
        h.update(self.block_hash);
        h.update(self.public_key);
        h.finalize().into()
    }
}

/// Puzzle ticket (= `PowNullifier`) of an opcode-64 op payload.
pub fn puzzle_ticket(op_payload: &Value) -> Result<[u8; 32], String> {
    Ok(ClaimOp::parse(op_payload)?.puzzle_ticket())
}

/// `op_id` of an opcode-64 op payload.
pub fn claim_op_id(op_payload: &Value) -> Result<[u8; 32], String> {
    Ok(ClaimOp::parse(op_payload)?.op_id())
}
