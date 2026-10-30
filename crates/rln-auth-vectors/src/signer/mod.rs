//! Signers: the produce halves of the schemes.

pub mod eth;
#[cfg(feature = "keycard-pcsc")]
pub mod keycard;
pub mod lez;
pub mod logos;

use rln_auth_vector::{args_object, strip_0x};
use serde_json::Value;

pub use eth::EthSigner;
#[cfg(feature = "keycard-pcsc")]
pub use keycard::KeycardSigner;
pub use lez::{LezKey, LezSigner};
pub use logos::{LogosSigner, NodeArgs};

/// Where a file-key signer (eth, lez) gets its 32-byte private key for a
/// request: the module decides (its own persisted key, an imported one, …);
/// `args.private_key`, when present, wins.
pub trait KeySource: Send + Sync {
    fn key(&self, args: Option<&Value>) -> Result<[u8; 32], String>;
}

/// A fixed key (tests, one-shot tools).
pub struct StaticKey(pub [u8; 32]);

impl KeySource for StaticKey {
    fn key(&self, _args: Option<&Value>) -> Result<[u8; 32], String> {
        Ok(self.0)
    }
}

/// `args.private_key` as 32 bytes, if the request carries one.
pub fn private_key_arg(args: Option<&Value>) -> Result<Option<[u8; 32]>, String> {
    let Some(o) = args_object(args)? else { return Ok(None) };
    match o.get("private_key") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let bytes = hex::decode(strip_0x(s)).map_err(|e| format!("private key hex: {e}"))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|b: Vec<u8>| format!("private key must be 32 bytes, got {}", b.len()))?;
            Ok(Some(arr))
        }
        Some(v) => Err(format!("private_key: expected string, got {v}")),
    }
}
