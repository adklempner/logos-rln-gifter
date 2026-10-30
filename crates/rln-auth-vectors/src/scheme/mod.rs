//! Schemes: how a binding digest gets signed, and which identity that proves.

pub mod eth;
pub mod keycard;
pub mod lez;
pub mod logos;

pub use eth::{Eth, EthAddress};
pub use keycard::{Keycard, KeycardIdentity};
pub use lez::{Lez, LezAccount};
pub use logos::{Logos, LogosKey};
