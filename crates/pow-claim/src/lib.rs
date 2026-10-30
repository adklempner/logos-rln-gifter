//! The RLN gifter `pow-claim` authoriser (`docs/auth-pow-claim.md` §3–§4):
//! a logos zkSign key `K` authorised by a settled PoW reward claim it owns on
//! the Logos blockchain.
//!
//! Produce side (feature `produce`): find a `PoWRewardClaimed` event whose
//! minted note is owned by `K`, either directly (`note.pk == K`, path A) or
//! because a Transfer in the same tx spends `NoteId(utxo)` to `K` (path B);
//! bind the claim's nullifier into the challenge digest; have the node zkSign
//! it with `K` (`POST /wallet/sign/zk`); encode the payload.
//!
//! Verify side (feature `verify`, [`verify`]): the zkSign by `K` over the
//! digest, then the claim block final + canonical, the event, the ticket and
//! op_id recompute, and ownership of the minted note by `K`.
//!
//! Everything goes through the node's HTTP API ([`http::HttpNode`]); tests use
//! [`node::testing::FakeNode`].

pub mod args;
pub mod challenge;
pub mod discover;
pub mod http;
pub mod node;
pub mod ownership;
pub mod payload;
#[cfg(feature = "produce")]
pub mod produce;
#[cfg(feature = "verify")]
pub mod verify;

pub use args::ProduceArgs;
pub use challenge::digest;
pub use discover::{discover, Found};
pub use http::HttpNode;
pub use node::NodeApi;
pub use ownership::{note_id_hex, owner, Path};
pub use payload::Payload;
#[cfg(feature = "produce")]
pub use produce::{produce, produce_http, Produced};
