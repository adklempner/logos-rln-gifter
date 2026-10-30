//! The RLN gifter `pow-claim` authoriser (`docs/auth-pow-claim.md` §3–§4):
//! a logos zkSign key `K` authorised by a settled PoW reward claim it owns on
//! the Logos blockchain.
//!
//! Produce side (feature `produce`, [`gather`]): find a `PoWRewardClaimed`
//! event whose minted note is owned by `K`, either directly (`note.pk == K`,
//! path A) or because a Transfer in the same tx spends `NoteId(utxo)` to `K`
//! (path B), and hand back the [`Claim`]. The claim's nullifier is bound into
//! the digest the logos scheme signs; the [`claim::Evidence`] travels in the
//! payload.
//!
//! Verify side (feature `verify`, [`verify::check`]): for a signature-checked
//! claim, the claim block final + canonical, the event, the ticket and op_id
//! recompute, and ownership of the minted note by `K`.
//!
//! Everything goes through the node's HTTP API ([`http::HttpNode`]); tests use
//! [`node::testing::FakeNode`].

pub mod args;
pub mod claim;
pub mod discover;
pub mod http;
pub mod node;
pub mod ownership;
#[cfg(feature = "produce")]
pub mod produce;
#[cfg(feature = "verify")]
pub mod verify;

pub use args::ProduceArgs;
pub use claim::{Claim, Evidence};
pub use discover::{discover, Found};
pub use http::HttpNode;
pub use node::NodeApi;
pub use ownership::{note_id_hex, owner, Path};
#[cfg(feature = "produce")]
pub use produce::gather;
