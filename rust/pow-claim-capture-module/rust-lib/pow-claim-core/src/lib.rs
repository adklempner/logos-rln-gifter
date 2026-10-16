//! Producer logic for the RLN gifter `pow-claim` auth vector
//! (`docs/auth-pow-claim.md` §3–§4).
//!
//! The producer proves that the user's key `K` owns a settled PoW reward
//! claim on the local Logos blockchain node:
//!
//! 1. find a `PoWRewardClaimed` event whose minted note is owned by `K`,
//!    either directly (`note.pk == K`, path A) or because a Transfer in the
//!    same tx spends `NoteId(utxo)` to `K` (path B);
//! 2. compute the challenge digest
//!    `Blake2b-256("logos:rln:gifter:pow-claim:v1\0" ‖ u8 len ‖ audience ‖ idc ‖ rate_max LE ‖ nullifier)`;
//! 3. have the node zkSign it with `K` (`POST /wallet/sign/zk`);
//! 4. encode the 234/298-byte payload (§3.3).
//!
//! Everything goes through the node's HTTP API ([`http::HttpNode`]); tests
//! use [`node::testing::FakeNode`].

pub mod args;
pub mod challenge;
pub mod discover;
pub mod http;
pub mod node;
pub mod ownership;
pub mod payload;
pub mod produce;

pub use args::ProduceArgs;
pub use challenge::digest;
pub use discover::{discover, Found};
pub use http::HttpNode;
pub use node::NodeApi;
pub use ownership::{note_id_hex, owner, Path};
pub use payload::Payload;
pub use produce::{produce, produce_http, Produced};
