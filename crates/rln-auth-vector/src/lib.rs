//! Contract kit for RLN gifter auth vectors.
//!
//! An auth vector authorises a gifted membership allocation. Every vector is
//! the same pipeline over different pieces: the producer binds the identity
//! commitment, the asked `rate_max` and the gifter's `audience` (plus any
//! evidence the authoriser needs) into one digest, signs it, and frames a
//! payload; the verifier decodes the payload, rebuilds the digest, checks the
//! signature, authorises the signer and emits a nullifier.
//!
//! A vector is a composition, not a name: `<scheme>-<authoriser>`
//! ([`AuthType`]). A [`Scheme`] is how a digest gets signed and which identity
//! that proves (an eth address, a LEZ account, a logos zkSign key, a keycard);
//! an [`Authoriser`] is how an identity gets accepted (an allowlist, a trusted
//! CA, a claim on chain) and what evidence it binds. Modules compose the
//! pieces they ship into a [`VerifyRegistry`] / [`ProduceRegistry`]; the
//! registries answer every `auth_type` whose two halves exist and are
//! compatible ([`Authoriser::accepts`]).
//!
//! The two module methods ([`PRODUCE_METHOD`] / [`VERIFY_METHOD`]) take ONE
//! JSON-string argument and return a JSON string; the serde types in
//! [`types`] are the normative shapes. Success and refusal both travel as
//! data (`{"payload_hex"}` / [`Verdict`]); the `{"error": "..."}` envelope is
//! reserved for malformed requests, unknown compositions and operator
//! mistakes ([`pieces::Outcome`] vs `Err`).

pub mod authtype;
pub mod binding;
pub mod flow;
pub mod frame;
pub mod hex;
pub mod pieces;
pub mod reason;
pub mod registry;
pub mod types;

pub use authtype::AuthType;
pub use binding::{
    args_object, binding_digest, parse_audience, parse_rate_max, Binding, DEFAULT_RATE_MAX,
    MAX_AUDIENCE_LEN,
};
pub use flow::{produce_flow, verify_flow};
pub use frame::{frame, unframe, PAYLOAD_VERSION};
pub use hex::{hex32_bytes, norm_hex32, strip_0x};
pub use pieces::{
    downcast_identity, Authoriser, Cfg, Check, Claimant, Decoded, Evidence, Identity, Outcome,
    Scheme, Signer, Transport,
};
pub use registry::{dispatch_produce, dispatch_verify, ProduceRegistry, VerifyRegistry};
pub use types::{
    namespaced_nullifier, parse_produce_reply, parse_verdict, ProduceReply, ProduceRequest,
    Verdict, VerifyRequest, PRODUCE_METHOD, VERIFY_METHOD,
};
