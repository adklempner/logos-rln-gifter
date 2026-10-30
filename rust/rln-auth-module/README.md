# rln-auth-module — the gifter's verifier

One module answers every auth vector the gifter can be configured with. The
gifter calls `verify_auth(args_json)` with the `rln_auth_vector`
VerifyRequest; `auth_type` is a composition, `<scheme>-<authoriser>`, and
the module resolves both halves from the registry it builds at load
(`rln_auth_vectors`). `supported_auth_types()` lists the compositions.

| scheme | identity | authoriser | config | nullifier |
|---|---|---|---|---|
| `eth` | recovered 0x address (EIP-191 over the bare commitment) | `allowlist` | `{"allowlist":["0x…"],"audience"?}` | address |
| `lez` | LEE account id of the BIP-340 key | `allowlist` | `{"allowlist":["<64 hex or base58>"],"audience"?}` | account hex |
| `logos` | zkSign key K | `allowlist` / `pow-claim` | `{"allowlist":["<64 hex K>"],"audience"?,"zksign_vk_path"?}` / `{"node_url",…}` | hex K / hex(pow_nullifier) |
| `keycard` | card identity key | `allowlist` / `attestation` | `{"allowlist":["<33-byte hex>"]}` / `{"trusted_cas":["<33-byte hex>"],"audience"?}` | ident_pub hex / keccak(ident_pub) |

The rules every composition shares (the payload frame, the binding digest,
reject-vs-error, the rate rule) are in `docs/auth-vectors.md`. The pieces
themselves live in `crates/rln-auth-vectors`; this module only composes
them.

Build: `nix build 'path:.#lgx'` (delete `rust-lib/target` first). Local
tests: `cargo test` in `rust-lib` (no network).
