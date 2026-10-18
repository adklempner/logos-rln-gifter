# logos-sign-module — logos-allowlist producer (client side)

The producer half of the `logos-allowlist` auth vector (the verifier half is
`../logos-auth-module`). The key stays in a local logos-blockchain node's KMS:
this module asks the node to zkSign the request, so a membership module can
drive the vector through `auth_provider` with only a node URL.

| Method | Args | Reply |
|---|---|---|
| `produce_auth(args_json)` | `{"auth_type":"logos-allowlist","id_commitment_hex":"<64 hex>","args"?:{"node_url"?:"http://127.0.0.1:8080","public_key"?:"<64 hex>","http_timeout_ms"?:8000}}` (the `rln_auth_vector` ProduceRequest; `args` may be a JSON string) | `{"payload_hex":"<320 hex>"}` — `K(32) ‖ zksig(128)` — or `{"error":"…"}` |
| `public_key(args_json)` | the same `args` object (`""` for defaults) | `{"public_key":"<64 hex>","source":"args"\|"pow_status"}` or `{"error"}` |

- **Digest:** `sha256(b"logos/rln/logos-sign/1" ‖ id_commitment)`, sent raw as
  `tx_hash` to `POST /wallet/sign/zk` with `pks: [K]` (the node reduces it mod
  p and fills the other 31 key slots with the zero key).
- **K:** `args.public_key`, else the node's single `/pow/status`
  `auto_claim.targets[].public_key` (32-byte little-endian Fr hex, exactly as
  the node prints it — never reverse it). Zero or several targets is an error
  asking for `public_key`. Any non-zk key in the node's KMS can sign.
- **Transport:** plain http to a local node (no TLS); signing waits at least
  60 s (`zksign_light::SIGN_MIN_TIMEOUT_MS`), within the gifter's 120 s
  produce budget.

What an allocator operator does with it: read `public_key` from the client,
add it to `serve`'s `authVerifiers["logos-allowlist"].config.allowlist`. K is
the nullifier, so each allowlisted key gets one membership.

Build / test:

```sh
cd rust-lib && cargo test --lib                       # unit tests (fake node)
LOGOS_NODE_URL=http://127.0.0.1:18080 \
  cargo test --lib -- --ignored --nocapture           # real node: sign, verify offline,
                                                      # re-record logos-auth's accept fixture
nix build 'path:.#lgx'                                # the installable bundle
```

`zksign_light` comes from this repo's `crates/zksign-light` as a git dep pinned
to a rev; the `[patch]` in `rust-lib/Cargo.toml` points it at the local path
for development and must be gone before `nix build` (the builder stages only
`rust-lib/`).
