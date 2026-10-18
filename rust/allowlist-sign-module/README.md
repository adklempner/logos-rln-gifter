# allowlist-sign-module — allowlist producers (client side)

The producer half of the three allowlist auth vectors in one module (the
verifier half is `../allowlist-auth-module`). It lets a membership module
drive any of them through `auth_provider`:
`liblogos_rln_module.register_membership` mints the identity commitment,
`rln_gifter_module` asks this module for a payload bound to it, and the
allocator's `allowlist_auth_module` verifies it against its allowlist.

| `auth_type` | signer | payload |
|---|---|---|
| `eth-allowlist` (`src/eth.rs`) | module-owned secp256k1 key | 65 B `r‖s‖recid`, recid 0/1: EIP-191 `personal_sign` over the **lowercase hex** of the commitment (what `cast wallet sign "<hex>"` produces, minus the 27 offset) |
| `lez-allowlist` (`src/lez.rs`) | module-owned LEZ public-account key (untweaked, x-only) | 96 B x-only key ‖ BIP-340 sig over `sha256("logos/rln/lez-sign/1" ‖ id_commitment)` |
| `logos-allowlist` (`src/logos.rs`) | a key in a local logos-blockchain node's KMS (`POST /wallet/sign/zk`, http only) | 160 B `K(32) ‖ zksig(128)` over `sha256("logos/rln/logos-sign/1" ‖ id_commitment)`; ~15 s per signature |

## Methods

| Method | Args | Reply |
|---|---|---|
| `produce_auth(args_json)` | the `rln_auth_vector` ProduceRequest `{"auth_type","id_commitment_hex":"<64 hex>","args"?}`. eth/lez `args`: `{"private_key"?:"0x…"}` signs with that key instead of the module key. logos `args`: `{"node_url"?:"http://127.0.0.1:8080","public_key"?:"<64 hex K>","http_timeout_ms"?:8000}`, as an object or a JSON string | `{"payload_hex":"…"}` or `{"error":"…"}` |
| `identity(req_json)` | `{"auth_type":"eth-allowlist"\|"lez-allowlist"\|"logos-allowlist","args"?:{…}}`; `args` only matters for logos (`node_url`, `public_key`) | `{"auth_type","id","persisted"}`; eth `id` = lowercase `0x` address; lez `id` = account id hex plus `"id_base58"`; logos `id` = K plus `"source":"args"\|"pow_status"` (`persisted` is always `true`: the node holds the key). Generates the eth/lez module key on first use |
| `import_key(req_json)` | `{"auth_type":"eth-allowlist"\|"lez-allowlist","private_key":"0x…"}` | the identity object, after persisting the key; `logos-allowlist` → `{"error":"logos-allowlist keys live in the node's KMS; nothing to import"}` |

For logos, K is `args.public_key`, else the node's single `/pow/status`
auto-claim target. Zero or several targets is an error asking for
`args.public_key`.

The lez account id is LEZ's public-account id,
`sha256(b"/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`. The same private
key in a LEZ wallet shows the same account id. Each signed digest has its own
domain, so a payload can never be replayed as a LEZ transaction.

**Key custody (eth, lez) is demo-grade.** Each module key lives as plaintext
hex under `<instance_persistence_path>/`: `eth_sign_key.hex` and
`lez_sign_key.hex` (mode 0600), one per type. Importing one never touches the
other. Basecamp stamps a persistence path per module instance, so the
identities are stable there. `logos-standalone-app` stamps none, so the keys
are in-memory, change per run (`persisted:false`), and the module warns on
stderr. `import_key` from the CLI puts the key on a command line.

An eth key held by the old `eth_sign_module` lives in that module's own
persistence directory. To keep its address, `import_key` it into this module.

What an allocator operator does with it: read `identity` for the type from
the client and put `id` (or `id_base58` for lez) in `serve`'s
`authVerifiers["<auth_type>"].config.allowlist`. The identity is the
nullifier, so each allowlisted identity gets one membership.

Build / test:

```sh
cd rust-lib && cargo test --lib        # unit tests for all three vectors + routing
LOGOS_NODE_URL=http://127.0.0.1:18080 cargo test --lib -- --ignored --nocapture
                                       # real-node logos signature; rewrites
                                       # ../allowlist-auth-module/rust-lib/tests/fixtures/logos_sign_real.json
nix build 'path:.#lgx'                 # the installable bundle (delete rust-lib/target first)
```
