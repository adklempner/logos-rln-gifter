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
| `lez-allowlist` (`src/lez.rs`) | module-owned LEZ public-account key (untweaked, x-only) | 104 B x-only key(32) ‖ BIP-340 sig(64) ‖ rate_max(8, u64 LE); the sig is over `sha256("logos/rln/lez-sign/2" ‖ id_commitment ‖ rate_max LE ‖ audience)` |
| `logos-allowlist` (`src/logos.rs`) | a key in a local logos-blockchain node's KMS (`POST /wallet/sign/zk`, http only) | 168 B `K(32) ‖ zksig(128) ‖ rate_max(8, u64 LE)`; zksig over `sha256("logos/rln/logos-sign/2" ‖ id_commitment ‖ rate_max LE ‖ audience)`; ~80 ms–1 s per signature on a local node (node 0.3.0-rc.5 or later) |

logos and lez bind `args.rate_max` (u64, default 100: the highest rate the
payload may be used for) and `args.audience` (string, default `""`, at most
255 bytes: the gifter it is meant for) into the signed digest. The
verifier's `config.audience` must match. **eth binds neither.** Its message
stays the bare commitment hex, so existing wallets and `cast` vectors keep
working.

## Methods

| Method | Args | Reply |
|---|---|---|
| `produce_auth(args_json)` | the `rln_auth_vector` ProduceRequest `{"auth_type","id_commitment_hex":"<64 hex>","args"?}`. `args` is an object or a JSON string holding one. eth/lez `args`: `{"private_key"?:"0x…"}` signs with that key instead of the module key. lez `args` also take `"rate_max"?:100,"audience"?:""`. logos `args`: `{"node_url"?:"http://127.0.0.1:8080","public_key"?:"<64 hex K>","http_timeout_ms"?:8000,"rate_max"?:100,"audience"?:""}` | `{"payload_hex":"…"}` or `{"error":"…"}` |
| `identity(req_json)` | `{"auth_type":"eth-allowlist"\|"lez-allowlist"\|"logos-allowlist","args"?:{…}}`; `args` only matters for logos (`node_url`, `public_key`) | `{"auth_type","id","persisted"}`; eth `id` = lowercase `0x` address; lez `id` = account id hex plus `"id_base58"`; logos `id` = K plus `"source":"args"\|"pow_status"` (`persisted` is always `true`: the node holds the key). Generates the eth/lez module key on first use |
| `import_key(req_json)` | `{"auth_type":"eth-allowlist"\|"lez-allowlist","private_key":"0x…","force"?:false}` | the identity object, after persisting the key. If a **different** key of that type is already persisted (or the file is unreadable), the reply is `{"error":"a different <type> key is already persisted; pass force:true to replace it"}` unless `force` is `true`. Re-importing the same key is fine. `logos-allowlist` → `{"error":"logos-allowlist keys live in the node's KMS; nothing to import"}` |

For logos, K is `args.public_key`, else the node's single `/pow/status`
auto-claim target. Zero or several targets is an error asking for
`args.public_key`.

The lez account id is LEZ's public-account id,
`sha256(b"/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`. The same private
key in a LEZ wallet shows the same account id. Each signed digest has its own
domain, so a payload can never be replayed as a LEZ transaction.

**Key custody (eth, lez) is demo-grade.** Each module key lives as plaintext
hex under `<instance_persistence_path>/`: `eth_sign_key.hex` and
`lez_sign_key.hex` (mode 0600), one per type. Each write goes to `FILE.tmp`
(0600), is fsynced and renamed over the key file, which is then chmodded
0600. Importing one never touches the other. Basecamp stamps a persistence path per module instance, so the
identities are stable there. `logos-standalone-app` stamps none, so the keys
are in-memory, change per run (`persisted:false`), and the module warns on
stderr. `import_key` from the CLI puts the key on a command line.

An eth key held by the old `eth_sign_module` lives in that module's own
persistence directory. To keep its address, `import_key` it into this module
(with `"force":true` if this module has already generated its own key).

What an allocator operator does with it: read `identity` for the type from
the client and put `id` (or `id_base58` for lez) in `serve`'s
`authVerifiers["<auth_type>"].config.allowlist`. The identity is the
nullifier, so each allowlisted identity gets one membership.

Build / test:

```sh
cd rust-lib && cargo test --lib        # unit tests for all three vectors + routing
LOGOS_NODE_URL=http://127.0.0.1:18080 cargo test --lib -- --ignored --nocapture
                                       # real-node v2 logos signature; rewrites
                                       # ../allowlist-auth-module/rust-lib/tests/fixtures/logos_sign_real.json
nix build 'path:.#lgx'                 # the installable bundle (delete rust-lib/target first)
```
