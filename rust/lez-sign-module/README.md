# lez-sign-module — lez-allowlist producer (client side)

The producer half of the `lez-allowlist` auth vector (the verifier half is
`../lez-auth-module`). It lets a membership module drive the vector through
`auth_provider`: `liblogos_rln_module.register_membership` mints the identity
commitment, `rln_gifter_module` asks this module for a payload bound to it,
and the allocator's `lez_auth_module` verifies the signature and checks the
signer's LEZ account id against its allowlist.

| Method | Args | Reply |
|---|---|---|
| `produce_auth(args_json)` | `{"auth_type":"lez-allowlist","id_commitment_hex":"<64 hex>","args"?:{"private_key"?:"0x…"}}` (the `rln_auth_vector` ProduceRequest) | `{"payload_hex":"<192 hex>"}` — x-only public key (32 B) ‖ BIP-340 Schnorr signature (64 B) over `sha256("logos/rln/lez-sign/1" ‖ id_commitment)` — or `{"error":"…"}` |
| `account_id()` | — | `{"account_id":"<64 hex>","account_id_base58":"…","public_key":"<64 hex x-only>","persisted":bool}`; generates the module key on first use |
| `import_key(private_key_hex)` | hex, optional `0x` | `{"account_id","account_id_base58","public_key"}` after persisting the key |

The account id is LEZ's public-account id,
`sha256(b"/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`, shown in hex and
in base58. LEZ uses imported keys untweaked, so the same private key in a LEZ
wallet shows the same account id. The signed digest uses its own domain, so
a payload can never be replayed as a LEZ transaction.

**Key custody is demo-grade.** The module key lives as plaintext hex in
`<instance_persistence_path>/lez_sign_key.hex` (mode 0600). Basecamp stamps a
persistence path per module instance, so the account is stable there;
`logos-standalone-app` stamps none, so the key is in-memory and changes per
run (`persisted:false`). `args.private_key` signs with a caller-supplied key
instead, for scripts and tests. `import_key` from the CLI puts the key on a
command line.

What an allocator operator does with it: read `account_id` (hex or base58)
from the client, put it in `serve`'s
`authVerifiers["lez-allowlist"].config.allowlist`. The account id is the
nullifier, so each allowlisted account gets one membership.

Build / test:

```sh
cd rust-lib && cargo test --lib        # unit tests incl. the BIP-340 vector-0 account id
nix build 'path:.#lgx'                 # the installable bundle
```
