# eth-sign-module — eth-allowlist producer (client side)

The producer half of the `eth-allowlist` auth vector (the verifier half is
`../eth-auth-module`). It lets a membership module drive the vector through
`auth_provider`: `liblogos_rln_module.register_membership` mints the identity
commitment, `rln_gifter_module` asks this module for a payload bound to it,
and the allocator's `eth_auth_module` recovers the signer and checks its
allowlist.

| Method | Args | Reply |
|---|---|---|
| `produce_auth(args_json)` | `{"auth_type":"eth-allowlist","id_commitment_hex":"<64 hex>","args"?:{"private_key"?:"0x…"}}` (the `rln_auth_vector` ProduceRequest) | `{"payload_hex":"<130 hex>"}` — `r‖s‖recid`, recid 0/1, an EIP-191 `personal_sign` over the **lowercase hex** of the commitment (what `cast wallet sign "<hex>"` produces, minus the 27 offset) — or `{"error":"…"}` |
| `address()` | — | `{"address":"0x…" (lowercase),"persisted":bool}`; generates the module key on first use |
| `import_key(private_key_hex)` | hex, optional `0x` | `{"address":"0x…"}` after persisting the key |

**Key custody is demo-grade.** The module key lives as plaintext hex in
`<instance_persistence_path>/eth_sign_key.hex` (mode 0600). Basecamp stamps a
persistence path per module instance, so the address is stable there;
`logos-standalone-app` stamps none, so the key is in-memory and changes per
run (`persisted:false`). `args.private_key` signs with a caller-supplied key
instead, for scripts and tests.

What an allocator operator does with it: read `address` from the client,
put it in `serve`'s `authVerifiers["eth-allowlist"].config.allowlist`. The
address is the nullifier, so each allowlisted key gets one membership.

Build / test:

```sh
cd rust-lib && cargo test --lib        # unit tests incl. a foundry `cast` vector
nix build 'path:.#lgx'                 # the installable bundle
```

Exercised end to end (chainless) by `tools/allocator/verify-chainless.sh`
assert A9, and by the membership UI's allocator step
(`logos-rln-membership-ui`, auth vector "Ethereum key").
