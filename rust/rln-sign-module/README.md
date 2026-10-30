# rln-sign-module — the client's producer

The produce half of every auth vector that needs no card hardware, in one
module, so a membership module can drive any of them through
`auth_provider`. `produce_auth(args_json)` takes the `rln_auth_vector`
ProduceRequest; `auth_type` is `<scheme>-<authoriser>` over the schemes
`eth`, `lez`, `logos` and the authorisers `allowlist`, `attestation`,
`pow-claim` (the keycard scheme is `../keycard-capture-module`).

| scheme | key | `args` | identity (`identity`) |
|---|---|---|---|
| `eth` | module-owned secp256k1 key, or `args.private_key` | `rate_max`, `audience`, `private_key`? | `0x…` address |
| `lez` | module-owned LEZ account key, or `args.private_key` | same | account id (hex + base58) |
| `logos` | the node's KMS key (`POST /wallet/sign/zk`) | `node_url`, `public_key`?, `http_timeout_ms`, `rate_max`, `audience` | key K |

`pow-claim` adds the claim locator from the same node (`claim_address`,
`claim_block_id`, `pow_nullifier`, `exclude_nullifiers`, … — see
`crates/pow-claim`); the key the claim is searched for is `claim_address`,
else `public_key`.

- `identity` `{"scheme"|"auth_type","args"?}` → `{"scheme","id","persisted"}`
  (+ `id_base58` for lez, `source` for logos). Generates and persists the
  eth/lez module key on first use.
- `import_key` `{"scheme"|"auth_type","private_key","force"?}` replaces the
  eth or lez module key; a different persisted key needs `force:true`.

Key custody is demo-grade on purpose: one plaintext hex file per scheme
under the module's host-stamped persistence path (0600); a host that stamps
no path gets in-memory keys that change per run.

The rules every composition shares (the payload frame, the binding digest,
the eth exception) are in `docs/auth-vectors.md`; the pieces are
`crates/rln-auth-vectors`.

Build: `nix build 'path:.#lgx'` (delete `rust-lib/target` first). Local
tests: `cargo test` in `rust-lib` (no network).
