# Allowlist auth vectors: eth, logos, lez

Three reference vectors share one shape: the allocator operator keeps a list
of credentials; a tester proves, with a signature bound to the identity
commitment of THIS request, that they hold a listed credential. The verifier
returns the credential as the nullifier, so each listed entry yields exactly one
membership. They differ in who holds the key and what is signed with it.

One module per side serves all three, dispatching on the request's
`auth_type`: the verifier `allowlist_auth_module` (`rust/allowlist-auth-module`,
each type keeps its own per-type config in `authVerifiers`) and the producer
`allowlist_sign_module` (`rust/allowlist-sign-module`). The producer's
methods:

- `produce_auth(args_json)`: the `rln_auth_vector` ProduceRequest
  `{"auth_type","id_commitment_hex","args"?}` -> `{"payload_hex"}`.
- `identity(req_json)`: `{"auth_type","args"?}` ->
  `{"auth_type","id","persisted"}`, plus `id_base58` (lez) or `source`
  (logos). `id` is what the operator allowlists. The eth/lez module key is
  generated on first use.
- `import_key(req_json)`: `{"auth_type":"eth-allowlist"|"lez-allowlist","private_key":"0x…","force"?:true}`
  -> the identity object, after persisting the key. A different key already
  persisted for that type is kept and the import refused unless `"force": true`,
  which replaces it (the old id is then no longer the one that signs).
  logos-allowlist is refused (the key lives in the node's KMS).

Every reply can be `{"error":"…"}` instead (an unknown `auth_type` among them).

Common rules:

- `idc32` is the 32 raw bytes of the identity commitment (the request's
  `identityCommitment` hex, decoded). It is a canonical BN254 scalar,
  little-endian (the gifter refuses anything else before and after the wire).
- The payload travels as `authPayload` hex. A producer module (`authProvider`)
  makes it during the request; there is no pre-made payload for logos or lez
  that is not bound to the commitment, so use the producer.
- The verifier config is `{"allowlist": [...]}`. A missing or empty allowlist
  is an operator error answered as `allowlist is empty`, never a silent accept.
  Order of checks: payload shape, allowlist membership (cheap), then the
  signature; a credential not on the list is refused by name without any
  signature work.
- Nullifiers are persisted by the gifter as `<auth_type>:<nullifier>`; a
  credential whose registration did not land (`insufficient_balance`, chain
  error) is released and can be retried.
- Keys: never logged. The logos and lez digests are version 2:
  `sha256(DOMAIN || idc32 || rate_max u64 LE || audience)`, with distinct
  domains (`logos/rln/logos-sign/2`, `logos/rln/lez-sign/2`), so a signature
  for one vector (or for the keycard vector) cannot be replayed as another.
  `rate_max` and `audience` come from the producer's `auth_args`
  (`{"rate_max": 100, "audience": ""}` by default) and travel in the payload
  (rate_max) or the verifier config (audience):
  - the verifier refuses a request whose `rate` exceeds the signed `rate_max`;
  - the verifier's `config.audience` (default `""`) must equal the producer's
    `audience`, so a payload made for one allocator is refused by another that
    sets a different audience. The Docker allocator sets it from
    `LOGOS_AUDIENCE` / `LEZ_AUDIENCE`.
- eth-allowlist is unchanged: EIP-191 over the commitment only, so any wallet
  can sign it. It therefore binds neither the rate nor the allocator: a leaked
  eth payload (for a commitment the attacker can register) can be spent at any
  allocator that allowlists the address, at any rate up to that allocator's
  `maxRateLimit`. The nullifier still limits it to one membership per
  allocator.

## Summary

| | `eth-allowlist` | `logos-allowlist` | `lez-allowlist` |
|---|---|---|---|
| Verifier / producer | `allowlist_auth_module` / `allowlist_sign_module` | `allowlist_auth_module` / `allowlist_sign_module` | `allowlist_auth_module` / `allowlist_sign_module` |
| Who holds the key | the module on the tester's client (file `eth_sign_key.hex`, 0600, under the module's persistence dir), or any wallet | the tester's own logos-blockchain node (its PoWClaim key); nothing is stored in the module | the module on the tester's client (file `lez_sign_key.hex`, 0600, under the persistence dir) |
| Signature | secp256k1 `personal_sign` (EIP-191) | zero-knowledge signature over the node's key, proved by the node (about 15 s) | BIP-340 Schnorr over secp256k1 |
| Digest | EIP-191 over the lowercase hex of `idc32` (binds no rate or allocator) | `sha256("logos/rln/logos-sign/2" \|\| idc32 \|\| rate_max u64 LE \|\| audience)` | `sha256("logos/rln/lez-sign/2" \|\| idc32 \|\| rate_max u64 LE \|\| audience)` |
| Payload | 65 B `r\|\|s\|\|v` | 168 B `K(32) \|\| zksig(128) \|\| rate_max(8)` | 104 B `xonly(32) \|\| sig(64) \|\| rate_max(8)` |
| Producer `auth_args` | `private_key`? | `node_url`, `public_key`?, `http_timeout_ms`?, `rate_max` (100), `audience` (`""`) | `private_key`?, `rate_max` (100), `audience` (`""`) |
| Verifier config | `allowlist` | `allowlist`, `audience` (`""`), `zksign_vk_path`? | `allowlist`, `audience` (`""`) |
| Allowlist entry | `0x` + 40 hex address, lowercase (the Docker reader accepts it without `0x` or in mixed case) | 64 hex public key K (little-endian, as the node prints it); `0x` and uppercase accepted | 64 hex account id, or its base58 form (decodes to exactly 32 bytes) |
| Nullifier | the address | K as 64 hex | the account id as 64 hex (`sha256(LEE prefix \|\| xonly)`) |
| Operator file (Docker) | `config/allowlist.txt` | `config/allowlist-logos.txt` | `config/allowlist-lez.txt` |
| Tester recipe | testers doc A | testers doc D | testers doc E |

## eth-allowlist

- Signed message: the lowercase hex of `idc32` (no `0x`), `personal_sign`.
- Producer: `identity` with `{"auth_type":"eth-allowlist"}` -> `id` = the
  lowercase `0x` address; `import_key` with
  `{"auth_type":"eth-allowlist","private_key":"0x…"}`; `auth_args`
  `{"private_key":"0x<32-byte hex>"}` signs with that key instead. `rate_max`
  and `audience` are not used: the signature does not bind them (see Common
  rules).
- A key held by the earlier `eth_sign_module` is not read by the new module
  (it lives in that module's own persistence directory): `import_key` it to
  keep the allowlisted address.
- Verifier config: `{"allowlist":["0x…"]}`.
- Refusals: `signature verification failed` (bad payload / signature),
  `not allowlisted`, `allowlist is empty`.

## logos-allowlist

- The key is a logos-blockchain node's PoWClaim key. The node proves a
  zero-knowledge signature over the digest on request; the producer asks the
  tester's own node over its HTTP API (http only, a local node) and appends the
  key. The private key never leaves the node.
- Producer: `identity` with `{"auth_type":"logos-allowlist","args":{"node_url":…}}`
  -> `id` = K and `source` = `args` or `pow_status` (the node's single
  PoWClaim target; zero or several targets need `public_key` in the args);
  `persisted` is always true. `import_key` is refused. `auth_args`: `{"node_url":"http://127.0.0.1:8080","public_key"?,"http_timeout_ms"?,"rate_max"?:100,"audience"?:""}`.
  From the Docker client the node is `http://host.docker.internal:18080`.
- Verifier config: `{"allowlist":["<64 hex K>", …],"audience":""}`;
  `zksign_vk_path` optionally replaces the vendored verification key. An entry
  that is not a canonical little-endian BN254 scalar rejects the whole config.
- Checks in order: config, payload length (168), idc, K allowlisted, K is not
  the all-zero key, request rate ≤ signed `rate_max`, signature verifies
  against K and the digest (which includes the verifier's `audience`).
- Byte order: K is the hex the node's `/pow/status` prints (little-endian
  field element) everywhere; it is never reversed. A byte-reversed K is refused.
- Refusals: `not allowlisted`, `allowlist is empty`, payload-length and
  signature failures (exact wording is the module's).

## lez-allowlist

- The key is a plain secp256k1 key held by `allowlist_sign_module`. The account id is
  `sha256(LEE_PREFIX || xonly)` over the x-only public key, the same derivation
  as a LEZ account; the base58 form is what a LEZ wallet shows.
- Producer: `identity` with `{"auth_type":"lez-allowlist"}` -> `id` = the
  account id hex and `id_base58`; `import_key` with
  `{"auth_type":"lez-allowlist","private_key":"0x…"}`; `auth_args`
  `{"private_key"?:"0x<32-byte hex>","rate_max"?:100,"audience"?:""}`; a
  `private_key` there signs with that key instead. Without a
  persistence path the key is per-run; use the override for a stable id.
  `import_key` through the CLI puts the key on a command line.
- Verifier config: `{"allowlist":["<64 hex or base58>", …],"audience":""}`,
  entries normalised to hex; a base58 entry that does not decode to 32 bytes is
  an operator error for the whole list.
- Checks in order: config, payload length (104), idc, request rate ≤ signed
  `rate_max`, x-only key parses, signature verifies (digest includes the
  verifier's `audience`), account id derived, account id allowlisted.
- Refusals: `not allowlisted`, `allowlist is empty`, signature failures.

## Docker allocator

Files in `tools/allocator/docker/config/` (bind-mounted at `/etc/allocator`,
live files git-ignored, examples `*.txt.example`): lines are `#` comments or one
credential. `allowlist.txt` lines must match `(0x)?[0-9a-fA-F]{40}` (normalised
to lowercase with `0x`). `allowlist-logos.txt` lines must match
`(0x)?[0-9a-fA-F]{64}` (normalised to lowercase without `0x`) and be a canonical
little-endian field element (< the BN254 modulus; a big-endian paste usually is
not). `allowlist-lez.txt` lines are 64 hex, or base58 that the reader decodes and
keeps only if it is exactly 32 bytes; both are passed to the verifier as
lowercase hex. Other lines are dropped and logged (the verifier would reject the
whole list for one bad entry), and duplicates are dropped. `LOGOS_AUDIENCE` /
`LEZ_AUDIENCE` (default empty) become the verifiers' `config.audience`; testers
must put the same string in `auth_args.audience`. The
entrypoint watches the three files by mtime and re-serves within
`HEALTH_EVERY_S` (30 s) when any changes. `LOGOS_ALLOWLIST=0` / `LEZ_ALLOWLIST=0`
turn a vector off; both are on by default and served even when empty (with a
WARNING in the log). Paths can be overridden with `ALLOWLIST_LOGOS_FILE` /
`ALLOWLIST_LEZ_FILE`.
