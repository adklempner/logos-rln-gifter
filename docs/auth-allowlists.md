# Allowlist auth vectors: eth, logos, lez

Three reference vectors share one shape: the allocator operator keeps a list
of credentials; a tester proves, with a signature bound to the identity
commitment of THIS request, that they hold a listed credential. The verifier
returns the credential as the nullifier, so each listed entry yields exactly one
membership. They differ in who holds the key and what is signed with it.

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
- Keys: never logged. Digests of the new vectors use a `sha256(DOMAIN || idc32)`
  prefix with distinct domains, so a signature for one vector (or for the
  keycard vector) cannot be replayed as another.

## Summary

| | `eth-allowlist` | `logos-allowlist` | `lez-allowlist` |
|---|---|---|---|
| Verifier / producer | `eth_auth_module` / `eth_sign_module` | `logos_auth_module` / `logos_sign_module` | `lez_auth_module` / `lez_sign_module` |
| Who holds the key | the module on the tester's client (file `eth_sign_key.hex`, 0600, under the module's persistence dir), or any wallet | the tester's own logos-blockchain node (its PoWClaim key); nothing is stored in the module | the module on the tester's client (file `lez_sign_key.hex`, 0600, under the persistence dir) |
| Signature | secp256k1 `personal_sign` (EIP-191) | zero-knowledge signature over the node's key, proved by the node (about 15 s) | BIP-340 Schnorr over secp256k1 |
| Digest | EIP-191 over the lowercase hex of `idc32` | `sha256("logos/rln/logos-sign/1" \|\| idc32)` | `sha256("logos/rln/lez-sign/1" \|\| idc32)` |
| Payload | 65 B `r\|\|s\|\|v` | 160 B `K(32) \|\| zksig(128)` | 96 B `xonly(32) \|\| sig(64)` |
| Allowlist entry | `0x` + 40 hex address, lowercase | 64 hex public key K (little-endian, as the node prints it); `0x` and uppercase accepted | 64 hex account id, or its base58 form (decodes to exactly 32 bytes) |
| Nullifier | the address | K as 64 hex | the account id as 64 hex (`sha256(LEE prefix \|\| xonly)`) |
| Operator file (Docker) | `config/allowlist.txt` | `config/allowlist-logos.txt` | `config/allowlist-lez.txt` |
| Tester recipe | testers doc A | testers doc D | testers doc E |

## eth-allowlist

- Signed message: the lowercase hex of `idc32` (no `0x`), `personal_sign`.
- Producer `eth_sign_module`: `produce_auth`, `address()` -> `{"address","persisted"}`,
  `import_key(hex)`; `auth_args` `{"private_key":"0x<32-byte hex>"}` overrides.
- Verifier config: `{"allowlist":["0x…"]}`.
- Refusals: `signature verification failed` (bad payload / signature),
  `not allowlisted`, `allowlist is empty`.

## logos-allowlist

- The key is a logos-blockchain node's PoWClaim key. The node proves a
  zero-knowledge signature over the digest on request; the producer asks the
  tester's own node over its HTTP API (http only, a local node) and appends the
  key. The private key never leaves the node.
- Producer `logos_sign_module`: `produce_auth`, `public_key(args_json)` ->
  `{"public_key","source"}` where source is `args` or `pow_status` (the node's
  single PoWClaim target; zero or several targets need `public_key` in the
  args). `auth_args`: `{"node_url":"http://127.0.0.1:8080","public_key"?,"http_timeout_ms"?}`.
  From the Docker client the node is `http://host.docker.internal:18080`.
- Verifier config: `{"allowlist":["<64 hex K>", …]}`; `zksign_vk_path`
  optionally replaces the vendored verification key.
- Checks in order: config, payload length (160), idc, K allowlisted, K is not
  the all-zero key, signature verifies against K and the digest.
- Byte order: K is the hex the node's `/pow/status` prints (little-endian
  field element) everywhere; it is never reversed. A byte-reversed K is refused.
- Refusals: `not allowlisted`, `allowlist is empty`, payload-length and
  signature failures (exact wording is the module's).

## lez-allowlist

- The key is a plain secp256k1 key held by `lez_sign_module`. The account id is
  `sha256(LEE_PREFIX || xonly)` over the x-only public key, the same derivation
  as a LEZ account; the base58 form is what a LEZ wallet shows.
- Producer `lez_sign_module`: `produce_auth`, `account_id()` ->
  `{"account_id","account_id_base58","public_key","persisted"}`, `import_key(hex)`;
  `auth_args` `{"private_key":"0x<32-byte hex>"}` overrides. Without a
  persistence path the key is per-run; use the override for a stable id.
  `import_key` through the CLI puts the key on a command line.
- Verifier config: `{"allowlist":["<64 hex or base58>", …]}`, entries
  normalised to hex; a base58 entry that does not decode to 32 bytes is an
  operator error.
- Checks in order: config, payload length (96), idc, x-only key parses,
  signature verifies, account id derived, account id allowlisted.
- Refusals: `not allowlisted`, `allowlist is empty`, signature failures.

## Docker allocator

Files in `tools/allocator/docker/config/` (bind-mounted at `/etc/allocator`,
live files git-ignored, examples `*.txt.example`): lines are `#` comments or one
credential. `allowlist-logos.txt` lines must match `(0x)?[0-9a-f]{64}`
(normalised to lowercase without `0x`); `allowlist-lez.txt` lines are 64 hex or
base58 and are passed as given. Other lines are dropped and logged. The
entrypoint watches the three files by mtime and re-serves within
`HEALTH_EVERY_S` (30 s) when any changes. `LOGOS_ALLOWLIST=0` / `LEZ_ALLOWLIST=0`
turn a vector off; both are on by default and served even when empty (with a
WARNING in the log). Paths can be overridden with `ALLOWLIST_LOGOS_FILE` /
`ALLOWLIST_LEZ_FILE`.
