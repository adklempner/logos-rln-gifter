# lez-auth-module — lez-allowlist verifier (allocator side)

The verifier half of the `lez-allowlist` auth vector (the producer half is
`../lez-sign-module`). The allocator's gifter calls `verify_auth` with the
requester's payload and the operator's config.

| Method | Args | Reply |
|---|---|---|
| `verify_auth(args_json)` | the `rln_auth_vector` VerifyRequest, `auth_type` `"lez-allowlist"` | `{"ok":true,"nullifier":"<64 hex account id>"}`, `{"ok":false,"reason":"…"}`, or `{"error":"…"}` for a malformed request or config |

- **Payload** (96 B): x-only secp256k1 public key (32 B) ‖ BIP-340 Schnorr
  signature (64 B) over `sha256("logos/rln/lez-sign/1" ‖ id_commitment)`.
- **Config**: `{"allowlist":["<account id>", …]}`; each entry is 64 hex
  (optional `0x`, any case) or base58 decoding to exactly 32 bytes. A missing,
  empty or malformed allowlist is an `error` (operator mistake).
- **Account id**: `sha256(b"/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`,
  LEZ's public-account id. It is the nullifier, so each allowlisted account
  gets one membership.
- Bad hex or length, a bad key or signature, and an unlisted account (the
  reason names its id) are rejects, not errors.

Build / test:

```sh
cd rust-lib && cargo test --lib
nix build 'path:.#lgx'
```
