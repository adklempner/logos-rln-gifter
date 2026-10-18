# logos-auth-module — logos-allowlist verifier (gifter side)

The verifier half of the `logos-allowlist` auth vector (the producer half is
`../logos-sign-module`). It checks, offline, that an allowlisted
logos-blockchain key zkSigned the requester's identity commitment.

`verify_auth(args_json)` — the `rln_auth_vector` VerifyRequest with
`auth_type` `logos-allowlist`:

- **payload:** `K(32) ‖ zksig(128)` = 160 bytes. K is the 32-byte
  little-endian Fr public key as the node prints it; zksig is the node's
  `pi_a(32) ‖ pi_b(64) ‖ pi_c(32)`.
- **digest:** `sha256(b"logos/rln/logos-sign/1" ‖ id_commitment)`.
- **config:** `{"allowlist":["<64 hex K>", …], "zksign_vk_path"?:"/path/vk.json"}`.
  Entries may carry `0x` and any case. Without `zksign_vk_path` the bundled
  zkSign VK (circuits v0.5.7) is used.
- **order:** config (missing/empty/malformed allowlist or unreadable VK is an
  `{"error"}`) → payload length → commitment → K allowlisted → K ≠ zero key →
  Groth16 verify → `{"ok":true,"nullifier":"<hex K>"}`. Everything after the
  config step is a reject verdict (`{"ok":false,"reason"}`).

The accept tests use `rust-lib/tests/fixtures/logos_sign_real.json`, a
signature recorded from a real node by logos-sign-module's ignored test (the
follower node's disposable test key, node 0.3.2, verifying against the v0.5.7
VK).

Build / test:

```sh
cd rust-lib && cargo test --lib
nix build 'path:.#lgx'
```

As for logos-sign-module, drop the local `[patch]` in `rust-lib/Cargo.toml`
once `zksign_light` is pinned to a pushed rev.
