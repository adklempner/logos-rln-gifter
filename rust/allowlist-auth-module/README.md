# allowlist-auth-module — allowlist verifiers (gifter side)

The verifier half of the three allowlist auth vectors in one module (the
producer half is `../allowlist-sign-module`). The gifter calls
`verify_auth(args_json)` with the `rln_auth_vector` VerifyRequest; the request's
`auth_type` picks the vector, and each vector reads its own per-type config,
so `serve`'s `authVerifiers` entries keep their shape, now with
`"module":"allowlist_auth_module"`.

| `auth_type` | payload | digest signed | config | nullifier |
|---|---|---|---|---|
| `eth-allowlist` (`src/eth.rs`) | 65 B `r‖s‖recid` (recid 0/1 or 27/28) | EIP-191 `personal_sign` over the **lowercase hex** of the commitment | `{"allowlist":["0x…",…]}` (any case) | recovered address, lowercase `0x…` |
| `logos-allowlist` (`src/logos.rs`) | 160 B `K(32) ‖ zksig(128)`; K is the 32-byte LE Fr key as the node prints it, zksig `pi_a‖pi_b‖pi_c` | `sha256("logos/rln/logos-sign/1" ‖ id_commitment)` | `{"allowlist":["<64 hex K>",…],"zksign_vk_path"?}` (`0x`/any case OK; default VK = bundled circuits v0.5.7) | hex K |
| `lez-allowlist` (`src/lez.rs`) | 96 B x-only key (32) ‖ BIP-340 sig (64) | `sha256("logos/rln/lez-sign/1" ‖ id_commitment)` | `{"allowlist":["<64 hex or base58 LEZ account id>",…]}` | account id `sha256("/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`, lowercase hex |

Reply: `{"ok":true,"nullifier":"…"}`, `{"ok":false,"reason":"…"}`, or
`{"error":"…"}`. A missing, empty or malformed allowlist (or an unreadable
`zksign_vk_path`) is an operator error and comes back as `{"error"}`; anything
wrong with the untrusted payload or commitment, a bad signature or an unlisted
signer is a reject verdict. An unknown `auth_type` is an `{"error"}`
(`unknown auth_type '…' on this module`). For logos the allowlist check runs
before the Groth16 verification, and the zero key is rejected.

The logos accept tests use `rust-lib/tests/fixtures/logos_sign_real.json`, a
signature recorded from a real node (follower node 0.3.2, its disposable test
key) by allowlist-sign-module's ignored real-node test.

Build / test:

```sh
cd rust-lib && cargo test --lib        # all three vectors' tests + routing
nix build 'path:.#lgx'                 # the installable bundle (delete rust-lib/target first)
```
