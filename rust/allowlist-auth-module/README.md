# allowlist-auth-module — allowlist verifiers (gifter side)

The verifier half of the three allowlist auth vectors in one module (the
producer half is `../allowlist-sign-module`). The gifter calls
`verify_auth(args_json)` with the `rln_auth_vector` VerifyRequest; the request's
`auth_type` picks the vector, and each vector reads its own per-type config,
so `serve`'s `authVerifiers` entries keep their shape, now with
`"module":"allowlist_auth_module"`.

| `auth_type` | payload | digest signed | config | nullifier |
|---|---|---|---|---|
| `eth-allowlist` (`src/eth.rs`) | 65 B `r‖s‖recid` (recid 0/1 or 27/28; low-S only) | EIP-191 `personal_sign` over the **lowercase hex** of the 32-byte commitment | `{"allowlist":["0x…",…]}` (`0x` + 40 hex or bare 40 hex, any case) | recovered address, lowercase `0x…` |
| `logos-allowlist` (`src/logos.rs`) | 168 B `K(32) ‖ zksig(128) ‖ rate_max(8, u64 LE)`; K is the 32-byte LE Fr key as the node prints it, zksig `pi_a‖pi_b‖pi_c` | `sha256("logos/rln/logos-sign/2" ‖ id_commitment ‖ rate_max LE ‖ audience)` | `{"allowlist":["<64 hex K>",…],"audience"?:"","zksign_vk_path"?}` (`0x`/any case OK, each K a canonical LE scalar; default VK = bundled circuits v0.5.7) | hex K |
| `lez-allowlist` (`src/lez.rs`) | 104 B x-only key (32) ‖ BIP-340 sig (64) ‖ rate_max (8, u64 LE) | `sha256("logos/rln/lez-sign/2" ‖ id_commitment ‖ rate_max LE ‖ audience)` | `{"allowlist":["<64 hex or base58 LEZ account id>",…],"audience"?:""}` | account id `sha256("/LEE/v0.3/AccountId/Public/\0\0\0\0\0" ‖ xonly)`, lowercase hex |

**Rate and audience binding (logos, lez).** The producer signs the highest
rate it allows (`rate_max`, default 100) and the gifter it means
(`audience`, default `""`). The payload carries `rate_max`. The verifier
rejects `rate N exceeds the signed rate_max M` when the request's `rate` is
higher, and recomputes the digest with its own `config.audience`, so a
payload signed for another gifter does not verify. **eth is the exception:**
its message stays the bare commitment hex so any wallet (`personal_sign`,
`cast wallet sign "<hex>"`) can produce it. It binds neither rate nor
audience.

Reply: `{"ok":true,"nullifier":"…"}`, `{"ok":false,"reason":"…"}`, or
`{"error":"…"}`. Operator errors come back as `{"error"}`: a missing, empty or
malformed allowlist (an eth entry that is not an address, a logos key that is
not a canonical BN254 scalar, which usually means a big-endian paste), a bad
`audience`, or an unreadable or wrong-shape `zksign_vk_path` (the VK must
have 33 public inputs). Anything wrong with the untrusted payload or
commitment, a bad signature, a rate above `rate_max` or an unlisted signer is
a reject verdict. An unknown `auth_type` is an `{"error"}`
(`unknown auth_type '…' on this module`). For logos the allowlist check runs
before the Groth16 verification, and the zero key is rejected. A VK file
replaced at the same path is reloaded: the cache is keyed by path, mtime and
size.

The logos accept tests use `rust-lib/tests/fixtures/logos_sign_real.json`
(`{idc, k, rate_max, audience, payload_hex}`), a v2 signature recorded from a
real node (its disposable test key) by allowlist-sign-module's ignored
real-node test. Its digest is ≥ p, so the test also covers the node's
mod-p reduction of the signed bytes.

Build / test:

```sh
cd rust-lib && cargo test --lib        # all three vectors' tests + routing
nix build 'path:.#lgx'                 # the installable bundle (delete rust-lib/target first)
```
