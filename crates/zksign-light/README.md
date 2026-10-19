# zksign_light

Logos-blockchain zkSign helpers for RLN gifter auth vectors (no logos SDK
dependency):

- feature `verify` — `PreparedVk::{from_json, from_path}`, `DEFAULT_VK_JSON`
  (the zkSign VK of circuits v0.5.7, `assets/`), `default_vk`, `zero_pk`,
  `zero_pk_le`, `verify_sig(vk, k_le32, digest32, zksig128)`. Public inputs are
  `[K, zero_pk × 31, Fr::from_le_bytes_mod_order(digest)]`.
- feature `client` — plain-http (ureq, no TLS) `pow_status(url, timeout_ms)`,
  `sign_zk(url, digest32, pk_hex, timeout_ms) -> [u8; 128]` (K alone in `pks`),
  `parse_sig_reply`.
- always — `norm_hex32`, `hex32_bytes`.

Both features are default for `cargo test` here; consumers take
`default-features = false` plus the feature they need, as a git dep pinned to
a rev:

```toml
zksign_light = { git = "https://github.com/logos-co/logos-rln-gifter", rev = "<rev>", package = "zksign_light", default-features = false, features = ["verify"] }
```

`tests/real_fixture.rs` is a known answer from a real node (0.3.0-rc.5): the
pow-claim capture fixture's signature verifies; flipped proof bytes, another
key, a byte-reversed key, the zero key and another digest reject.
