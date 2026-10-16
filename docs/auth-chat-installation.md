# `chat-installation` — a gifter auth vector for logos-chat accounts

Design note. Nothing in this document is implemented yet; the roadmap at the
end says what has to change, where, and in which order.

## 1. Purpose and threat model

End-users of `chat_module` need an RLN membership to post on the DoS-protected
logos-delivery network. The gifter registers memberships on their behalf,
gated by a pluggable auth vector (`crates/rln-auth-vector`). The two reference
vectors — keycard attestation and an Eth allowlist — assume hardware or a
wallet a chat user does not necessarily have.

This vector lets a chat user authenticate with what the chat client already
holds: an **installation key** endorsed by a **published account log**.

What it proves:

- the requester possesses the private half of an Ed25519 installation key;
- that key is endorsed, under the `chat.signer` context, in an account log
  signed by the account it claims to belong to;
- the signature was made for *this* identity commitment at *this* rate.

What it does not prove:

- that unmodified logos-chat software produced the request. Key possession is
  key possession; a modified client holds the same key.
- anything about scarcity. Accounts and endorsements cost nothing to create
  (`Ed25519SigningKey::generate` is the whole price). **This vector alone is
  not sybil-resistant.** It is the identity layer a sybil layer can be
  attached to (§7).

## 2. Primitives it builds on

All references are to `logos-messaging/logos-chat` at `d4e20ad`
("Account: namespace implementation (#294)").

| Primitive | Where | What matters here |
|---|---|---|
| `AccountAddr` | `account/account-log/src/addr.rs` | **Is** the account's 32-byte Ed25519 verifying key (no hash). `Display`/`FromStr` are 64 lowercase hex chars, no prefix. `TryFrom<&[u8]>` rejects non-canonical and small-order keys. |
| `SignedAccountLog { payload, signature }` | `account/account-log/src/account_log.rs:39`, `codec.rs` | Wire bytes are `signature(64) ‖ payload`. `SignedAccountLog::from_bytes(&[u8])` splits, `to_bytes()` joins. |
| `SignedAccountLog::verify(&addr) -> AccountLog` | `account_log.rs:98` | Verifies the signature under the address key with `verify_strict`, then decodes and validates the entries. One call does the whole trust check. |
| Payload encoding | `codec.rs:13,42-51` | `"logos:accounts:1\0" ‖ entry*`, each entry `opcode u8 ‖ u16 LE len ‖ body`. `Add(Ed25519Key)` body is `ctx_len u8 ‖ ctx ‖ 0x01 ‖ key[32]`. `MAX_PAYLOAD_BYTES = 128 KiB`. |
| `ed25519_keys_for(ctx)` / `revoked_ed25519_keys_for(ctx)` | `account_log.rs:175,192` | Live and revoked keys per context. A `Remove` must target an earlier live entry or the whole log is invalid. |
| `"chat.signer"` | `account/account/src/namespaces/chat.rs:12` | The context chat installations are endorsed under. The constant is private; `ChatRead::chat_signers()` / `revoked_chat_signers()` on `AccountRecord` expose it. |
| `Installation { signing_key, signer, account, origin }` | `crates/generic-chat/src/installation.rs:76` | The identity a client runs as. Validated against the `AuthService` on every start (`validate`, `:179`). |
| `IdentityProvider::sign` | `core/conversations/src/service_traits.rs:15-23`, impl `installation.rs:197-213` | Raw Ed25519 over the given bytes, **no domain prefix**. Also used by MLS (openmls prepends `"MLS 1.0 "`) and by keypackage registration (`timestamp_ms u64 LE ‖ key_package`, `extensions/components/src/contact_registry/store.rs:175-183,269`). |
| Registry | `extensions/components/src/http_auth_client.rs:1-6,66` | `GET {base}/v1/account/{addr}` → 200 `sig ‖ payload`, 404 never published. Default base `https://devnet.chat-kc.logos.co`. The server is untrusted by design. |
| Freshness | `AccountRecord::update` (`account/account-log/src/account_record.rs:79`), over the crate-private `compare_log_freshness` (`account_log.rs:351`) | "A longer log is a newer log": a candidate is accepted only as a strict byte-prefix extension; anything else is `Behind`/`Diverged`. No counters, no timestamps. `AccountRecord::new(addr, signed)` + `update(candidate)` is the public way to apply the rule. |

Two facts that shape the design:

1. **The account key cannot sign.** `register_account`
   (`crates/logos-chat/src/logos.rs:237-248`) mints a fresh account, publishes
   one `chat.signer` endorsement, and drops the key. Only the installation key
   survives, inside the running client. Any challenge must therefore be
   signed by the installation key and *linked* to the account through the log.
2. **There is no public signing API.** `ChatClient` exposes `addr()` and
   `installation_name()` only (`crates/generic-chat/src/client.rs:137-144`);
   the `Installation` moves into `Core` at build time. Exposing a
   domain-separated signer is the one change logos-chat needs (§6B).

## 3. Vector specification

### 3.1 `auth_type`

`chat-installation`. (Optionally registered as
`rln_auth_vector::CHAT_INSTALLATION_AUTH_TYPE`; the vocabulary is open, so a
constant is a convenience, not a requirement.)

### 3.2 Challenge message

The gifter wire is one request and one response on
`/logos/rln/membership/1.0.0`; there is no slot for a server-issued nonce. The
challenge is therefore non-interactive and commitment-bound, the same shape
the keycard vector uses (`SHA256("logos/rln/keycard-attest/1" ‖ idc)`):

```
msg := DOMAIN ‖ id_commitment ‖ rate_limit

DOMAIN        = b"logos:rln:gifter:chat-installation:1\0"   (38 bytes, NUL-terminated)
id_commitment = 32 bytes, as carried in RlnGifterRequest.identity_commitment
rate_limit    = u64 LE, the SETTLED rate (VerifyRequest.rate)
```

- The domain tag follows the `ACCOUNT_LOG_DOMAIN` convention
  (`"logos:accounts:1\0"`), including the version segment, so a future
  `…:2\0` is a different message space.
- Binding `id_commitment` makes the signature useless for any other
  commitment. Binding `rate_limit` stops an intermediary from re-submitting
  the same payload at a different rate. The gifter settles the rate (default,
  then operator cap) *before* calling the verifier, so `VerifyRequest.rate` is
  exactly the value that will be registered; the producer must sign the rate
  it is going to request (§4.3).
- No nonce or timestamp: a replayed payload yields the same nullifier, which
  the gifter has already spent, so replay buys nothing. This matches both
  reference vectors.
- Cross-protocol check against the installation key's other uses: MLS
  payloads carry the `"MLS 1.0 "` label; keypackage payloads are
  `u64 LE timestamp ‖ key_package`. A gifter signature replayed as a keypackage
  upload would decode to a timestamp of `"logos:rl"` as LE u64 (≈ 7.9 × 10¹⁸
  ms — far future) followed by garbage that is not a key package; a keypackage
  signature replayed here would have to begin with our 38-byte domain tag,
  which a chat client never signs as a timestamp. Neither direction yields a
  valid artefact on the other side.

### 3.3 Payload (`authentication_payload`)

Binary, fixed header, log appended:

```
offset  size   field
0       1      version        = 0x01
1       32     account_addr   the account verifying key (AccountAddr bytes)
33      32     signer_key     the installation verifying key
65      64     signature      Ed25519(installation_signing_key, msg)
129     2      log_len        u16 LE
131     n      signed_log     SignedAccountLog::to_bytes()  (sig(64) ‖ payload)
```

Embedding the log makes verification self-contained: the verifier does not
have to reach the registry inside the gifter's 30 s verifier budget on its
single serialized worker, and the gifter does not inherit the registry's
availability. Freshness is restored by an optional online re-check (§3.4
step 6).

Size: a one-endorsement log is `64 + (17 + 3 + 1 + 11 + 1 + 32) = 129` bytes,
so the whole payload is `131 + 129 = 260` bytes. The request frame is capped at
`MAX_RPC_SIZE = 4096` bytes (`rln-gifter-module/src/server.rs:40`), of which
the other fields use well under 100. Logs with a handful of entries still fit
with room to spare; the producer MUST refuse to build a payload whose
`signed_log` exceeds 3 584 bytes (4096 − 512 headroom) and the verifier MUST
reject one (it would never have arrived anyway).

### 3.4 Verifier algorithm (`verify_auth`)

Inputs: `VerifyRequest { auth_type, payload_hex, id_commitment_hex, rate, config }`.

1. Hex-decode `payload_hex`; check `version == 1` and that lengths add up
   exactly (no trailing bytes). Any structural problem → `Verdict::reject`.
2. `AccountAddr::try_from(&account_addr)` — rejects non-canonical and
   small-order keys. `Ed25519VerifyingKey::from_canonical_slice(&signer_key)`
   likewise. Failure → reject.
3. `SignedAccountLog::from_bytes(signed_log)?.verify(&addr)?` → `AccountLog`.
   Failure (bad signature, malformed entries, invalid `Remove`) → reject.
   This is the step that ties the installation to the account: the log is
   signed by the account key, and the account key *is* the address.
4. `signer_key ∈ log.ed25519_keys_for("chat.signer")` and
   `signer_key ∉ log.revoked_ed25519_keys_for("chat.signer")`, else reject
   with a reason that distinguishes `not endorsed` from `revoked`.
5. Rebuild `msg` from `id_commitment_hex` (must decode to 32 bytes) and
   `rate`; `signer_key.verify(msg, signature)` (`verify_strict`). Failure →
   reject.
6. **Optional online re-check** (only if `config.registry_url` is set):
   `GET {registry_url}/v1/account/{addr}` with a short timeout
   (`config.registry_timeout_ms`, default 5 000).
   - 200: build `AccountRecord::new(addr, embedded)` and call
     `.update(SignedAccountLog::from_bytes(body)?)`. If the outcome is
     `Updated` (a verified strict extension), re-run step 4 on the returned
     record's log — this is how a revocation newer than the client's copy is
     honoured. `Unchanged` (identical, behind, diverged) or a bad signature
     is ignored: the server is
     untrusted and cannot downgrade a log the account signed.
   - 404, timeout, 5xx: if `config.registry_required == true` → reject
     (`registry unavailable`); otherwise continue on the embedded log.
7. `Verdict::accept(nullifier)`. The nullifier is the lowercase hex of
   `account_addr` by default (one membership per account), or of `signer_key`
   when `config.nullifier == "installation"`. The gifter namespaces it as
   `chat-installation:<hex>` and persists it on successful registration.

Error discipline follows `eth-auth-module`: an operator mistake (unparseable
`config`, a non-URL `registry_url`, an unknown `nullifier` value) is `Err` →
`{"error"}` envelope; anything attacker-controlled is a `reject` verdict.

### 3.5 `config` schema

```json
{
  "registry_url":        "https://devnet.chat-kc.logos.co",   // optional; enables step 6
  "registry_required":   false,                               // optional; default false
  "registry_timeout_ms": 5000,                                // optional
  "nullifier":           "account"                            // optional; "account" | "installation"
}
```

An empty or absent `config` is valid: offline verification against the
embedded log, account-address nullifier.

## 4. Producer specification

### 4.1 Where it lives

The installation signing key exists only inside the running chat client, so
the producer is `chat_module` itself: it implements the
`rln_auth_vector` producer contract and is named as `auth_provider` by the
requesting application. No separate producer module is needed.

### 4.2 `chat_module.produce_auth(args_json) -> json`

In: `ProduceRequest { auth_type: "chat-installation", id_commitment_hex, args? }`.
Out: `{"payload_hex": …}` or `{"error": …}` (via `rln_auth_vector::dispatch_produce`).

Steps:

1. Parse; `id_commitment_hex` must decode to 32 bytes.
2. Determine the rate to sign (§4.3).
3. `with_client(|c| c.sign_gifter_challenge(&id_commitment, rate))` → the
   installation signer key, the account address, and the signature over
   `msg` (§6B describes this `ChatClient` method).
4. Fetch the current `SignedAccountLog` for the account from the registry the
   module already uses (`HttpAuthClient` implements `AccountProvider::fetch`;
   `extensions/components/src/http_auth_client.rs:138`). Verify it locally
   with `verify(&addr)` and confirm the signer is live under `chat.signer`
   before embedding — a client whose endorsement has been revoked should
   learn that here, not from the gifter.
5. Encode the payload (§3.3) and return it as lowercase hex.

Failures are `{"error": …}` — not initialised, registry unreachable (the
producer has no fallback copy of the log unless it caches one at `init`),
oversize log.

### 4.3 The rate the producer signs

`VerifyRequest.rate` is the settled rate: `request.rate_limit` if the
requester sent one, else the gifter's default (100), then capped by the
operator's `maxRateLimit`. The producer must sign the same number or the
signature will not verify. `rln_gifter_module.request` forwards `authArgs`
verbatim to the producer (as a JSON **string**, not an object — the RLN
membership module stringifies it), so the convention is:

- the requesting application passes `authArgs` = `{"rate": <u64>}` equal to
  the `rate` it passes to `request`; absent → the producer signs 100.
- a mismatch is a normal rejection (`signature verification failed`) and the
  application retries with the right rate. This is the same contract the
  keycard producer has with its `authArgs`.

(Having `rln_gifter_module` inject the settled rate into `ProduceRequest`
would remove this coordination, but it is a contract change to
`rln_auth_vector` and out of scope here.)

### 4.4 Requester wiring

Through the RLN membership module's flat `RegistryOptions`:

```
auth_type:     "chat-installation"
auth_provider: "chat_module"
auth_args:     {"rate": 100}
```

or directly on `rln_gifter_module.request`: `authType`, `authProvider`,
`authArgs`.

## 5. Operator wiring and budgets

```json
"authVerifiers": {
  "chat-installation": {
    "module": "chat_auth_module",
    "config": { "registry_url": "https://devnet.chat-kc.logos.co" }
  }
}
```

The host application declares `chat_auth_module` in its `metadata.json`
dependencies so it is installed and loaded; `serve` opens its verifier client
on the owner thread at start and fails loudly if the module is missing.

Budgets:

| Limit | Value | This vector |
|---|---|---|
| Request frame | 4 096 B | ≈ 260 B typical, ≤ 3 584 B log enforced |
| Verifier call | 30 s, single worker | Offline path: a few Ed25519 verifies, sub-millisecond. Online re-check bounded by `registry_timeout_ms` (default 5 s). |
| Replay | nullifier store | `chat-installation:<account hex>` |

## 6. Implementation roadmap

Order matters: C depends on B, and C's host repo is behind.

### Prerequisite — `chat_module` identity pin

`logos-co/logos-chat-module` 0.2.1 pins libchat at `5c55c2e` (2026-07-26, 56
commits behind `d4e20ad`) through a `doomcrack/libchat` fork patch. At that
rev identity is `TestLogosAccount` + `DelegateSigner`, seeds derived in
`rust-lib/src/identity.rs` from a `keystore_signer` signature; neither type
exists on current main, which uses `Installation` and the `chat.signer`
context. Until the module moves past the identity-model rewrite there is no
installation key for `produce_auth` to sign with. This is the gating item and
belongs to the chat team.

(The local `logos-workspace/repos/logos-chat-module` checkout is the retired
C++ plugin; the Rust module needs a fresh clone.)

### A. `logos-rln-gifter` — `rust/chat-auth-module` (verifier)

Can be built and unit-tested now, independently of the chat side.

- Copy `rust/eth-auth-module/{metadata.json,CMakeLists.txt,flake.nix,rust-lib/Cargo.toml}`;
  rename to `chat_auth_module`, trait `ChatAuthModule`, `verify_auth` only.
- `rust-lib/src/lib.rs`: `ChatInstallationVector: AuthVector` implementing
  §3.4; `verify_auth` is one line of `dispatch_verify`; `logos_module_install`.
- Dependencies: `account-log` and `account` (alias `logos-account`) as
  rev-pinned git deps from `https://github.com/logos-messaging/logos-chat`
  (both are standalone crates with their own `Cargo.lock`; neither is on
  crates.io), `rln_auth_vector`, `hex`, `serde_json`, and a minimal blocking
  HTTP client (`ureq`) behind the online re-check. Note both account crates
  use `<[u8]>::as_array()` and need a recent stable toolchain.
- Put the registry fetch behind a small trait so tests can inject logs.
- Tests (pure `cargo test` in `rust-lib`, no host; `lp` stubs itself when the
  FFI is absent):
  - accept: fresh account + installation, payload built in-test, nullifier =
    account hex; `nullifier: "installation"` switches it;
  - reject: wrong commitment; wrong rate; signer not endorsed; signer
    revoked (log with `Remove`); log signed by a different key; account
    address not canonical; truncated / trailing bytes; oversize log;
  - online: stale embedded log + fetched extension that revokes → reject;
    fetched log diverged → ignored, embedded verdict stands; registry down
    with `registry_required` true → reject, false → accept;
  - operator error: `nullifier: "bogus"` → `Err`.
- README: a bullet under "Reference vectors" pointing here.

### B. `logos-chat` — expose a domain-separated signer

- `crates/generic-chat/src/client.rs`: add

  ```rust
  pub struct GifterChallengeSignature {
      pub account: AccountAddr,
      pub signer: Ed25519VerifyingKey,      // installation key
      pub signature: Ed25519Signature,
  }
  pub fn sign_gifter_challenge(&self, id_commitment: &[u8; 32], rate: u64)
      -> GifterChallengeSignature
  ```

  which builds `msg` (§3.2) and signs it with the installation key held in
  `Core`. A specific method is preferred over a general
  `sign_with_installation(domain, payload)`: it keeps "what can this key
  sign" enumerable in one place. `IdentityProvider::sign` and its MLS /
  keypackage callers are untouched.
- Unit test: the signature verifies under the key `installation_name()`
  displays; the message begins with the domain tag.

### C. `logos-chat-module` — `produce_auth`

- `rust-lib/chat_module.lidl`: `method produce_auth(args_json: tstr) -> tstr`.
  String in / string out matches the gifter convention; a LIDL `result`
  would marshal as `LogosResult` and null through the UI bridge.
- `rust-lib/src/actions.rs`: §4.2, using the existing `with_client` helper
  and an `HttpAuthClient` for the registry URL `ContactRegistry` already uses.
- `rust-lib/Cargo.toml`: add `rln_auth_vector` (rev-pinned git dep).
- No new `metadata.json` dependency: the requester names the provider at
  runtime.

### D. End-to-end

`logos-rln-e2e-v030/scenarios/delivery-rln-gifter` with the verifier
configured and `chat_module` as `authProvider`: first request from an account
succeeds; a second request from the same account (any commitment) is refused
with the nullifier reason; a request after the installation is revoked in
the registry is refused once `registry_url` is set.

## 7. Where sybil resistance plugs in

Nothing above costs anything to obtain, so this vector must be paired with a
scarcity signal before an open gifter uses it. The design leaves three hooks,
all reachable through verifier `config` without touching the wire:

- **Account-log attestations.** The log accepts `EntryData::Text` under any
  context (`account.update().endorse_text(ctx, value)`). A policy such as
  "accept only accounts carrying an `rln.voucher` entry whose value is a
  signature by an issuer in `config.voucher_issuers`" is a few lines in step
  4b of the verifier. The append-only log gives the issuer a tamper-evident
  place to publish and the account a way to revoke.
- **Registry-side signals.** With `registry_url` set the verifier already
  fetches the account; a registry that records first-seen time or
  rate-limits account creation can expose that, and `config.min_account_age`
  becomes a check.
- **Stacked vectors.** The gifter accepts several `authVerifiers`; an
  operator can keep `chat-installation` for identity and require a second,
  scarce credential (keycard, Eth allowlist, a future PoW vector) by
  composing at the application layer, or a combined vector can require both
  payloads in one.

Whichever is chosen, the nullifier stays the account address: the sybil
layer decides *which* accounts may claim, the identity layer guarantees each
claims once.
