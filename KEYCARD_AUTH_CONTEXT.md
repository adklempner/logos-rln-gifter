# Handoff: pluggable Keycard attestation auth for the LEZ RLN gifter

Task: add a second pluggable authentication method to **this repo** (the
standalone, LEZ-facing `logos-rln-gifter`), alongside the existing
`eth-allowlist` EIP-191 auth: a client proves it holds a **genuine Keycard**
and each card can claim exactly **one** gifted membership. The gifter stays a
centralized service — it verifies the attestation itself, tracks consumption
itself, and registers on the LEZ RLN program on the client's behalf exactly as
it does today. **No stealth addresses, no zone** — those belong to a separate
experimental branch (see "Reference implementations" below, which you will
cherry-pick from while leaving the stealth parts behind).

## Repo map

Target (LEZ-based, what you modify):

| Repo | Role |
|---|---|
| `/Users/arseniy/Waku/Logos/logos-rln-gifter` | This repo. Nim libp2p protocol `/logos/rln/membership/1.0.0` (LIP-158) + cbind C surface. |
| `/Users/arseniy/Waku/Logos/logos-libp2p-module` | logoscore host module (`src/gifter.cpp`): exposes `rlnGifterServe` / `rlnGifterRequest`, drives the cbind, does the on-chain call. |
| `/Users/arseniy/Waku/Logos/logos-lez-rln` | LEZ RLN program + `logos-rln-module` (the `register_member` provider the host calls). **Unchanged by this task.** |

Reference (branched copies under `/Users/arseniy/Waku/Logos/rln-zone/`, where
keycard auth is ALREADY implemented end-to-end but entangled with
stealth/zone work — port the keycard parts, skip the stealth parts):

| File | What to take | What to skip |
|---|---|---|
| `rln-zone/logos-rln-gifter/src/rln_gifter/keycard_attest.nim` | **All of it** (172 lines). Self-contained verifier: TLV parse, CA recovery, low-S normalization, challenge verify, nullifier. Uses only `secp256k1` + `nimcrypto`, both already in this repo's `.nimble`. | Nothing — copy verbatim. |
| `rln-zone/logos-rln-gifter/tests/test_keycard_attest.nim` | **All of it.** Golden known-answer vectors from keycard-go (see below). Add to `test_all.nim`. | Nothing. |
| `rln-zone/logos-rln-gifter/src/rln_gifter/rpc.nim` | The one-line constant `KeycardAttestAuthType* = "keycard-attestation"`. | The stealth fields (`schemeId`, `commitmentX/Y`, `ephemeralPublicKey`, `viewTag`). **The wire format needs no other change** — `authenticationType` / `authenticationPayload` are already generic. |
| `rln-zone/logos-rln-gifter/src/rln_gifter/protocol.nim` | `KeycardAttestAuth` type (`trustedCAs` + `consumedNullifiers` HashSets), `newKeycardAttestAuth` (hex normalization), the `KeycardAttestAuthType` branch in `handleRequest` (parse → boundChallenge → verify → consumed check → mark consumed after successful registration), the extra `keycardAuth` param on `RlnGifter.new`. | The entire `commitmentX.len == 32` stealth-relay branch; the `nullifier`/`stealth` params added to `RegisterMemberHandler` (see "Handler signature" below). |
| `rln-zone/logos-rln-gifter/cbind/cbind_gifter.nim` + `cbind/libp2p_gifter.h` | Serve-config parsing of `"trustedCAs": [...]` → `newKeycardAttestAuth`; client-side: an `"attestation"` hex field in the request JSON that, when present, sets `authenticationType = "keycard-attestation"` and puts the raw TLV bytes in `authenticationPayload` (takes precedence over `authKey` EIP-191 signing). | The `nullifierHex`/`stealthJson` params added to the register callback signature, and all `commitmentX...` request fields. |
| `rln-zone/logos-libp2p-module/src/gifter.cpp` | `trustedCAs` passthrough in the `rlnGifterServe` args JSON. | The `register_stealth_device` branch and the nullifier threading into `rln.register_member`. |
| `rln-zone/logos-rln-mix-sim/docker/testnet/mix_e2e/mount_gifter.sh` | Working example of mounting with a pinned CA: `{"config":..., "wallet":..., "trustedCAs":["<hex>"]}`. | — |

Rust mirrors of the same verifier (useful as spec cross-checks, byte-identical
semantics, same golden vectors):
- `rln-zone/logos-rln-stealth/keycard/src/attest.rs` — the original; also has
  the **client/card side** (capturing the TLV over APDU) and the `keycard-rln`
  CLI (`src/bin/keycard-rln.rs`, `attest` subcommand).
- `rln-zone/rln-zone-sequencer/core/src/attest.rs` — consensus-vendored copy
  with typed errors and a full mint-your-own-attestation test harness
  (`core/tests/attest_tests.rs`) showing how to fabricate valid attestations
  from k256 `SigningKey`s for tests.

## The attestation scheme (spec)

A Keycard's IDENTIFY_CARD command returns a TLV over a caller-supplied
32-byte challenge:

```
A0 {                              (signature template)
  8A <98 bytes>                   (certificate = ident_pub(33) || ca_sig(65))
  30 <DER ECDSA signature>        (card's signature over the challenge)
}
```

All secp256k1 (no X.509, no P-256). Verification, in order:

1. **Parse** the TLV (`A0` → `8A` cert must be exactly 98 bytes → first `30`
   DER sequence). Length forms supported: short, `0x81`, `0x82`.
2. **CA check (genuine card)**: `ca_sig` is a 64-byte compact recoverable
   signature + 1-byte recovery id over the prehash `SHA256(ident_pub)`.
   Recover the pubkey, compress to 33 bytes, compare against the trusted CA
   set. This proves the card's identity key was certified by the vendor CA.
3. **Challenge binding**: the DER sig is by `ident_pub` over the **raw
   32-byte challenge** (the card signs it un-rehashed — verify against the
   prehash, do not hash again). JavaCard ECDSA emits **high-S** signatures;
   normalize to low-S first or libsecp256k1 rejects them.
4. **Nullifier**: `keccak256(ident_pub)` — the once-per-card claim token.
   Stable across card factory resets (the identity key is burned in), so a
   wiped card cannot re-claim.

The challenge is **deterministically bound to the RLN identity commitment**:

```
challenge = SHA256("logos/rln/keycard-attest/1" || id_commitment)   (33 + 32 bytes)
```

No server nonce. That makes attestations replayable-by-design *for the same
commitment* — harmless, because (a) the commitment is only usable by whoever
holds the identity secret, and (b) the nullifier one-shot means a captured TLV
cannot claim a second membership anyway.

Trust anchor — Status production IdentApplet CA (compressed hex):

```
029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c
```

Golden known-answer vector (from keycard-go `types/certificate_test.go`,
signed by keycard-go's **test** CA — already embedded in the reference test
file):

```
TLV       = a081ab8a620365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a11188ada267db3312a84e1be27c01c736a89da7a1fe4f7e90ce297e74f00008e2bfdb06058374abfc1c026386d16ead7bbc19bc0645d2e7acf7b953169bbc1ac0130450220364c5ca937b7ca42861978f086d206cc569ef0bb2ea4c7de08929c2fcca7434d022100c87699ce4f977e6a7a4800343db9b6842b91ca873e56dfe3327d19a2d01af14e
challenge = 63acd6e02a8b5783551ff2836a9cbdf237c115c3ff018b943f044e6a69b19fe7
test CA   = 02fc929321aa94fea085b166994aa66590116252cf0235a03accaa2c8ab4595de5
ident_pub = 0365c18485fe7018e11cb992011426803aa8e843c63aab9657aed7d3ee4b85a62a
```

## Server flow (what the pluggable auth does)

Mirroring the existing `EthAllowlistAuth` pattern in `protocol.nim`:

1. Request arrives with `authenticationType = "keycard-attestation"` and
   `authenticationPayload = <raw IDENTIFY_CARD TLV bytes>`.
2. `parseAttestation(payload)` → reject malformed.
3. `challenge = boundChallenge(request.identityCommitment)`.
4. `verifyAttestation(att, trustedCAs, challenge)` → rejects untrusted CA or
   a signature not bound to *this* commitment; returns the nullifier.
5. Reject if nullifier already in `consumedNullifiers` ("card already used").
6. Delegate to `RegisterMemberHandler` (unchanged: the host registers the
   commitment on LEZ with the gifter's funded wallet via
   `logos-rln-module`'s `register_member` — same paid path as eth-allowlist).
7. **Only after successful registration**, add the nullifier to
   `consumedNullifiers` (same ordering the eth path uses for `consumed`).

### Handler signature

The branched copy widened `RegisterMemberHandler` with
`nullifier: Option[seq[byte]]` and `stealth: Option[string]` because the
*zone* consumed them on-chain. LEZ has no nullifier concept — keep the
handler at `(identityCommitment, rateLimit)` unless you decide to thread the
nullifier out to the host for persistence (see next section). Either is fine;
threading it only to ignore it is noise.

## Known gaps to address (the reference implementation has these too)

- **Consumed-nullifier persistence.** `consumedNullifiers` is an in-memory
  HashSet: a gifter restart forgets every claim, letting each card claim once
  per restart. The eth-allowlist has the same flaw but its allowlist is small
  and operator-curated; for open genuine-card claiming this matters. Persist
  the set (append-only file or the host's storage via the callback — your
  call), and note that a single shared set assumes a single gifter instance.
- **Check/consume race.** The nullifier is checked before the `await` on the
  registration handler and consumed after it. Two concurrent requests with
  the same card interleave past the check and both register. The host drain
  queue in `gifter.cpp` is sequential, which masks this today, but the
  protocol layer shouldn't rely on that: mark the nullifier as
  pending/consumed *before* delegating and roll back on registration failure,
  or serialize keycard requests.
- **Rate-limit choice is client-controlled** (`request.rateLimit`, default
  100). For a one-per-card free grant you may want the gifter to clamp or fix
  the rate limit rather than let a card claim at 600.

## Client side (how the TLV is produced)

The client computes its RLN `id_commitment` locally (identity secret never
leaves the client), derives `challenge = boundChallenge(id_commitment)`, and
runs IDENTIFY_CARD against the physical card with that challenge (pairing key
+ index required). Tooling that already does this:

- `keycard-rln` CLI (`rln-zone/logos-rln-stealth/keycard/src/bin/keycard-rln.rs`):
  capture + `attest <tlv> <id_commitment>` offline verify.
- The Basecamp app's `rlnGifterRequest` path (real card) — the branched
  `cbind_gifter.nim` shows the request JSON: pass `"attestation": "<tlv hex>"`
  instead of `"authKey"`, and the client sends
  `authenticationType="keycard-attestation"`.
- For CI, mint synthetic attestations with a throwaway CA key: see
  `rln-zone-sequencer/core/tests/attest_tests.rs` (`mint_attestation`) — CA
  `sign_prehash_recoverable` over `SHA256(ident_pub)`, card `sign_prehash`
  over the bound challenge, DER-encode, wrap in `8A`/`A0` TLV — then mount
  the gifter with that CA in `trustedCAs`.

## What does NOT change

- Protobuf wire format (`rpc_codec.nim`) — `authenticationType` /
  `authenticationPayload` already carry arbitrary auth methods.
- The EIP-191 auth path, and coexistence: a gifter can mount with allowlist
  auth, keycard auth, or both (`RlnGifter.new(handler, auth, keycardAuth)`).
- The LEZ RLN program and `logos-rln-module`'s `register_member` — the
  gifter's wallet funds a normal paid registration exactly as today.
- The no-close stream discipline in `protocol.nim`/`client.nim` (yamux
  use-after-free workaround) — don't "fix" it.
