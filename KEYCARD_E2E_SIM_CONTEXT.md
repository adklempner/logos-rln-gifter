# Handoff: e2e-testing keycard attestation auth in the mix sim (alongside EIP-191)

For the agent working on `logos-rln-mix-sim`. The gifter now supports a second
pluggable auth method — **keycard attestation** — implemented in
`logos-rln-gifter` (branch `feat/keycard`, working tree) and plumbed through
`logos-libp2p-module` (working tree). Both auths can be mounted **at the same
time**; the goal is an e2e run where some clients onboard via EIP-191 exactly
as today and at least one client onboards via a (synthetic) keycard
attestation, plus the negative paths.

## What changed (interface surface you drive from the sim)

`rlnGifterServe` args JSON (host module → cbind, `gifter.cpp`):

| key | type | meaning |
|---|---|---|
| `config`, `wallet` | string | unchanged |
| `allowlist` | array | unchanged — EIP-191 auth, mountable together with keycard |
| `trustedCAs` | array | **new** — compressed secp256k1 CA pubkeys (hex, 0x-optional). Non-empty ⇒ keycard auth enabled |
| `consumedNullifiersPath` | string | **new, optional** — append-only file (inside the gifter container) persisting consumed card nullifiers across gifter restarts |

`rlnGifterRequest` args JSON:

| key | type | meaning |
|---|---|---|
| `gifterPeerId`, `gifterMultiaddr`, `config`, `seed`, `rate` | | unchanged, all still required (`seed` is still required — identity is derived from it exactly as in the eth path) |
| `authKey` | string | unchanged — EIP-191 path |
| `attestation` | string | **new, optional** — hex IDENTIFY_CARD TLV. When present the client sends `authenticationType="keycard-attestation"`; **takes precedence over `authKey`** |

Server-side semantics (protocol.nim):

- Verify TLV → recover CA → must be in `trustedCAs` → verify card signature
  over `challenge = SHA256("logos/rln/keycard-attest/1" || id_commitment)`.
- **One membership per card**: nullifier = `keccak256(ident_pub)`; consumed on
  successful registration, *reserved before* the registration await (two
  concurrent requests with the same card can't both pass), rolled back if
  registration fails.
- **Rate clamp**: keycard-authenticated requests are clamped to rate 100
  (`maxRateLimit` default) — a request with `rate: 600` registers at 100.
- EIP-191 path byte-identical to before; both auths coexist independently.

## Build wiring — no git push needed

`docker/build_lgx_linux.sh` rsyncs the **local working trees** of
`logos-rln-gifter` and `logos-libp2p-module` (siblings under `~/Waku/Logos`)
into the Docker context. The keycard changes are in those working trees
(gifter: branch `feat/keycard`, currently uncommitted; module: uncommitted on
its current branch). **Rebuild the `.lgx` before running** — the checked-in
`docker/lp2p-out/libp2p_module.lgx` predates keycard auth:

```bash
docker/build_lgx_linux.sh
```

Sanity check the artifact carries the new code:
`grep -ac keycard-attestation <extracted libp2p.dylib/so>` > 0.

## Minting synthetic attestations (no physical card in CI)

`logos-rln-gifter/tools/mint_attest.py` — pure python, zero deps (same style
as the sim's `keys.py`), mirrors the rln-zone-sequencer `mint_attestation`
harness. **Its output is verified against the gifter's actual Nim verifier**
(positive + tampered-challenge + untrusted-CA cases) — if the gifter rejects a
minted TLV, the bug is in the wiring, not the tool.

```bash
# one-time fixtures: a throwaway CA and one "card" key per keycard client
CA_PRIV=1111...11   # any 64-hex; NOT the Status production CA
CARD_PRIV=2222...22 # one per client; same card twice = the reuse negative test
CA_PUB=$(python3 tools/mint_attest.py pub "$CA_PRIV")

# per run, after deriving the client's id_commitment (see below):
python3 tools/mint_attest.py mint "$CA_PRIV" "$CARD_PRIV" "$ID_COMMITMENT"
# -> {"tlv": "...", "challenge": "...", "ca_pub": "...", "ident_pub": "...", "nullifier": "..."}
```

`tlv` goes into the request's `attestation` field; `nullifier` is what the
gifter logs/rejects on reuse (handy for asserts). Deterministic: same inputs →
same TLV, so fixtures can be pre-minted if the seed is fixed.

## The chicken-and-egg, and how to solve it

The attestation is **bound to the id_commitment**, but `rlnGifterRequest`
derives the identity from `seed` internally. Fortunately
`generate_identity(seed)` is deterministic (`rln::seeded_keygen`), so:

1. Pick the seed (random per run is fine).
2. Derive the commitment on the node first — same module the request path
   uses: `call "$s" "$RLN_MOD" generate_identity "$seed"` → parse
   `id_commitment` from the result JSON.
3. Mint: `tools/mint_attest.py mint $CA_PRIV $CARD_PRIV $id_commitment`.
4. `rlnGifterRequest` with the same `seed` + `"attestation":"<tlv>"` (no
   `authKey`) — it re-derives the same identity and the binding matches.

**Byte-order caveat**: use the `id_commitment` hex string exactly as
`generate_identity` returns it (it's little-endian field-element bytes; the
whole pipeline — cbind, wire, challenge — treats it as opaque 32 bytes, so
pass it through verbatim, never re-encode).

## Suggested e2e matrix (orchestrate.sh gifter section)

Mount once, with both auths (relay1):

```json
{"config":"$CONFIG_ACCT","wallet":"$HOLDING_ACCT",
 "allowlist":[... 3 of the 4 client addresses ...],
 "trustedCAs":["$CA_PUB"],
 "consumedNullifiersPath":"/testnet/consumed_nullifiers.txt"}
```

Happy path: 3 clients onboard via `authKey` (unchanged flow), 1 client (e.g.
receiver2 — drop its address from the allowlist to prove keycard alone
suffices) onboards via `attestation`. Then the normal mix exchange must pass
as today — a gifted membership is a gifted membership regardless of auth.

Negatives worth scripting (each is a distinct server error string):

| case | how | expected failure message (client `error` / gifter log) |
|---|---|---|
| card reuse | second request, fresh seed, same `CARD_PRIV` | `card already used: <nullifier>` |
| untrusted CA | mint with a different CA priv | `attestation verification failed: attestation CA is not trusted: ...` |
| wrong binding | mint against commitment A, request with seed deriving B | `attestation verification failed: challenge signature does not verify` |
| garbage TLV | `"attestation":"deadbeef"` | `attestation parse failed: ...` |
| keycard sent, no keycard auth mounted | omit `trustedCAs` from serve | `unsupported authentication_type: 'keycard-attestation'` |
| rate clamp | request `rate: 600` with attestation | succeeds; gifter logs `clamping keycard grant rate limit`; `get_membership` shows rate 100 |
| persistence | remount/restart gifter, retry used card | still `card already used` (only with `consumedNullifiersPath` set; without it the set is in-memory and a restart forgets — that's the point of the test) |

Existing eth negatives (NEG=1/NEG=2) must keep passing unchanged.

Gifter log lines to grep (`docker logs relay1`):

- `RLN gifter keycard attestation auth enabled` (mount, `cas=N persisted=true/false`)
- `RLN gifter registration succeeded` (count = eth clients + keycard clients)
- `clamping keycard grant rate limit`

## What does NOT exist here (vs the rln-zone branch)

The rln-zone sim's keycard flow (`keycard_gifter_onboard`, `derive-stealth`,
`commitmentX/Y`, `identitySecret`, `keycard_bridge.sh`) is the **stealth**
variant — none of those request fields exist in this port and the gifter will
ignore/reject them. Here the keycard client is identical to the eth client
except `attestation` replaces `authKey`. The rln-zone `mount_gifter.sh` is
still the right *mount* reference (its `trustedCAs` JSON shape is what this
port accepts).

For a future real-card demo (not CI): mount with the Status production CA
`029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c` and
capture the TLV with the `keycard-rln` CLI
(`rln-zone/logos-rln-stealth/keycard`, `attest` subcommand) using the bound
challenge for the derived commitment — pairing key + slot index required.

## Verification status of the pieces you're building on

- Gifter unit tests: 17/17 (`nim c -r tests/test_all.nim`), incl. the
  keycard-go golden vector.
- Full combined cbind (`mix-rln-spam-protection-plugin#cbind-rln` with the
  working tree overridden in) compiles; `logos-libp2p-module#default` builds
  and both dylibs contain the new symbols/strings.
- `tools/mint_attest.py` selftest checks keccak + secp256k1 against the sim's
  own committed key fixtures; its minted TLVs verify against the gifter's
  Nim verifier.
