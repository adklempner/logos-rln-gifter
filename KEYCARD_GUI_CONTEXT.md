# Handoff: gifted RLN registration via Keycard attestation, for the Basecamp membership-management GUI

Task: the membership-management module currently registers RLN memberships via
the **base path** — the user's funded wallet submits a `register_member`
transaction on LEZ. Add a second path: **dial a gifter node over libp2p and
register via Keycard attestation** — the user proves they hold a genuine
Status Keycard, the gifter pays for and submits the registration, and the user
never funds or signs a transaction. One gifted membership per physical card.

Everything below the GUI layer is **already built and e2e-verified** (including
against a real retail Keycard on 2026-07-15): the gifter protocol + keycard
auth, the host-module client call, and capture tooling. The GUI work is
orchestration + UX around one module call.

## Repo map (all local working trees; keycard branches partly unpushed)

| Repo | Branch | Role |
|---|---|---|
| `/Users/arseniy/Waku/Logos/logos-rln-gifter` | `feat/keycard` | Protocol `/logos/rln/membership/1.0.0` (LIP-158) + keycard verifier (`src/rln_gifter/keycard_attest.nim`) + `tools/mint_attest.py` synthetic minter |
| `/Users/arseniy/Waku/Logos/logos-libp2p-module` | working tree | Host module `src/gifter.cpp`: `rlnGifterRequest` / `rlnGifterServe` on `libp2p_module` |
| `/Users/arseniy/Waku/Logos/logos-rln-mix-sim` | `feat/keycard` | **Canonical working client reference**: `docker/testnet/mix_e2e/orchestrate.sh` — the `dest` node onboards exactly this way (search "onboarding via keycard attestation") |
| `/Users/arseniy/Waku/Logos/rln-zone/logos-rln-stealth` | — | `keycard/capture/` (Go `kc-capture`, PC/SC TLV capture) and `keycard-rln` CLI (Rust offline verifier) |

Sibling docs in this repo: `KEYCARD_AUTH_CONTEXT.md` (the attestation scheme
spec + server-side verification, byte-level), `KEYCARD_E2E_SIM_CONTEXT.md`
(the sim e2e matrix). Read the scheme section of the former before touching
challenge/TLV bytes.

> **Build caveat:** the keycard work in `logos-rln-gifter` and
> `logos-libp2p-module` lives in local working trees (not fully pushed). Any
> build of the libp2p module for the GUI must come from these trees. A stale
> module **silently drops the `attestation` request field** — the failure mode
> is a confusing `unsupported authentication_type` or generic auth error, not
> a crash. The sim guards against this by grepping the built artifact for the
> literal string `keycard-attestation`; do the same if you ship a prebuilt.

## The one call the GUI makes

`rlnGifterRequest` on `libp2p_module` (same invocation mechanism the GUI
already uses for the rln module's base path). Args JSON:

| field | type | notes |
|---|---|---|
| `gifterPeerId` | string | gifter's libp2p peer id (GUI input field) |
| `gifterMultiaddr` | string | gifter's dialable multiaddr (GUI input field) |
| `config` | string | the RLN config account — same one the base path uses |
| `seed` | string | identity seed; `generate_identity(seed)` is **deterministic** — the module re-derives the identity from this internally |
| `rate` | int | requested rate limit. **Required.** Keycard grants are clamped server-side to 100 regardless — display the actual value from `get_membership`, not the requested one |
| `attestation` | hex string | the raw IDENTIFY_CARD TLV. Presence of this field selects keycard auth (takes precedence over `authKey`) |
| `authKey` | hex string | EIP-191 path — omit for keycard |

Success result data: `{"leaf_index": N, "id_commitment": "<hex>",
"auth_success": true}`. The call is synchronous with a **180 s internal
timeout** (dial + auth + on-chain registration on the gifter's side) — run it
off the UI thread with a progress state.

**Side effect the GUI must design around:** on success the module **adopts**
the granted identity (`rlnSetIdentity(idSecretHash, leafIndex)` + proof
refresh timer) — it becomes the node's active RLN identity, **overwriting
whatever identity was previously adopted** (e.g. one from a base-path
registration). If the GUI manages multiple memberships, treat "register via
gifter" as also "switch active membership to the new one", and say so in the
UX.

## The flow (order matters — the attestation must be bound to the commitment *before* the request)

1. **Derive the commitment first.** Pick/generate a `seed`, call
   `generate_identity(seed)` on `liblogos_rln_module` →
   `{"id_commitment": "<hex>", "id_secret_hash": "<hex>"}`. Keep the seed; you
   pass the **same seed** to `rlnGifterRequest` (it re-derives — the identity
   secret never goes over the wire, only the commitment).
2. **Compute the bound challenge:**
   `challenge = SHA256("logos/rln/keycard-attest/1" || idc_bytes)` where
   `idc_bytes` = the hex-decoded 32 bytes of `id_commitment` **verbatim**. The
   hex is an opaque little-endian field element — never re-interpret, reverse,
   or re-encode it. Python reference (from the sim):
   ```python
   hashlib.sha256(b"logos/rln/keycard-attest/1" + bytes.fromhex(idc_hex)).hexdigest()
   ```
3. **Capture the TLV from the card.** IDENTIFY_CARD (INS 0x14) with the
   32-byte challenge as data. **This is a public applet command: no pairing,
   no PIN, no password, plain (unencrypted) channel** — holding the card is
   the credential. Do not add a pairing/PIN step to this path; it's
   unnecessary and was empirically confirmed so on a retail v3.1 card.
   - Go (natural fit if the GUI backend can link Go or shell out):
     `status-im/keycard-go` — `NewCommandSet(io.NewNormalChannel(card))`,
     `cs.Select()`, `cs.IdentifyChallenge(challenge)` → TLV bytes. Working
     ~90-line example: `rln-zone/logos-rln-stealth/keycard/capture/main.go`
     (built binary: `kc-capture <challenge-hex>` → prints `response <tlvhex>`).
   - The TLV is `A0 { 8A cert(98B = ident_pub(33) || ca_sig(65)) , 30 DER sig }`,
     all secp256k1 — but the GUI never parses it; it's an opaque hex blob.
4. *(Optional but good UX)* **Pre-verify offline before dialing:**
   `keycard-rln attest <tlv-hex> <id_commitment-hex>` →
   `{"verified": true, "nullifier": "<hex>"}` against the production CA. Gives
   instant local feedback ("genuine card, correctly bound") and the nullifier,
   without burning a network round-trip. Fails fast on a wrong-card or
   wrong-challenge capture.
5. **Call `rlnGifterRequest`** with `{gifterPeerId, gifterMultiaddr, config,
   seed, attestation, rate}`.
6. **Confirm on-chain** the same way the base path does: poll
   `get_membership(config, id_commitment)` until the leaf is confirmed, check
   `rlnIsReady`. The gifter returns as soon as its transaction lands, but the
   client's proof-readiness still depends on root sync.

## Error surface (exact strings, verify UX against them)

Auth refusals arrive in the result's error message as
`authentication failed: <reason>`:

| reason substring | meaning | suggested UX |
|---|---|---|
| `card already used` | this card's nullifier already claimed a membership at this gifter | "This Keycard has already claimed a membership from this provider" |
| `attestation CA is not trusted` | card's CA not in the gifter's trust set (e.g. dev card vs production gifter) | "Card not recognized by this provider" |
| `challenge signature does not verify` | TLV bound to a different commitment — stale capture, or seed changed between derive and request | re-capture; check the seed didn't change |
| `attestation parse failed` | malformed TLV | re-capture |
| `unsupported authentication_type: 'keycard-attestation'` | the gifter has no keycard auth mounted (no `trustedCAs`) | "This provider doesn't accept Keycard registration" |

Plus non-auth failures: dial/timeout errors, and
`registration failed: <msg>` if the gifter's on-chain call fails.

Semantics worth encoding in the GUI:

- **One membership per physical card, forever per gifter instance**: nullifier
  = `keccak256(ident_pub)` from the card's burned-in identity key — survives
  factory reset. Consumption persists across gifter restarts via its
  `consumedNullifiersPath` file.
- **Retry is safe** with the *same* seed + TLV (nullifier is only consumed on
  success; binding is unchanged). Known edge: if the success reply is lost in
  transit, the registration happened — a retry then reports
  `card already used`. Handle that by checking `get_membership` for the
  derived commitment before declaring failure.
- The attestation is **replayable-by-design for the same commitment** (no
  server nonce) — harmless, since only the seed-holder can use the commitment
  and the nullifier is one-shot. No need to treat the TLV as a secret, but no
  reason to persist it either: capture is cheap, always capture fresh against
  the current commitment.

## Trust anchor + dev/test setup

Status **production** IdentApplet CA (what a real gifter pins; real retail
cards verify against this):

```
029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c
```

For development without a physical card, mint synthetic attestations:

```sh
python3 logos-rln-gifter/tools/mint_attest.py selftest
python3 logos-rln-gifter/tools/mint_attest.py pub  <ca_priv_hex>          # -> CA pubkey
python3 logos-rln-gifter/tools/mint_attest.py mint <ca_priv> <card_priv> <id_commitment>
# -> {"tlv": ..., "challenge": ..., "ca_pub": ..., "ident_pub": ..., "nullifier": ...}
```

Throwaway keys convention:
`logos-rln-mix-sim/docker/testnet/mix_e2e/fixtures/gifter_auth/keycard.env`
(`KC_CA_PRIV=1111…`, `KC_CARD_PRIV=2222…`, etc — NOT for production).

To stand up a live gifter to test against, either run the sim
(`bash docker/testnet/mix_e2e/orchestrate.sh` — 5-node stack against the LEZ
testnet, gifter on relay1), or mount one on any logoscore node with a funded
wallet via `rlnGifterServe` on `libp2p_module`:

```json
{"config": "<config-acct>", "wallet": "<wallet>",
 "allowlist": ["0x..."],                       // optional; both auths coexist
 "trustedCAs": ["<compressed CA pubkey hex>"], // non-empty => keycard auth on
 "consumedNullifiersPath": "/path/consumed_nullifiers.txt"}
```

Mount with your throwaway CA's pubkey for synthetic testing, or the Status
production CA for real-card testing.

## Gotchas checklist

- Same `seed` for `generate_identity` and `rlnGifterRequest`; commitment hex
  passed to the challenge **verbatim**.
- IDENTIFY_CARD needs **no pairing/PIN** — don't reintroduce one.
- `rate` is required in the args; keycard grants clamp to 100 server-side.
- Success **overwrites the node's active RLN identity** — surface this.
- 180 s call timeout — async UI, and on ambiguous failure check
  `get_membership` before telling the user it failed.
- Module build must include the keycard-aware working trees (grep the artifact
  for `keycard-attestation`).
- The card signs the raw 32-byte challenge with a possibly high-S signature —
  the server (and `keycard-rln`) normalize; the GUI never needs to.
