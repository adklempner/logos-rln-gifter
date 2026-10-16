# `pow-claim` — a gifter auth vector backed by logos-blockchain PoW rewards

Design note. Nothing in this document is implemented; §6 says what has to be
built and in which order. Companion to `auth-chat-installation.md`, which
covers the identity-only vector for chat accounts.

## 1. Purpose and threat model

A user runs a logos-blockchain node through basecamp/logoscore. The node's
PoW service mines reward claims. Another module on the same logoscore
instance wants an RLN membership from the gifter. Unlike a chat account, a
PoW claim costs real work, so this vector is a candidate for *sybil
resistance*, not just identification: **one included claim = one
membership**.

What it proves:

- a claim transaction is final on the chain the gifter trusts;
- the reward note that claim minted is owned by, or was spent to, a wallet
  key `K`;
- the requester can obtain a zkSign signature under `K` over a message
  bound to *this* identity commitment, *this* rate ceiling and *this* claim.

What it does not prove:

- possession of `K` in isolation. The signature comes from the node's
  unauthenticated HTTP sign oracle (`POST /wallet/sign/zk`), so the
  credential is "access to the HTTP API of a node whose wallet holds `K`" —
  which is already full wallet compromise for anyone who has it. Bind the
  API to `127.0.0.1`.
- anything the trusted node does not vouch for. There is no light client
  and no inclusion proof on this chain today (§2); the verifier trusts the
  node it is pointed at.

Sybil bound: memberships ≤ PoW rewards won. A miner pays no *marginal* cost
beyond mining they would do anyway; what is bounded is the number of
memberships per unit of hashpower over time (network targets ~1 claim per
block, see §7 for tightening).

## 2. Chain primitives it builds on

All references are to `logos-blockchain/logos-blockchain` at `abd0453d9`.

### 2.1 A claim is not a proof of key possession

| Fact | Where |
|---|---|
| `ClaimPowRewardOp { epoch_nonce: ZkHash, block_hash: Hash, public_key: ZkPublicKey }` | `core/src/mantle/ops/pow.rs:82-90` |
| `Proof = NoOpProof`, opcode `0x40` — the op is **unsigned**; anyone can publish a claim for any `public_key` | `pow.rs:285-288` |
| Puzzle ticket = on-chain nullifier: `PowNullifier = Poseidon2([pk, fr_from_mod_bytes(block_hash), epoch_nonce])` | `pow.rs:93-103` |
| Execution inserts the nullifier, mints `Note::new(epoch_reward, public_key)` as `Utxo { op_id: claim.op_id(), output_index: 0, note }`, emits `PoWRewardClaimed { pow_nullifier, utxo }` | `pow.rs:343-368` |
| The node mines with a **fresh random key per ticket**; the secret keys live only in `PoWServiceState` and are pruned once the claim settles or expires. No FFI/HTTP exports them. | `services/pow/src/tickets.rs ~252-296`, `services/pow/src/service.rs:337-345, 1198-1210, 1295-1327` |
| The node's claim tx is `[Claim×≤32, Transfer, …]`: each Transfer spends the freshly minted notes (multi-signed by the mined keys over the tx hash) and pays `claim_address` | `service.rs:1486-1590` |
| The ledger verifies Transfer signatures against the **input notes' public keys** | `core/src/mantle/ops/transfer.rs:159-164` |
| Default `claim_address` is the wallet's dedicated `PoWClaim` KMS key | `nodes/node/binary/src/cli/config/init.rs:216` (`build_pow_config`) |

So the stable, challengeable identity is `claim_address` (`K`), and the
link from work to `K` is *the spend of the minted note*, which only the
mined key can authorise.

### 2.2 Signing under `K`

| Fact | Where |
|---|---|
| `POST /wallet/sign/zk { tx_hash: 32 B, pks: [ZkPublicKey] } → { sig }` signs **any** 32 bytes: `PayloadEncoding::Zk(tx_hash.to_fr())` with KMS key id `hex(fr_to_bytes(pk))` | `nodes/api-common/src/paths.rs:49`, `services/wallet/src/lib.rs:1130-1155` |
| Only KMS-registered keys; unknown id → `NotRegisteredKeyId` (HTTP 500) | `services/key-management-system/src/backend/preload.rs:85-100` |
| `TxHash::to_fr = Fr::from_le_bytes_mod_order(bytes)` | `core/src/mantle/transactions/hash.rs:122-123` |
| Signature = zkSign Groth16/BN254; compressed proof 128 B (`pi_a 32 ‖ pi_b 64 ‖ pi_c 32`); JSON `{pi_a, pi_b, pi_c}` hex | `kms/keys/src/keys/zk/signature.rs:13-26, 74-98`, `zk/groth16/src/proof/mod.rs:29` |
| Public inputs: 32 pk slots padded with `zero_pk = Poseidon2::compress([KDF, 0])`, `KDF = fr_from_bytes_unchecked(b"KDF")`, then `msg` (33 `Fr`) | `kms/keys/src/keys/zk/public.rs:88-108`, `zk/private.rs:14, 62-67`, `zk/proofs/zksign/src/public.rs:12-17` |
| Verify = `ark_groth16::Groth16::<Bn254>::verify_proof(prepared_vk, proof, inputs)`; VK is snarkjs JSON from circuits release `v0.5.7` | `zk/groth16/src/verifier.rs:30-37`, `zk/groth16/src/verification_key/mod.rs:19-60`, `zk/proofs/zksign/src/verification_key/mod.rs:15-23` |

A light verifier needs only `logos-blockchain-groth16` (pure arkworks),
`logos-blockchain-poseidon2`, `blake2`, and a vendored
`verification_key.json`. Depending on `kms/keys` drags the rapidsnark
prover and a build-time artifact download into the module — avoid.

### 2.3 Chain queries

| Route | Returns | Notes |
|---|---|---|
| `GET /cryptarchia/info` | `{ cryptarchia_info: { lib, lib_slot, tip, slot, height, state }, phase }` | `lib_slot` is **nested** (`services/chain/chain-service/src/lib.rs:234-250`) |
| `GET /cryptarchia/blocks/:id` | `{ header{id,parent_block,slot,body_root,…}, uncle_headers, transactions }` | raw storage read — **forks included** (`handlers.rs:1526-1551`) |
| `GET /cryptarchia/blocks?slot_from=&slot_to=` | immutable canonical blocks | served from the immutable-block index written only on LIB advance (`services/api/src/http/mantle.rs:626-671`, `chain-service/src/service/mod.rs:1140-1155`). **This is the canonicity primitive.** |
| `GET /cryptarchia/blocks/:id/events` | `[ { "Tx": { tx_hash, op_id, payload } }, { "Header": … } ]` | raw storage read; carries the full minted `utxo` (incl. `value = epoch_reward`, which is *not* derivable from the tx) |
| `GET /pow/status` | `{ is_mining, are_rewards_enabled, auto_claim: { is_armed, tick, targets: [ { public_key, threshold, balance } ] } }` | how the producer learns `K` (`services/pow/src/service.rs:150-170`) |

Not usable as inclusion evidence: `/cryptarchia/transaction/:id` reads the
**mempool** store (entries pruned 10 min after removal); `/mantle/status`
answers only `Unknown | Pending`. There is no PoW ledger-state endpoint, no
`pk → tx` index, no per-tx Merkle proof API (`transactions_root` is a plain
binary tree over the whole block, `core/src/utils/merkle.rs:14-30`), and no
light client.

### 2.4 Encodings the verifier parses

- `Fr`-typed fields (`ZkPublicKey`, `epoch_nonce`, `pow_nullifier`, `NoteId`)
  → 64-char lowercase hex of the **32-byte little-endian** value
  (`utils/src/lib.rs:20-27`, `zk/groth16/src/lib.rs:47-53`).
- `TxHash`, `HeaderId` → 64-char lowercase hex.
- `Hash = [u8; 32]` (`core/src/crypto.rs:4`) has **no custom serde**, so
  `ClaimPowRewardOp.block_hash`, `TxEvent.op_id` and `Utxo.op_id` arrive as
  **JSON arrays of 32 integers**.
- Block transactions are emitted through `ApiTransactionSerializer`, which
  adds `mantle_tx.hash` (`nodes/node/binary/src/api/serializers/transactions.rs:10-24`):

```json
{ "mantle_tx": { "hash": "<hex64>", "ops": [
    { "opcode": 64, "payload": { "epoch_nonce": "<hex64>", "block_hash": [u8×32], "public_key": "<hex64>" } },
    { "opcode": 0,  "payload": { "inputs": ["<NoteId hex64>", …], "outputs": [ { "value": 123, "pk": "<hex64>" } ] } } ] },
  "ops_proofs": [ { "None": null }, { "ZkSig": { "pi_a": "<hex64>", "pi_b": "<hex128>", "pi_c": "<hex64>" } } ] }
```

```json
{ "Tx": { "tx_hash": "<hex64>", "op_id": [u8×32],
          "payload": { "PoWRewardClaimed": { "pow_nullifier": "<hex64>",
                       "utxo": { "op_id": [u8×32], "output_index": 0, "note": { "value": 123, "pk": "<hex64>" } } } } } }
```

- `op_id = Blake2b-256("OPERATION_ID_V1" ‖ canonical op bytes **without** the opcode)`
  (`core/src/mantle/ops/op.rs:29-36`, `ops/mod.rs:38-45`).
- `NoteId = Poseidon2([NOTE_ID_V1, Fr::from_le_bytes_mod_order(op_id), Fr(output_index), Fr(value), pk])`,
  `NOTE_ID_V1 = fr_from_bytes(b"NOTE_ID_V1")` (`core/src/mantle/ledger.rs:491-525`).

### 2.5 Deployment parameters that matter

`slot_window = 300` slots (claim must be included within it; ledger
nullifiers prune after it). `security_param` = **30** blocks in the
standalone template, **120** on devnet/testnet
(`deployment/ceremony/genesis/*/deployment-template.yaml:23`). Target ~1
claim per block network-wide; `slot_duration` 1 s, ~20 slots per block.

## 3. Vector specification

### 3.1 `auth_type`

`pow-claim`.

### 3.2 Challenge

```
digest = Blake2b-256( "logos:rln:gifter:pow-claim:v1\0"
                    ‖ u8 len(audience) ‖ audience
                    ‖ id_commitment[32]
                    ‖ rate_max  u64 LE
                    ‖ pow_nullifier[32] LE )
msg_fr = Fr::from_le_bytes_mod_order(digest)          -- same reduction as TxHash::to_fr
sig    = POST /wallet/sign/zk { "tx_hash": hex(digest), "pks": [hex(K)] }
```

- Non-interactive and commitment-bound, like every other vector (the wire
  has no nonce round-trip); replay is neutralised by the nullifier.
- `rate_max`, not `rate`: the gifter **clamps** the requested rate to the
  operator's `maxRateLimit` *before* calling the verifier
  (`rust/rln-gifter-module/rust-lib/src/server.rs:218-221`), so the signed
  value is a ceiling and the verifier checks `req.rate <= rate_max`.
- `pow_nullifier` is in the message so a signature cannot be moved between
  claims. It is globally unique: a claim's `block_hash` must be within
  `slot_window` of the including block and the ledger's nullifier set covers
  that window, so the same ticket can never be re-included after pruning.
- `audience` (default empty) is the gifter's name; it stops a captured
  payload being replayed to another gifter (which would only register the
  same commitment there, but without consent).
- Domain separation: real tx signatures are over
  `Blake2b-256("MANTLE_TXHASH_V1" ‖ tx)`; colliding with our tagged digest
  needs a second preimage. The producer must compute the digest itself —
  never sign bytes a remote party supplies.

### 3.3 Payload (`authentication_payload`, little-endian)

```
offset size   field
0      1      version = 0x01
1      1      flags           bit0 = spend locator present
2      32     K               ZkPublicKey, Fr LE
34     32     claim_block_id  HeaderId
66     32     pow_nullifier   Fr LE
98     8      rate_max        u64 LE
106    32     spend_block_id  if bit0
138    32     spend_tx_hash   if bit0
..     128    zksig           pi_a ‖ pi_b ‖ pi_c (compressed Groth16)
```

234 B without the locator, 298 B with it; the request frame allows 4096 B.
The verifier fetches everything else from its node; the payload only
*locates* evidence.

### 3.4 Verifier algorithm (`verify_auth`)

Inputs: `VerifyRequest { payload_hex, id_commitment_hex, rate, config }`.

1. Decode; exact length for the flags; `req.rate > rate_max` → reject.
   Verify the signature **first**, offline:
   `groth16_verify(vk, zksig, [K, zero_pk × 31, msg_fr])`. Milliseconds, and
   junk never costs an HTTP call.
2. `GET /cryptarchia/info` → `lib_slot`.
3. `GET /cryptarchia/blocks/{claim_block_id}` → `s = header.slot`. Reject if
   `s > lib_slot` (`not final yet`) or 404.
4. `GET /cryptarchia/blocks?slot_from=s&slot_to=s` must contain an entry
   with `header.id == claim_block_id`; that object is `B`. Reject otherwise
   (`not canonical`). With `config.node_urls`, every node must agree here.
5. `GET /cryptarchia/blocks/{claim_block_id}/events` → the `Tx` event whose
   `PoWRewardClaimed.pow_nullifier` equals the payload's; take
   `(tx_hash, op_id, utxo)`. Reject if absent.
6. In `B`, find `T` with `mantle_tx.hash == tx_hash`, and in `T` the
   `opcode 64` op whose recomputed ticket
   `Poseidon2([public_key, from_le_mod(block_hash), epoch_nonce])` equals the
   nullifier. Require `utxo.note.pk == op.public_key` and
   `utxo.op_id == event.op_id` (cheap consistency checks on the node's data).
7. Ownership, one of:
   - **(A) direct**: `utxo.note.pk == K`. A claim mined with `pk = K` is a
     single lottery ticket per (block, epoch) — rare but valid, and the
     strongest ownership evidence there is. Gated by
     `config.allow_direct_ownership`.
   - **(B) spent to K**: `note_id = NoteId(utxo)` (§2.4). `S = T`, or, if
     `bit0`, repeat steps 3–4 for `spend_block_id` and find `S` by
     `spend_tx_hash`. Require an `opcode 0` op in `S` with
     `note_id ∈ inputs` and an output `{ pk == K, value >= min_payout }`.
8. `Verdict::accept(nullifier = hex(pow_nullifier))` — 64 lowercase hex
   chars; the gifter namespaces it `pow-claim:<hex>` and persists it on
   successful registration.

**Why `note_id ∈ inputs` is the load-bearing check.** Claim ops are
unsigned, so a block proposer or mempool observer can lift an honest claim
op into their own tx `T' = [Claim(honest pk), Transfer(attacker notes → K_att)]`.
`T'` is valid (the honest tx then fails `DoubleClaimed`). A rule of the
form "some Transfer in the same tx pays `K`" would hand the honest miner's
credential to `K_att`. Requiring that the Transfer *spends the minted note*
closes this: only the mined key can sign that spend. The side effect is
that the honest miner's note then sits at the mined pk in `T'`; once they
sweep it to `K` in a later tx, the spend locator (`bit0`) makes the
credential redeemable again.

Reject-vs-error follows the reference vectors: anything
attacker-controlled → `reject`; bad `config`, unreadable VK → `Err`
(`{"error"}` envelope). A lagging or syncing `node_url` produces transient
`not final yet` / `not canonical` rejects; callers retry.

Budget: one pairing check + 3–5 HTTP calls to a local node, well inside
the 30 s verifier window on the gifter's single worker.

### 3.5 `config` schema

```json
{
  "node_url":               "http://127.0.0.1:8080",
  "node_urls":              [],                 // optional quorum; all must agree in step 4
  "audience":               "",                 // optional; must match the producer's
  "min_payout":             0,                  // optional; path B output value floor
  "allow_direct_ownership": true,               // path A
  "allow_spend_locator":    true,               // bit0
  "http_timeout_ms":        8000,
  "zksign_vk_path":         null                // overrides the embedded VK (circuits v0.5.7)
}
```

`node_url` is required (operator mistake → `Err`).

## 4. Producer specification

### 4.1 Where it lives

A new client-side module, `pow_claim_capture_module`, that talks to the
user's node over its in-process HTTP API (`http_addr`, default
`127.0.0.1:8080` — `nodes/node/binary/src/config/api/serde.rs:34-41`).

State of the C++ `blockchain_module` (`logos-blockchain/logos-blockchain-module`,
checked 2026-10-07):

| | shipped `0.2.0` (nix store, darwin-arm64) | `master` `63c3b0a` (2026-10-05) |
|---|---|---|
| bundled node | pre-PoW: no `/pow/*` routes, no PoW service, no `PoWClaim` key | `0.3.0-rc.5` (`2c652646`): PoW routes + `PoWClaim` key |
| PoW methods | none | `pow_status`, `pow_start_mining`, `pow_stop_mining`, `pow_start_auto_claim`, `pow_stop_auto_claim`, `pow_claim(claim_address_hex)`, `pow_claimable_rewards` |
| chain reads | `get_cryptarchia_info`, `get_block`, `get_blocks`, `get_block_events` | same |
| sign method | none | none (`/wallet/sign/zk` exists on the in-process node's HTTP API in both) |
| address discovery | `user_config_path`/config methods, no "get http addr" | same; `http_addr` is an optional `generate_user_config` arg, node default `127.0.0.1:8080` |

So once `master` is released, the producer can take K and the mining switch
from `blockchain_module` over `call_json` (`pow_status`, `pow_start_mining`)
and only needs the HTTP port for the signature and, optionally, the block
scan. Until then the HTTP API is the only path for everything, and the
shipped module cannot mine at all.

### 4.2 `produce_auth(args_json) → json`

In: `ProduceRequest { auth_type: "pow-claim", id_commitment_hex, args }`.
`args` arrives as a JSON **string** (the RLN membership module stringifies
`auth_args`); parse it to:

```json
{ "node_url": "http://127.0.0.1:8080",
  "audience": "",                 // optional
  "rate_max": 100,                // optional, default 100
  "claim_block_id": "…",          // optional pin
  "pow_nullifier": "…",           // optional pin
  "spend_block_id": "…",          // optional locator
  "spend_tx_hash": "…",           // optional locator
  "exclude_nullifiers": ["…"] }   // optional, for retries
```

Steps:

1. `GET /pow/status` → candidate set `{K}` = `auto_claim.targets[].public_key`
   (plus `wallet_get_known_addresses` if the app passes them; any wallet key
   that received a claim payout qualifies).
2. If `pow_nullifier` is pinned, go to 4. Otherwise scan
   `GET /cryptarchia/blocks?slot_from=lib_slot−W&slot_to=lib_slot` in
   100-slot chunks, newest first, and each block's `/events`; collect
   `PoWRewardClaimed` events whose minted note satisfies path A or B for
   some `K` (path B: find the Transfer in the same tx spending `NoteId(utxo)`
   with an output to `K`). Skip `exclude_nullifiers`.
3. Pick the newest candidate. None → `{"error": "no redeemable PoW claim found"}`.
4. Compute `digest` (§3.2) locally; `POST /wallet/sign/zk { tx_hash: hex(digest), pks: [K] }`.
5. Encode the payload (§3.3); return `{"payload_hex"}`.

The producer cannot know which credentials a given gifter has already
spent; on a `credential already used` refusal the application retries with
that nullifier in `exclude_nullifiers`.

Out: `{"payload_hex": …}` or `{"error": …}` via `rln_auth_vector::dispatch_produce`.

### 4.3 Requester wiring

RLN membership module `RegistryOptions`:

```
auth_type:     "pow-claim"
auth_provider: "pow_claim_capture_module"
auth_args:     {"node_url": "http://127.0.0.1:8080", "rate_max": 100}
```

Requirements on the user's side: a `blockchain_module` release built from
its current `master` (node `0.3.0-rc.5`; the shipped `0.2.0` has no PoW),
mining started (`PUT /pow/mining/start` or the module's `pow_start_mining` —
off by default and not persisted across restarts,
`services/pow/src/service.rs:538-540`; the `blockchain_ui` module
(`logos-blockchain/logos-blockchain-ui`, Mining view since 2026-09-18, #67)
drives it through `pow_configure` / `pow_start_mining` and shows rewards and
claim history, so end users already have a toggle), and an auto-claim target
or manual `POST /pow/claim`. The `PoWClaim` key is one of
the six predefined zk keys created at keystore init and preloaded into the
KMS (`cli/config/keystore.rs:31-38`, `cli/config/init.rs:208-214`), so a
keystore generated by the old module lacks it; whether `migrate_user_config`
adds it was not verified.

## 5. Operator wiring and budgets

```json
"authVerifiers": {
  "pow-claim": {
    "module": "pow_claim_auth_module",
    "config": { "node_url": "http://127.0.0.1:8080" }
  }
}
```

The gifter operator runs (or points at) a node they trust. v1 assumes the
operator's own node on the gifter host; `node_urls` is cheap hardening
against a single compromised RPC.

| Limit | Value | This vector |
|---|---|---|
| Request frame | 4 096 B | 234 B (298 B with locator) |
| Verifier call | 30 s, single worker | Groth16 verify (ms) + 3–5 local HTTP calls |
| Producer call | 120 s | `/pow/status` + bounded block scan + one `/wallet/sign/zk` (KMS proving, seconds) |
| Replay | nullifier store | `pow-claim:<pow_nullifier hex>` |
| Usable after | LIB | 30 blocks standalone, 120 blocks devnet/testnet |

## 6. Implementation roadmap

### A. `logos-rln-gifter` — `rust/pow-claim-auth-module` (verifier)

- Skeleton copied from `rust/eth-auth-module/` (`metadata.json`,
  `CMakeLists.txt`, `flake.nix`, `rust-lib/Cargo.toml` with `[workspace]`,
  `staticlib`, `panic = "abort"`, `logos-rust-sdk` path dep); trait
  `PowClaimAuthModule`, `verify_auth` = `dispatch_verify`.
- Dependencies: `logos-blockchain-groth16`, `logos-blockchain-poseidon2`
  (git, rev-pinned to the chain release the gifter serves), `blake2`,
  `ureq`, `serde_json`, `hex`, `rln_auth_vector`; vendored
  `zksign_verification_key.json` from circuits `v0.5.7`. **Not**
  `kms/keys`, `core` or `zksign`.
- Chain access behind `trait NodeApi { info, block, immutable_blocks_at, events }`
  so tests inject JSON fixtures captured from a real node.
- Tests (`cargo test` in `rust-lib`, no host):
  - golden: a real `/wallet/sign/zk` signature verifies under the vendored VK;
  - accept via path A; via path B same tx; via path B with locator;
  - reject: `rate > rate_max`; block slot > `lib_slot`; block absent from the
    immutable slot-range answer; nullifier not in events; ticket recompute
    mismatch; front-run tx (Transfer that pays `K` but does not spend the
    note id); audience mismatch; quorum disagreement; truncated / trailing
    bytes;
  - `Err`: missing `node_url`; unreadable `zksign_vk_path`.
- Optional `POW_CLAIM_AUTH_TYPE = "pow-claim"` in `crates/rln-auth-vector`.

### B. `logos-rln-gifter` — `rust/pow-claim-capture-module` (producer)

- `produce_auth` only; dependencies `ureq`, `serde_json`, `blake2`, `hex`,
  `rln_auth_vector`, `logos-blockchain-poseidon2` (for `NoteId` in the path-B
  scan).
- `authArgs` string → JSON; `K` discovery; bounded scan; local digest; sign;
  encode. Tests against a stubbed `NodeApi` with the same fixtures as A.

### C. Outside this repo

- Users: a `blockchain_module` release from its current `master` (node
  `0.3.0-rc.5`, `pow_*` methods already wrapped), mining enabled.
- v2 (contract change): `Verdict.nullifiers: Vec<String>` in
  `rln-auth-vector` with reserve-all / rollback-all in the gifter
  (`server.rs:283-335`) — prerequisite for "k claims per membership" (§7).
- v2 (ergonomics): a `blockchain_module` zk-sign method wrapping
  `/wallet/sign/zk`, so the producer stops depending on the HTTP port.

### D. Fixtures and end-to-end

Follow `tests/cucumber_tests/features/pow_mining.feature` (standalone node,
`minimum_difficulty = 1`, `PUT /pow/mining/start`, poll
`/pow/rewards/claimable`, `POST /pow/claim {claim_address}`, wait for the
block to pass LIB). Capture `/cryptarchia/info`, the block, its events, and
a `/wallet/sign/zk` signature as JSON fixtures. Then run the gifter with the
verifier configured against the same node: first request succeeds; a second
request for the same nullifier is refused; the front-run fixture is refused.

## 7. Limits, privacy, and where to tighten

- **Trusted node.** A lying `node_url` fabricates everything. Cheaper trust
  models, in order of cost: operator-owned node (v1); `node_urls` quorum on
  step 4; header-chain + proof-of-leadership light verification (out of
  scope — nothing packaged for it).
- **Sign oracle.** The HTTP API is unauthenticated and signs any 32 bytes
  with any wallet key. The credential is exactly as strong as access control
  on that port. The bundled module config listens on `0.0.0.0:8080`; the
  doc for users must say `127.0.0.1`.
- **Latency.** A claim becomes usable only after LIB (30 / 120 blocks).
- **Privacy.** The gifter learns `K ↔ id_commitment`, and `K`'s balance and
  history are public. `K` is the dedicated `PoWClaim` key by default, so the
  exposure is "this RLN identity is the miner whose reward sink is `K`", not
  the whole wallet — unless rewards are swept into other keys. Per-claim
  fresh addresses would need KMS key creation over HTTP (none exists) or
  local proving with rapidsnark; deferred.
- **Marginal cost.** A miner gets one membership per reward at no cost
  beyond mining they would do anyway. Raising the price to *k* claims per
  membership is cheap on the wire (k nullifiers, challenge over the sorted
  list) but unsafe with today's single-string `Verdict.nullifier`: any claim
  inside a k-bundle stays redeemable alone or in another bundle. It needs
  `Verdict.nullifiers: Vec<String>` and atomic reserve/rollback in the
  gifter — v2.
- **Front-running.** Proposers can strand a credential (§3.4) until the
  miner sweeps the note; the spend locator restores it.
- **VK pinning.** The zkSign VK is tied to a circuit release; `zksign_vk_path`
  tracks upgrades, and the module's chain-crate pins must follow the network.
- **Composability.** `pow-claim` can be the scarcity layer that
  `chat-installation` lacks: an application may require both at the
  application layer today, and a combined vector carrying both payloads is a
  straightforward follow-up once the two exist.
