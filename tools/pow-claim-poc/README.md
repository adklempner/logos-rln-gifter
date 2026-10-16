# pow-claim PoC

Proof of concept for the RLN gifter `pow-claim` auth vector: a Logos module
produces the auth payload from a PoW reward claim, using only a Logos
blockchain node's HTTP API.

## What was proven

A Logos module (`pow_claim_capture_module`, Rust, logos-module-builder) loaded
in the **same logoscore daemon** as an **unmodified** `blockchain_module`
(built from its `master` 63c3b0a, node 0.3.0-rc.5) produced the `pow-claim`
auth payload for the RLN gifter. It used only the in-process node's HTTP API:

- `GET /pow/status`, `GET /cryptarchia/info`
- `GET /cryptarchia/blocks*`, `GET /cryptarchia/blocks/:id/events`
- `POST /wallet/sign/zk`

The control plane went through the modules' own methods: `start`,
`pow_start_mining`, `pow_stop_mining`, `pow_claim`.

The payload's zkSign Groth16 signature verifies offline (`pow-claim-verify`,
vendored v0.5.7 VK) for the right ID commitment and fails for a different one.
`args` was accepted both as a JSON object and as a JSON string.

Run `runs/20261007-111117/summary.json`:

| Item | Value |
|---|---|
| total | 88 s |
| node up | 15 s |
| claim found after `pow_claim` | 3 s |
| wait for LIB | 64 s |
| produce + sign (two calls) | ~1 s |
| verify | 1 s |
| payload | 234 B |
| K | `e3635f20...ce07` |
| `sig_valid` / negative check | true / false (exit 1) |

Round 1 did not demonstrate the verifier side, gifter wiring, the Basecamp UI
or spend-locator discovery. Round 2 (below) demonstrates the verifier module and
the gifter wiring (validation only, no registry); the UI and spend locator are
still open (see "Not done").

## Layout

```
rust/pow-claim-capture-module/      thin module glue (flake.nix, metadata.json, rust-lib/src/lib.rs)
  rust-lib/pow-claim-core/          producer logic: args, discover, ownership, payload, challenge, produce
    tests/producer.rs               synthetic-fixture tests
    tests/real_fixtures.rs          tests over recorded real-node fixtures
    tests/fixtures/real/            captured by run.sh (pow_status, info, block_*, events_*, sign_zk, meta)
tools/pow-claim-poc/
  run.sh                            end to end: node -> mine -> claim -> LIB -> capture -> produce -> verify
  node-up.sh                        start/stop a single node inside logoscore (blockchain_module)
  build-module.sh                   build a module .lgx (producer by default; round 2: `pow_claim_auth_module`)
  lib/logoscore.sh                  logoscore daemon helpers
  lib/node_config.py                standalone node config + deployment patches
  lib/nodeq.py                      small node HTTP query helper
  verify/                           pow-claim-verify (offline Groth16 check, vendored VK) + golden test
  runs/<ts>/                        per-run artifacts (summary.json, claim.json, produce/, logs)
```

## Prerequisites

- nix with the logos cache (`--accept-flake-config`); `/nix/var/nix/profiles/default/bin` on `PATH`
- Rust >= 1.85 locally (core tests, verifier)
- `jq`, `curl`, `python3`, `openssl`
- outbound UDP for NTP (`pool.ntp.org`)

## Commands

One-time builds, from the repo root:

```sh
# blockchain_module .lgx (~56 min; NOT in the binary cache; default max-jobs 1 made it serial)
cd ../logos-blockchain-module && \
  nix build '.#lgx' --accept-flake-config --max-jobs 8 -o <repo>/tools/pow-claim-poc/runs/bm-lgx

# logoscore CLI (~42 s)
nix build github:logos-co/logos-logoscore-cli/d015a40c5f1c9c8ec1de5575d057410e856f8bd9 \
  --accept-flake-config -o tools/pow-claim-poc/runs/logos

# producer module (.lgx): first run ~9 min (rust-overlay 1.96.0 toolchain), then ~1.5 min
tools/pow-claim-poc/build-module.sh
```

If the GitHub fetch flakes, prefetch the node source:

```sh
nix eval --impure --expr 'builtins.fetchGit {url="https://github.com/logos-blockchain/logos-blockchain"; rev="2c652646d74354b2877620bf0bc53b4c4d3f18e4"; allRefs=true;}'
```

Run the PoC (fresh node, ~90 s once built):

```sh
tools/pow-claim-poc/run.sh
tools/pow-claim-poc/node-up.sh --down        # stop a node left up (POC_KEEP=1)
```

Env knobs:

| Variable | Default / meaning |
|---|---|
| `POC_HTTP_PORT` | 18080 (node HTTP) |
| `POC_P2P_PORT` | 13000 (node-up.sh) |
| `POC_K` | claim key (default `e3635f20...ce07`) |
| `POC_AUDIENCE` | `poc` |
| `POC_RATE_MAX` | 100 |
| `POC_ALLOW_UNFINAL` | 0; 1 lets the producer use a non-final block |
| `POC_KEEP` | 0; 1 leaves the node up |
| `PCM_LGX` | prebuilt producer .lgx (skips build) |
| `BM_LGX` | blockchain_module .lgx (default `runs/bm-lgx/*.lgx`) |
| `LOGOSCORE` | logoscore binary (default `runs/logos/bin/logoscore`) |

Unit tests:

```sh
cd rust/pow-claim-capture-module/rust-lib/pow-claim-core
cargo test                       # default (strict-ownership)
cargo test --no-default-features # loose ownership
cargo test --manifest-path tools/pow-claim-poc/verify/Cargo.toml   # from repo root; golden test
```

## Why `blockchain_module` needed no change

`start(config_path, deployment)` forwards the deployment path to
`start_lb_node`, so the standalone node config and deployment run inside the
module. The HTTP API (`listen_address`) is the node's own, so the producer
module reaches it over localhost.

## Node config / deployment patches

Applied by `lib/node_config.py`:

| Patch | Why |
|---|---|
| difficulty 1, coeff 1/2, EMA smoothing 1 / 1e18, `target_claims_per_block` 1e18 | fast mining (as cucumber `pow_mining.feature`) |
| reward pool = epoch reward = 1e6 | single-claim budget |
| `rate_num` 3000 | standalone genesis is ~21851 epochs in the past; at the epoch boundary reward = pool*rate_num/(rate_den*target*expected_blocks) collapsed to 333, and a 134-ticket batched claim produced a zero-value change output rejected by Blend ("Transfer verification error: Outputs error: Zero value note") |
| `targets: [{K, 1e12}]` | standalone has `targets: []`, so `/pow/status` would expose no K |
| swarm port 13000 | an unrelated local node held 3000; 3400 is fixed by the genesis SDP locator |
| absolute db/state/log dirs, HTTP 18080 | run isolation |

## Findings and caveats

- **Ownership is Path B only.** The reward note pays a throwaway ticket key;
  K receives via a Transfer in the same tx. The producer checks
  `NoteId(utxo) in Transfer.inputs` and an output to K. NoteId is Poseidon2,
  replicated from `core/src/mantle/ledger.rs:497-529` and checked against
  upstream `test_note_id`. The real fixtures confirm this
  (`tests/real_fixtures.rs::real_ownership_is_path_b_via_note_id`).
- **`/wallet/sign/zk` reply** is `{"sig":{"pi_a","pi_b","pi_c"}}`, not a flat
  128 B as the design doc says; the payload concatenates them.
- **Gifter `authArgs`** is forwarded as a JSON value, not a string; the
  producer accepts both.
- **Auto-claim race.** Auto-claim is armed once K is a target (tick 300 s) and
  could spend the single claim first; claim promptly.
- **One claim per fresh state** (pool == reward).
- **Randomised signature.** Two payloads for the same inputs differ only in
  the Groth16 sig (`args_string_same_signature: false` in the summary is
  expected).
- **LIB** takes ~64 s at k=30 with ~25 blocks/min.
- **Build cost.** `blockchain_module` takes ~56 min to build; the module
  builder toolchain is capped at 1.96.0 by its rust-overlay pin.
- **Loose ownership** (`--no-default-features`) is weak: a tx proposer could
  wrap an honest claim op with their own Transfer. Documented in
  `ownership.rs`; a verifier must not accept it.
- **Credential = access to the node's HTTP port.** Bind it to 127.0.0.1.
- Blend in single-node broadcast mode worked.

## Corrections to fold into `docs/auth-pow-claim.md`

(Not edited here.)

1. zkSign signature shape is `pi_a` / `pi_b` / `pi_c`, not a flat 128 B.
2. `authArgs` arrives as a JSON value, not a string.
3. Standalone / Path-B reality: reward note pays a ticket key; ownership via NoteId in Transfer inputs.
4. `rate_num` genesis caveat for any standalone test harness.
5. The module's `pow_*` methods now exist on `blockchain_module` master, so the control plane can go through `call_json`.

Round 2 additions (verified against the artifacts/code of this round):

6. Ticket derivation: `puzzle_ticket = Poseidon2::digest([pk, from_le_bytes_mod_order(block_hash), epoch_nonce])`, a 3-element `digest`, not `compress`. It matches the real `pow_nullifier` (known-answer test in `pow-claim-verifier/tests/real.rs`).
7. A flipped signature byte can fail at proof decode OR at verification; both are rejects and both messages contain "signature". The verifier treats proof-decode / K-parse failures as rejects, never `Err`.
8. Audience longer than 255 B is a config error (`Err`): `challenge::digest` panics on it and the host runs `panic="abort"`.
9. An unreachable or failing node is an `Err` (operator problem, `auth verifier ...: node unreachable or failing: ...`), not a reject. Rejects are only for things derived from the payload or the chain.
10. Contract gap: the gifter client collapses `auth_success:true` + registration failure into `{"error": ...}` (`client.rs:117-130`), so a caller cannot tell "auth accepted, registration failed" from other errors. The design doc should either surface `auth_success` or say so.
11. The gifter should verify against its OWN follower node, not the client's. Generated user configs need `prolonged_bootstrap_period` lowered (default `'3600.000000000'`) for a follower to go Online in seconds.
12. IBD backlog: a late-joining follower served pre-existing immutable blocks and their events (15/57 sampled, all served; `runs/node2-probe.json`), so the verifier's `immutable_blocks` + `events` queries work for blocks that predate node 2. Starting node 2 before mining is a margin, not a requirement.
13. `min_payout` applies to the output paying K in the NoteId-spending Transfer (path B); the implementation also applies it to path A (`utxo` value). The real payout was 999108 < 1e6 reward because of the fee, so a `min_payout` near the reward would reject honest claims.
14. The 30 s verify budget in the gifter (`lp` call timeout) is 4 sequential node calls (`info`, `block`, `immutable_blocks`, `events`) x `http_timeout_ms` (default 5000 ms) = 20 s worst case.
15. `op_id` recompute (`Blake2b-256("OPERATION_ID_V1" || epoch_nonce || block_hash || public_key)`) matches the on-chain event on the real fixture, so the verifier enforces it as a hard check (`chain.rs`).
16. The gifter's `serve` only checks that `config`/`wallet` are present; it does not catch an unloaded verifier module. The host defers clients for unloaded modules (no `lp_client_create failed`), so the failure shows up on the first `request`.
17. `logoscore call` gives up after ~20 s (`RPC_FAILED`, exit 4) while the module keeps running; any harness `request` must finish inside that.

## Not done / next (round 1; superseded by "Round 2: Not done")

- ~~Verifier module (`pow_claim_auth_module`) and gifter wiring~~ done in round 2 (validation only)
- Running via the Basecamp UI. Note: mining itself already has a UI — the
  `blockchain_ui` module (`logos-blockchain/logos-blockchain-ui`, Mining view
  since 2026-09-18) configures PoW, starts/stops mining and claims rewards
  through `blockchain_module`'s `pow_*` methods. What is missing is only the
  "spend a claim on an RLN membership" step.
- Spend-locator discovery
- `Verdict.nullifiers` v2

# Round 2: two-daemon gift flow (validation only, no registry)

## R2.1 What was proven

Two logoscore daemons on one host. The client asks the gifter for a membership
over libp2p with `authType: "pow-claim"`; the gifter verifies the claim with
`pow_claim_auth_module` against **its own follower node**. Run
`runs/20261007-133525-gifter/summary.json`: all assertions pass, 143 s total.

```
daemon A (runs/<ts>-gifter/a)                     daemon B (runs/<ts>-gifter/b)
  blockchain_module  node 1 (mining)                blockchain_module  node 2 (follower)
    HTTP :18080, UDP 13000 / blend 3400               HTTP :18081, UDP 13001 / blend 3401
  pow_claim_capture_module  (producer)  <---HTTP--- (not used by B)
  libp2p_module  tcp/0                              libp2p_module  tcp/61871
  rln_gifter_module  (client: request) --libp2p-->  rln_gifter_module serve
                                                      authVerifiers: pow-claim ->
                                                    pow_claim_auth_module (node_url :18081)
                                                    liblogos_lez_rln_module  (STUB, see R2.4)
node 2 syncs from node 1 (initial peer /ip4/127.0.0.1/udp/13000/quic-v1/p2p/<node1 id>)
```

Validation only: there is no LEZ registry. Registration fails by design at a
stub (see R2.4); what is validated is the auth path (payload decode, zkSign
signature, on-chain claim facts from node 2, nullifier handling).

Artifacts: gifter 0.3.0 built from `git archive` of `01dd6f8`; libp2p_module
master `7b4b776`; blockchain_module from round 1. The claim block was held by
node 2 as immutable and canonical before any request (`node2_view`, slot
13120937, `lib_slot` equal).

Results (`summary.json`, `requests[]`; error strings are the client's reply):

| Tag | Input | Reply (`error`) | Audit |
|---|---|---|---|
| pos-provider | `authProvider: pow_claim_capture_module` (A mints payload) | `register_member: reply parse: expected value at line 1 column 1` | accept |
| pos-replay | same payload via `authPayload` | same register error | accept |
| pos-node1-down | same payload, node 1 stopped | same register error | accept (node :18081) |
| neg-sig | one signature byte flipped | `zkSign signature invalid (proof does not verify)` | reject |
| neg-audience | payload for audience `evil` | `zkSign signature invalid (proof does not verify)` | reject |
| neg-idc | payload with another ID commitment | `zkSign signature invalid (proof does not verify)` | reject |
| neg-trunc | payload minus 1 byte | `payload: payload length 233 != 234 for flags 0x00` | reject |
| neg-authtype | `authType: "pow-claim-v0"` | `unsupported authentication_type: 'pow-claim-v0'` | none (never reaches the verifier) |
| neg-rate | payload `rate_max` 50, request rate 100 | `requested rate 100 exceeds payload rate_max 50` | reject |
| pos-dead-node | verifier re-pointed at stopped node 1 (:18080) | `auth verifier pow_claim_auth_module: node unreachable or failing: ... Connection refused` | error |

Audit totals: accept 3, reject 5, error 1; `stub_inbound_calls` 3. The three
accepts are all `node=:18081`, path `spent_to` (path B), about 4 ms each
(`b/verifier-audit.jsonl`). Every request finished in <= 1 s.

Timings (s): preflight 3, node1-up 18, node2-up 38, mine 1, claim 3, wait LIB 65,
gifter-b 2, client-a 4, pos-provider 0, replays 5, node1-down 4, total 143.

**Why the positive evidence is indirect.** The gifter client turns
`auth_success: true` + a registration failure into `{"error": failure.error_message}`
(`rust/rln-gifter-module/rust-lib/src/client.rs:117-130`), so the caller never sees
`auth_success`. The positive case is therefore established by three things
together: (1) the exact register-error string (`register_member: reply parse`)
appears only after auth passed; (2) the verifier's own audit line says
`verdict=accept` for that nullifier from node 2, in `b/verifier-audit.jsonl` and
on stderr in `b/daemon.log`; (3) every negative returns a different string, none
of which is the register error. Because the stub's reply is not JSON, the gifter
treats the registration as not submitted and releases the nullifier, so
`consumed_nullifiers.txt` is never created and the same claim could be replayed
(that is how pos-replay and pos-node1-down reuse it).

## R2.2 Commands

From the repo root. `PATH` needs `/nix/var/nix/profiles/default/bin`; round-1
prerequisites (logoscore in `runs/logos`, blockchain_module in `runs/bm-lgx`) apply.

```sh
# libp2p_module + rln_gifter_module (git archive of HEAD) + stub LEZ module -> runs/artifacts.env
tools/pow-claim-poc/build-gifter-artifacts.sh [--rebuild-libp2p]

# verifier module .lgx (re-syncs rust-lib/pow-claim-core from the capture module first)
tools/pow-claim-poc/build-module.sh pow_claim_auth_module | tail -1
tools/pow-claim-poc/build-module.sh pow_claim_auth_module --generate   # refresh scaffold; see caveat below

# chainless smoke: two daemons, no nodes -> runs/gifter-smoke.json
tools/pow-claim-poc/gifter-smoke.sh

# the follower on its own (needs a running node-up.sh run for node 1)
POC_RUN_DIR=<fresh dir> tools/pow-claim-poc/node2-up.sh --node1-run <RUN_A> [--no-wait]
tools/pow-claim-poc/node2-up.sh --down <RUN_B>

# the full two-daemon run (~2.5 min once built) -> runs/<ts>-gifter/summary.json
tools/pow-claim-poc/run-gifter.sh
tools/pow-claim-poc/node2-up.sh --down <RUN>/b     # with POC_KEEP=1
tools/pow-claim-poc/node-up.sh --down <RUN>/a
```

Caveat on `--generate`: the builder's `#generate` output does not contain a
`provider_gen.rs` (for either module), so `rust-lib/generated/provider_gen.rs`
of the auth module is a renamed copy of the capture module's file. It is only
needed for local `cargo check`/`cargo test`; the nix build runs its own codegen.

`run-gifter.sh` env knobs:

| Variable | Default / meaning |
|---|---|
| `POC_AUDIENCE` | `poc` |
| `POC_RATE_MAX` | 100 |
| `POC_KEEP` | 0; 1 leaves both daemons up |
| `POC_EXPECT_REGISTER_ERR` | regex for the positive reply, default `register_member: reply parse` |
| `PCM_LGX`, `PCA_LGX` | capture / auth module .lgx (default: the store paths from this round) |
| `LIBP2P_LGX`, `GIFTER_LGX`, `STUB_LGX` | from `runs/artifacts.env` unless set |
| `BM_LGX`, `LOGOSCORE` | as round 1 |

`node2-up.sh` env: `POC_RUN_DIR` (required, fresh), `POC2_HTTP_PORT` 18081,
`POC2_P2P_PORT` 13001, `POC2_BLEND_PORT` 3401, `POC2_WAIT_S` 300, `EXTRA_LGX`,
`BM_LGX`, `LOGOSCORE`, `POC_KEEP_ON_FAIL`. It writes `<B>/env.sh` and
`<B>/node2-up.json`. `gifter-smoke.sh` env: `STUB_LEZ_LGX`, `NO_STUB=1`,
`GIFTER_PORT` (61871).

Ports to keep free: TCP 18080, 18081, 61871; UDP 13000, 13001, 3400, 3401.

Unit tests for the verifier module:

```sh
cd rust/pow-claim-auth-module/rust-lib/pow-claim-core     && cargo test   # synced copy of the capture core: 30
cd rust/pow-claim-auth-module/rust-lib/pow-claim-verifier && cargo test   # 43 (tests/real.rs, tests/synthetic.rs)
cd rust/pow-claim-auth-module/rust-lib                    && cargo test   # glue: 5
```

## R2.3 Node 2 (follower) findings

From `runs/node2-probe.json` (two successful bring-ups; WP-B):

- `blockchain_module.generate_user_config` takes a **bare JSON object** as its one argument
  (`output`, `net_port`, `blend_port`, `http_addr`, `initial_peers`, `state_path`,
  `storage_path`, `logs_path`); it writes `user_config.yaml` and a fresh
  `keystore.yaml`. Node 1's PeerId goes into `initial_peers` as `.../p2p/<id>`; that
  also makes node 1 an IBD peer.
- Generated defaults: `prolonged_bootstrap_period '3600.000000000'`, `grace_period
  '1200.000000000'`, mining off, auto-claim targets a fresh PoWClaim key with the
  MAX threshold. `lib/node2_config.py` replaces the first with `'5.000000000'`
  (exact substring, one match).
- `start(config, <node 1's patched deployment.yaml>)`. The protocol names must match.
- Online about 9 s after start; lib lag 0 over three samples. Warnings seen and
  harmless: `failed to send the Ok result of dialing`, NTP failures, one `AlreadyApplied`.
- IBD backlog probe (node 1 mined alone, then node 2 started): 57 pre-existing
  immutable block ids identical on both nodes; 15 sampled old blocks all returned
  `/cryptarchia/blocks/:id` and `/events` on node 2 (`ibd_backlog_served: true`).
  So starting node 2 before mining is a safety margin only.
- Node 2 is not in the genesis SDP; blend ran in broadcast mode without trouble.
- `node2-up.sh --down` must source `<RUN_B>/env.sh`; `daemon_stop` reuses the
  global `POC_DAEMON_PID`, so callers use `POC_DAEMON_PID="" daemon_stop <run>`.

## R2.4 Gifter / host findings

- **Deferred clients.** The host does not fail `lp_client_create` for a module that
  is not loaded; it defers the client. So `serve` does not catch an unloaded
  verifier (`gifter-smoke.sh` probe 1: `serve` with `authVerifiers` naming
  `nonexistent_module` was accepted; `gf_check_lp_logs` found no
  `lp_client_create failed`). With no `liblogos_lez_rln_module` loaded,
  `register_member` waits about 190 s instead of failing fast.
- **20 s CLI deadline.** `logoscore call` gives up after about 20 s
  (`{"code":"RPC_FAILED"}`, exit 4); the module keeps running but the reply is
  lost. Every `request` in the harness must (and did) finish within that.
- **Load order.** Verifier module before `serve` (`lp::ensure_client`), `libp2p_module`
  before `rln_gifter_module` (`lp::init` in `on_context_ready`).
- **Stub `liblogos_lez_rln_module`** (`stub-lez-rln/`, built by
  `build-gifter-artifacts.sh`) stands in for the registry on daemon B. Its
  working shape is `register_member(config, wallet, id_commitment, rate: i64) -> String`
  returning non-JSON text. That yields `register_member: reply parse: ...`, the
  gifter's `NotSubmitted`, and releases the nullifier. Pitfalls found:
  - omitting `register_member`: the host answers OK/null, the gifter enters its 150 s
    confirm loop, ends Unconfirmed and **persists** the nullifier;
  - an empty-string reply does the same;
  - a `String`-typed `rate` gives a `dispatch_failed` object and the same loop;
  - never return a JSON object (it also enters the confirm loop).
- Rejects never reserve a nullifier. Only a submitted/unconfirmed registration does.
- CLI coercion: Rust string params take a bare JSON object; digit-leading scalars
  need an argfile.
- Disk: `/nix` was near full, so run dirs' `modules/` copies are deleted on teardown.

## R2.5 Verifier module `pow_claim_auth_module`

Layout: `rust/pow-claim-auth-module/` — glue `rust-lib/src/lib.rs`
(`PowClaimVector`, `auth_type "pow-claim"`, `dispatch_verify`), `rust-lib/pow-claim-core/`
(verbatim copy of the capture core; never hand-edit, `build-module.sh` re-syncs it),
`rust-lib/pow-claim-verifier/src/{lib,config,sig,ticket,chain,audit}.rs` (own
workspace; vendored zkSign VK v0.5.7).

`verify_request`:

1. Parse `config` (`node_url` required; `audience`; `min_payout` 0;
   `allow_direct_ownership` true; `allow_spend_locator` true; `http_timeout_ms` 5000;
   `zksign_vk_path`; `audit_log`).
2. Decode the payload (hex, length, version, flags), idc 32 B, `req.rate <= rate_max`,
   spend flag set -> reject.
3. zkSign Groth16 first, over `[K, zero_pk x31, digest(audience, idc, rate_max, nullifier) mod p]`.
4. `GET /cryptarchia/info` -> `lib_slot`; `GET /cryptarchia/blocks/:id` must exist and
   have `slot <= lib_slot`.
5. `immutable_blocks(s, s)` must contain the block (canonical).
6. `/events` must contain a `PoWRewardClaimed` with `pow_nullifier == nullifier`.
7. Find the opcode-64 op in the tx; recompute `puzzle_ticket` and `op_id`; both must
   match; `utxo.note.pk == op.public_key`; `utxo.op_id == event.op_id`.
8. Ownership: path A `utxo.note.pk == K` (if allowed) or path B (NoteId of the utxo is a
   Transfer input and an output pays K at least `min_payout`).
9. Accept with the nullifier; write one audit record.

Reject vs `Err`:

| Outcome | Cases |
|---|---|
| reject (`ok:false`, reason) | bad hex/length/version/flag, spend locator, rate above `rate_max`, bad/failed signature (incl. proof-decode), block unknown, not final, not canonical, no matching event, ticket / op_id mismatch, wrong utxo owner or op, no ownership path, payout below `min_payout` |
| `Err` (operator problem) | missing/invalid config, `node_url` not http(s), audience > 255 B, bad VK path, `node_urls` non-empty (quorum unsupported), node unreachable or erroring, `lib_slot` missing |

Audit: every decision writes a stderr line `pow_claim_auth: verdict=... node=...
nullifier=... path=... reason=... ms=...` (lands in `daemon.log`) and, with
`audit_log`, a JSON line `{ts, verdict, node, nullifier, path, reason, ms, lib_slot}`.

Verified in tests: known answers `puzzle_ticket(op64) == nullifier` and
`note_id_hex(utxo)` on the recorded real fixture; accept on the real fixture; reject
matrix (signature flips in pi_a / pi_b, other idc, other audience, rate, +-1 byte,
version, flags, spend flag, `lib_slot = s-1`, missing block, empty immutable list,
absent nullifier, changed tx hash / epoch_nonce / utxo pk / Transfer input,
`min_payout` above payout); `Err` cases; path A at the `chain.rs` layer (synthetic).
The lgx smoke (`runs/20261007-130915-pca-smoke/`) loaded the module in a throwaway
daemon.

## R2.6 Not done

- **LEZ registration.** No registry: the stub fails registration on purpose. The
  harness's local LEZ target is not buildable here. Nothing tested here shows a
  membership being created.
- **`auth_success` surfacing** in the gifter client (`client.rs:117-130`); see
  correction 10.
- **Spend-locator** discovery and verification (flag rejected by the verifier).
- **Quorum** verification (`node_urls` is `Err` unsupported).
- Basecamp UI step "spend a claim on a membership". Mining itself already has a UI
  (`blockchain_ui` Mining view in `logos-blockchain/logos-blockchain-ui`, using
  `blockchain_module`'s `pow_*` methods).
- `Verdict.nullifiers` v2 (as round 1).
- Real-chain duplicate protection beyond the gifter's `consumed_nullifiers` file was
  not exercised: the stub never lets a registration be submitted, so the persisted
  path was not hit.
