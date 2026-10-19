# Getting an RLN membership from the hosted allocator (for delivery-module testers)

You run a delivery node on the Logos testnet and need an RLN membership on
the `logos.test` registry. Instead of funding your own payer, you ask the
hosted **allocator** to register one for you. Your node proves one thing to
it (an allowlisted Ethereum key, a settled PoW reward claim, or a Status Keycard), the
allocator pays, and your RLN module owns the membership exactly as if you had
paid yourself. Nothing of your identity secret leaves your node.

What the operator gives you (from their `allocator.json`):

| | |
|---|---|
| `gifter_peer_id` | `16Uiu2HAm…` — the allocator's libp2p PeerId. This is the trust anchor: the libp2p handshake is the only check that you talk to the real allocator. |
| `gifter_multiaddr` | `/ip4/<ip>/tcp/<port>` (LAN alternatives in `alt_multiaddrs`), no `/p2p/` suffix |
| `registry_id` | `logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971` (the `logos.test` preset's registry). The registry id you use below must equal the `registry_id` in the operator's `allocator.json`; the allocator serves exactly one |
| `auth_types` | which of the recipes below the allocator accepts |

Nothing in the delivery module or the RLN module is configured for this: you
register once, by hand, with the commands below, **before** starting
delivery; afterwards delivery finds the membership and uses it.

## 1. Modules

Everything runs in your `logosctl` daemon (0.3.0 or later). From the official
catalog:

```sh
logosctl daemon start --detach
logosctl catalog refresh
logosctl package install libp2p_module --version 1.1.0 -y
logosctl package install liblogos_lez_rln_module --version 5.1.0 -y
logosctl package install liblogos_rln_module --version 0.12.0 -y
logosctl package install delivery_module --version 0.4.0 -y
```

From the operator (portable bundles built by `tools/allocator/docker/build-bundles.sh`):
the gifter client and ONE producer for the recipe you use. The linux bundles
from `build-bundles.sh` load only in the Docker client (`CLIENT.md`); a native
macOS `logosctl` needs darwin builds that the operator sends you.
`keycard-capture-module` is not produced by `build-bundles.sh` (the operator
builds it with `nix build ./rust/keycard-capture-module#lgx`).

```sh
logosctl install rln-gifter-module.lgx -y
logosctl install allowlist-sign-module.lgx -y      # recipes A, D, E (Ethereum key, logos-blockchain node key, LEZ account key)
logosctl install pow-claim-capture-module.lgx -y   # recipe B (PoW claim; built from branch feat/pow-claim-auth-vector)
logosctl install keycard-capture-module.lgx -y     # recipe C (Status Keycard; darwin build from the operator)
```

## 2. Prepare your RLN stack

Start the RLN module on the registry **with provisioning off** — otherwise it
parks a self-funded registration task waiting for your (empty) payer — and
bring up the libp2p node the gifter client dials through:

```sh
logosctl module load liblogos_lez_rln_module
logosctl module load liblogos_rln_module
logosctl module load libp2p_module
logosctl module load rln_gifter_module
logosctl call liblogos_rln_module start '{"registries":["logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971"],"provision":false,"epoch_size_sec":600}'
logosctl call libp2p_module createNode '{"addrs":["/ip4/0.0.0.0/tcp/0"],"transport":"tcp","mountGossipsub":false,"mountKad":false,"mountServiceDiscovery":false}'
logosctl call libp2p_module start
```

Your lez module needs the testnet: either it was started with
`LEZ_RLN_SEQUENCER=https://testnet.lez.logos.co/` in the daemon's
environment, or run `logosctl call liblogos_lez_rln_module use_network testnet`
once. `logosctl call liblogos_lez_rln_module wallet_status` must reach
`"state":"ready"` (no funds needed: your node only reads the registry).

## 3. Prove who you are

### Recipe A — Ethereum key (`eth-allowlist`)

```sh
logosctl module load allowlist_sign_module
logosctl call allowlist_sign_module identity '{"auth_type":"eth-allowlist"}'
# {"auth_type":"eth-allowlist","id":"0x…","persisted":true}
```

Send that address (`id`) to the operator. The module minted the key on first
use and keeps it under its data directory; the address is stable for your
installation and grants exactly one membership. Wait for the operator's
"added" before step 4.

Used the earlier `eth_sign_module`? Its key is not carried over. To keep the
address the operator already listed, import that key:
`logosctl call allowlist_sign_module import_key '{"auth_type":"eth-allowlist","private_key":"0x<hex>"}'`
(the key lands on a command line). If the module already minted a different
key, the import is refused; add `"force":true` to replace it (the old address
then no longer signs).

### Recipe B — PoW reward claim (`pow-claim`)

You need your own logos-blockchain node on the chain the operator names
(same release tag as the operator's follower node, because the claim must be
on the chain that follower follows; the standard
`deployment/compose.setup.yml` → `compose.run.yml` setup), with its API on
`localhost:18080`. **Keep that port bound to localhost**: the API also signs
on request. The chain parameters below are the public testnet's at 0.3.2
(1 s slots, a measured ~41 s per block, finality after 1000 blocks, about
11 h).

1. Your node already holds a `PoWClaim` key and has auto-claim armed with it
   (a config made by `init-config` does this):
   `curl -s localhost:18080/pow/status` must show `"are_rewards_enabled":true`
   and `"auto_claim":{"is_armed":true,"targets":[…]}`.
2. Start mining — it is off by default and off again after every restart:
   `curl -X PUT localhost:18080/pow/mining/start` (or
   `logosctl call blockchain_module pow_start_mining`). Then wait for a
   winning ticket (log line `Mined a winning ticket`); auto-claim submits the
   claim within seconds (`GET /pow/rewards/claimable` lists what is still
   unclaimed). How long that takes depends on the network's difficulty and
   your hash rate. Note the claim's tx hash (the `Claim submitted` log line).
3. The claim is usable once its block is final, about 11 h later
   (`curl -s localhost:18080/cryptarchia/info` → `lib_slot` must pass the
   claim's slot).
4. Pin the claim. The producer's default scan window is the 3000 slots
   (about 50 min) before `lib_slot`, which you will almost always miss, so
   pinning is the normal path. From `tools/allocator/docker/node/`:

   ```sh
   python3 -I find-claims.py --node http://127.0.0.1:18080 --tx <claim tx hash>
   ```

   prints `claim_block_id` and `pow_nullifier`. The full `auth_args`:

   - native `logosctl` (node on this host): `{"node_url":"http://127.0.0.1:18080","audience":"","rate_max":100,"claim_block_id":"<BLOCK_ID>","pow_nullifier":"<NULLIFIER>"}`
   - client container: the same with `"node_url":"http://host.docker.internal:18080"`
     (as `CLIENT_AUTH_ARGS` in `client.env`).

   `audience` is currently empty; it must equal the operator's
   `POW_AUDIENCE`.

```sh
logosctl module load pow_claim_capture_module
```

One claim grants one membership. The pow-claim check is independent of the
registry (the allocator's verifier checks the chain; the registry only pays),
but nullifiers are per registry, so a claim already used on the operator's
local zone can be used once more on testnet. Refusals: `claim block not final
yet` — the operator's node has not reached your claim's slot yet, retry later;
`credential already used` — this claim already bought a membership. Two
real claims from a mining node have been registered this way through the
allocator container (2026-10-16); the exact `logosctl` sequence below with
`register_membership` is the same request the probe client sends. If it
fails, report the error text and fall back to recipe A.

### Recipe C — Keycard (`keycard-attestation`)

You need a Status Keycard and a PC/SC smart-card reader on the machine that
runs `logosctl` **natively**: the client container cannot reach a reader. On
macOS the built-in PCSC framework is used (no `pcscd`). No PIN and no pairing:
the producer sends `IDENTIFY_CARD` over a challenge bound to your commitment.

```sh
logosctl module load keycard_capture_module
logosctl call keycard_capture_module card_status
# {"present":true}
```

Register as in step 4 with `"auth_type":"keycard-attestation"`,
`"auth_provider":"keycard_capture_module"` and no `auth_args`. One physical
card grants one membership, and it survives a factory reset of the card.
Refusals: `attestation verification failed` — the card is not from a CA the
allocator trusts, or the attestation was tampered with; `credential already
used` — this card already has a membership. Verified with a real card and an
ACS ACR39U reader (2026-10-16): grant in 9 s, replay refused. If
`card_status` stays `{"present":false}` with the card in, re-plug the reader:
a blinking reader that is not listed by PC/SC is not enumerated.

### Recipe D — logos-blockchain node key (`logos-allowlist`)

You run your own logos-blockchain node with one PoWClaim key; its public key
is your credential and the node signs for it (the key never leaves the node).
Install `allowlist-sign-module.lgx`, then:

```sh
logosctl module load allowlist_sign_module
logosctl call allowlist_sign_module identity '{"auth_type":"logos-allowlist","args":{"node_url":"http://127.0.0.1:8080"}}'
# {"auth_type":"logos-allowlist","id":"<64 hex>","persisted":true,"source":"pow_status"}
```

Send the `id` (K) to the operator and wait for "added". If the node has
more than one PoWClaim key, add `"public_key":"<64 hex>"` to the args. Register
as in step 4 with `"auth_type":"logos-allowlist"`,
`"auth_provider":"allowlist_sign_module"` and
`"auth_args":{"node_url":"http://127.0.0.1:8080","rate_max":100,"audience":""}`
(from the Docker client use `http://host.docker.internal:18080`). `rate_max`
(default 100) and `audience` (default `""`) are signed with the commitment:
`rate_max` must be at least the `rate_limit` you register with, and `audience`
must equal the operator's `LOGOS_AUDIENCE` (ask them; empty on both sides is
fine). The node proves the signature during the request (about 15 s). One key grants one
membership. Refusals: `not allowlisted` — K is not on the operator's list yet;
`credential already used`.

### Recipe E — LEZ account key (`lez-allowlist`)

Install `allowlist-sign-module.lgx`, then:

```sh
logosctl module load allowlist_sign_module
logosctl call allowlist_sign_module identity '{"auth_type":"lez-allowlist"}'
# {"auth_type":"lez-allowlist","id":"<64 hex>","id_base58":"…","persisted":true}
```

Send the `id_base58` to the operator and wait for "added". Register as
in step 4 with `"auth_type":"lez-allowlist"` and
`"auth_provider":"allowlist_sign_module"`; `auth_args` is optional:
`{"rate_max":100,"audience":""}` are the defaults, and both are signed with the
commitment (`rate_max` ≥ your `rate_limit`; `audience` must equal the
operator's `LEZ_AUDIENCE`). The key is minted on
first use and kept under the module's data dir (`persisted:true`); when it says
`persisted:false` the id changes per run, so pin a key: `logosctl call
allowlist_sign_module import_key '{"auth_type":"lez-allowlist","private_key":"0x<hex>"}'`
prints its ids (the key lands on a
command line; add `"force":true` to replace a different persisted key). Once
imported, the module signs with it: do not repeat it in `auth_args`. One
account grants one membership. Refusals: `not allowlisted`,
`credential already used`.

## 4. Register

One call. The RLN module mints the identity, asks the producer module for the
proof bound to it, dials the allocator, and records the membership as
`pending`; the allocator pays and the registry confirms within ~5 minutes.
Replace `<PEER>` and `<MADDR>`; keep the rate at 100 (the allocator's cap).
`<PEER>` is always the operator's `gifter_peer_id`. `<MADDR>` is the
operator's `gifter_multiaddr` (or one of `alt_multiaddrs`).

Recipe A:

```sh
logosctl call liblogos_rln_module register_membership \
  logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971 \
  5e269b6a19fce081f5808b13442dcbc3522197638dd38df5a28bc4e55236b977 \
  '[{"key":"rate_limit","value":"100"},{"key":"delegated","value":"true"},{"key":"gifter_peer_id","value":"<PEER>"},{"key":"gifter_multiaddr","value":"<MADDR>"},{"key":"auth_type","value":"eth-allowlist"},{"key":"auth_provider","value":"allowlist_sign_module"}]'
```

Recipe B: the same with `"auth_type":"pow-claim"`, `"auth_provider":"pow_claim_capture_module"`
and one more pair, the pinned `auth_args` from recipe B step 4 as escaped JSON:

```
{"key":"auth_args","value":"{\"node_url\":\"http://127.0.0.1:18080\",\"audience\":\"\",\"rate_max\":100,\"claim_block_id\":\"<BLOCK_ID>\",\"pow_nullifier\":\"<NULLIFIER>\"}"}
```

Recipe C: the same with `"auth_type":"keycard-attestation"` and
`"auth_provider":"keycard_capture_module"`; no `auth_args`.

Recipes D and E: the same with `"auth_type":"logos-allowlist"` or
`"lez-allowlist"`, `"auth_provider":"allowlist_sign_module"` and the
`auth_args` pair, e.g. for D:

```
{"key":"auth_args","value":"{\"node_url\":\"http://127.0.0.1:8080\",\"rate_max\":100,\"audience\":\"\"}"}
```

and for E `{"key":"auth_args","value":"{\"rate_max\":100,\"audience\":\"\"}"}`
(or no pair at all: those are the defaults).

The second argument is the `logos.test` preset's RLN identifier, so the
membership is scoped to delivery. The reply is the membership view with
`"state":"pending"`. Then poll:

```sh
logosctl call liblogos_rln_module get_membership_state \
  logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971 \
  5e269b6a19fce081f5808b13442dcbc3522197638dd38df5a28bc4e55236b977
```

until `"state":"active"` (up to 300 s). `"failed"` carries the reason in
`get_memberships`: `address not allowlisted` (ask the operator),
`credential already used` (this key already got its membership),
`insufficient_balance` (the allocator's payer is empty — tell the operator),
`confirmation_window_elapsed` (registry mismatch or chain trouble).

Notes (the Docker client automates §2–§5: `tools/allocator/docker/CLIENT.md` §5):

- Pass the RLN identifier to logosctl as an `@file` argument (write the hex
  to a file and call with `@rln-id.arg`); a bare hex may be mis-parsed.
- The lez wallet must report `ready` and `get_valid_roots` must return a
  non-empty list BEFORE `register_membership`. The wallet takes about 3
  minutes after the RLN module starts (and needs `use_network testnet`
  while it says "no network selected"); registering earlier spends the
  300 s confirmation window on the wallet sync and ends in
  `confirmation_window_elapsed` after the allocator has already paid.

## 5. Start delivery

```sh
logosctl module load delivery_module
logosctl call delivery_module createNode @logos-test.json
logosctl call delivery_module start
```

Delivery's own `start` of the RLN module finds the live membership and does
not try to provision one. Keep your logosctl session directory: the
membership lives in the RLN module's keystore there.
