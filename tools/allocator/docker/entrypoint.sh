#!/usr/bin/env bash
# tools/allocator/docker/entrypoint.sh — PID 1 of the allocator container: owns
# the daemon, the node identity, the serve call and a health loop.
#
# State, all on $ALLOCATOR_DATA (a volume):
#   node_key.hex              the libp2p private key → the PeerId testers pin
#   wallet-home-<network>/    the lez module's wallet (the PAYER SEED), one per
#                             REGISTRY_REFERENCE: a wallet home is bound to the
#                             sequencer it was created for, so switching between
#                             a local zone and the hosted testnet keeps both
#   consumed_nullifiers-<network>.txt  spent credentials, append-only
#   allocator.json            the hand-off for testers (peer id, multiaddr, …)
#   session/                  logosctl's own state and logs
#   serve.json                the last serve body (for inspection)
#
# Sequence: daemon up → modules → libp2p with the persisted key (refuse to run
# if the PeerId changed: that would orphan every tester) → publish
# allocator.json BEFORE funding → wait for the lez wallet → serve with up to
# up to five verifiers (pow-claim if POW_NODE_URL, keycard-attestation unless
# KEYCARD_TRUSTED_CAS=none, logos-allowlist unless LOGOS_ALLOWLIST=0,
# lez-allowlist unless LEZ_ALLOWLIST=0, eth-allowlist always) → supervise.
# The three allowlist files (eth, logos, lez) are watched by mtime: a change
# to any of them re-serves. The daemon
# dies → exit 1 → compose restarts the container and this script re-serves
# (serve is in-memory on the gifter).
#
# Reachability knobs: ADVERTISE_IP / ADVERTISE_DNS (+ ADVERTISE_PORT when the
# port testers dial differs from LISTEN_PORT, e.g. a port forward) form
# gifter_multiaddr; ALT_MULTIADDRS (comma-separated) is published as
# alt_multiaddrs, informational only.
set -uo pipefail
# Everything this script creates on the volume (node key, payer seed, session)
# is owner-only.
umask 077

. /usr/local/lib/allocator/lib-ctl.sh

DATA="${ALLOCATOR_DATA:-/var/lib/allocator}"
ALLOWLIST="${ALLOWLIST_FILE:-/etc/allocator/allowlist.txt}"
ALLOWLIST_LOGOS="${ALLOWLIST_LOGOS_FILE:-/etc/allocator/allowlist-logos.txt}"
ALLOWLIST_LEZ="${ALLOWLIST_LEZ_FILE:-/etc/allocator/allowlist-lez.txt}"
LOGOS_ALLOWLIST="${LOGOS_ALLOWLIST:-1}"
LEZ_ALLOWLIST="${LEZ_ALLOWLIST:-1}"
LISTEN_PORT="${LISTEN_PORT:-9000}"
REGISTRY_CONFIG="${REGISTRY_CONFIG:?REGISTRY_CONFIG (registry ConfigState hex) is required}"
REGISTRY_REFERENCE="${REGISTRY_REFERENCE:-testnet}"
MAX_RATE_LIMIT="${MAX_RATE_LIMIT:-100}"
MIN_NATIVE_BALANCE="${MIN_NATIVE_BALANCE:-0}"
POW_NODE_URL="${POW_NODE_URL:-}"
POW_AUDIENCE="${POW_AUDIENCE:-}"
# keycard-attestation: comma-separated compressed secp256k1 CA pubkeys; empty
# = the Status production CA only, "none" = the vector is not served.
STATUS_PRODUCTION_CA=029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c
KEYCARD_TRUSTED_CAS="${KEYCARD_TRUSTED_CAS:-}"
ADVERTISE_PORT="${ADVERTISE_PORT:-$LISTEN_PORT}"
ALT_MULTIADDRS="${ALT_MULTIADDRS:-}"
HEALTH_EVERY_S="${HEALTH_EVERY_S:-30}"
OUT_JSON="$DATA/allocator.json"
KEY_FILE="$DATA/node_key.hex"
NULLIFIERS="$DATA/consumed_nullifiers-${REGISTRY_REFERENCE}.txt"
SERVE_JSON="$DATA/serve.json"

# What testers dial: exactly one of ADVERTISE_IP / ADVERTISE_DNS.
if [ -n "${ADVERTISE_DNS:-}" ]; then
    ADVERTISE_ADDR="/dns4/${ADVERTISE_DNS}/tcp/${ADVERTISE_PORT}"
elif [ -n "${ADVERTISE_IP:-}" ]; then
    ADVERTISE_ADDR="/ip4/${ADVERTISE_IP}/tcp/${ADVERTISE_PORT}"
else
    al_die "set ADVERTISE_IP (public IPv4) or ADVERTISE_DNS in allocator.env — testers dial this"
fi

# Trusted keycard CAs, parsed once into a JSON array ([] = not served).
KEYCARD_CAS_JSON=$(CAS="$KEYCARD_TRUSTED_CAS" PROD="$STATUS_PRODUCTION_CA" python3 -I -c '
import json, os, re, sys
raw = os.environ["CAS"].strip()
if raw.strip("\"'"'"' ").lower() == "none":
    print("[]"); sys.exit(0)
if not raw.strip("\"'"'"' "):
    raw = os.environ["PROD"]
out = []
for e in raw.split(","):
    k = e.strip().strip("\"'"'"'").strip().lower()
    if k.startswith("0x"):
        k = k[2:]
    if not k:
        continue
    if not re.fullmatch(r"0[23][0-9a-f]{64}", k):
        sys.exit("not a 33-byte compressed secp256k1 pubkey (66 hex, 02/03 prefix): %r" % e.strip())
    if k not in out:
        out.append(k)
if not out:
    sys.exit("no CA public key listed (leave it empty for the production CA, \"none\" to disable)")
print(json.dumps(out, separators=(",", ":")))
' 2>&1) || al_die "KEYCARD_TRUSTED_CAS: $KEYCARD_CAS_JSON"
for ca in $(printf '%s' "$KEYCARD_CAS_JSON" | python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin)))'); do
    [ "$ca" = "$STATUS_PRODUCTION_CA" ] && continue
    # A test CA's key holder mints unlimited "cards": local zone only, unless
    # the operator explicitly overrides.
    [ "$REGISTRY_REFERENCE" = local ] || [ "${ALLOW_TEST_CA:-0}" = 1 ] \
        || al_die "non-production keycard CA $ca on registry '$REGISTRY_REFERENCE' (set ALLOW_TEST_CA=1 to override)"
    al_say "WARNING: non-production keycard CA $ca trusted (test CA: local zone only, never while publicly reachable)"
done

# The lez module reads its wallet configuration from the daemon's environment;
# the daemon is started from this shell, so export here. The wallet home is on
# the volume (it holds the payer seed). Both payer variables or neither: a key
# imported without its account is ignored and a fresh payer gets derived.
export LOGOSCTL_CONFIG_DIR="${LOGOSCTL_CONFIG_DIR:-$DATA/session}"
export LEE_WALLET_HOME_DIR="$DATA/wallet-home-${REGISTRY_REFERENCE}"
export NSSA_WALLET_HOME_DIR="$LEE_WALLET_HOME_DIR"
export LEZ_RLN_SEQUENCER="${LEZ_RLN_SEQUENCER:-https://testnet.lez.logos.co/}"
if { [ -n "${LEZ_RLN_PAYER:-}" ] && [ -z "${LEZ_RLN_PAYER_KEY:-}" ]; } || { [ -z "${LEZ_RLN_PAYER:-}" ] && [ -n "${LEZ_RLN_PAYER_KEY:-}" ]; }; then
    al_die "LEZ_RLN_PAYER and LEZ_RLN_PAYER_KEY must be set together (or both empty to derive a payer)"
fi
[ -n "${LEZ_RLN_PAYER:-}" ] || unset LEZ_RLN_PAYER LEZ_RLN_PAYER_KEY
export QT_QPA_PLATFORM=offscreen

mkdir -p "$DATA" "$LEE_WALLET_HOME_DIR" "$LOGOSCTL_CONFIG_DIR"
# Wallet homes created before umask 077 (older volumes) are tightened too.
chmod -R go-rwx "$DATA"/wallet-home-* 2>/dev/null || true
touch "$NULLIFIERS"

# daemon.yaml: the image's read-only modules dir (set once per session dir).
if [ ! -f "$LOGOSCTL_CONFIG_DIR/.modules_dirs_set" ]; then
    printf 'version: 2\nmodules_dirs:\n  - %s\n' "${MODULES_DIR:-/opt/modules}" > /tmp/daemon.yaml
    logosctl daemon config set /tmp/daemon.yaml || al_die "logosctl daemon config set failed"
    : > "$LOGOSCTL_CONFIG_DIR/.modules_dirs_set"
fi

stop_daemon() { logosctl daemon stop >/dev/null 2>&1 || true; }
on_term() { al_say "SIGTERM: stopping daemon"; stop_daemon; exit 0; }
trap on_term TERM INT

# ---------------------------------------------------------------- 1. daemon
# A fresh container can never have a live daemon; a stale pid left on the
# volume by the previous container may alias a live process in this one.
rm -f "$LOGOSCTL_CONFIG_DIR/daemon/state.json"
ctl_daemon_start

# ---------------------------------------------------------------- 2. modules
# libp2p first (the gifter opens its client to it on load), the registry
# module and every verifier BEFORE the gifter's serve. serve does not notice
# an absent verifier (the host defers clients), so each load is checked here.
VERIFIER_MODULES=""
[ -z "$POW_NODE_URL" ] || VERIFIER_MODULES="$VERIFIER_MODULES pow_claim_auth_module"
[ "$KEYCARD_CAS_JSON" = "[]" ] || VERIFIER_MODULES="$VERIFIER_MODULES keycard_auth_module"
[ "$LOGOS_ALLOWLIST" = 0 ] || VERIFIER_MODULES="$VERIFIER_MODULES logos_auth_module"
[ "$LEZ_ALLOWLIST" = 0 ] || VERIFIER_MODULES="$VERIFIER_MODULES lez_auth_module"
VERIFIER_MODULES="$VERIFIER_MODULES eth_auth_module"
ctl_load libp2p_module
ctl_load liblogos_lez_rln_module
for m in $VERIFIER_MODULES; do ctl_load "$m"; done
ctl_load rln_gifter_module

# ---------------------------------------------------------------- 3. identity
KEY=$(al_node_key "$KEY_FILE")
PEER=$(al_libp2p_up "/ip4/0.0.0.0/tcp/${LISTEN_PORT}" "$KEY")
if [ -f "$OUT_JSON" ]; then
    PREV=$(al_field "$(cat "$OUT_JSON")" gifter_peer_id)
    if [ -n "$PREV" ] && [ "$PREV" != "$PEER" ]; then
        al_die "PeerId changed: $PREV -> $PEER. node_key.hex no longer matches the published id; restore the key or delete allocator.json to re-publish (every tester holding the old id is orphaned)"
    fi
fi
LISTEN_ADDRS=$(al_res_field libp2p_module peerInfo addrs)
al_say "peer id $PEER, listening on $LISTEN_ADDRS, published as $ADVERTISE_ADDR"

# ---------------------------------------------------------------- 4. publish
# allocator.json before funding: the operator hands out the peer id while the
# payer is still being funded. `served`/`funded` flip later.
auth_types_json() {
    local t='['
    [ -z "$POW_NODE_URL" ] || t="$t\"pow-claim\","
    [ "$KEYCARD_CAS_JSON" = "[]" ] || t="$t\"keycard-attestation\","
    [ "$LOGOS_ALLOWLIST" = 0 ] || t="$t\"logos-allowlist\","
    [ "$LEZ_ALLOWLIST" = 0 ] || t="$t\"lez-allowlist\","
    printf '%s"eth-allowlist"]' "$t"
}
write_out_json() { # <payer> <served:true|false> <funded:true|false>
    PEER="$PEER" ADDR="$ADVERTISE_ADDR" ADDRS="$LISTEN_ADDRS" CFG="$REGISTRY_CONFIG" REF="$REGISTRY_REFERENCE" \
    WAL="$1" SERVED="$2" FUNDED="$3" TYPES="$(auth_types_json)" MAXR="$MAX_RATE_LIMIT" ALT="$ALT_MULTIADDRS" \
    python3 -I - "$OUT_JSON" <<'PY'
import json, os, sys, time
out = {
  "gifter_peer_id": os.environ["PEER"],
  "gifter_multiaddr": os.environ["ADDR"],
  "alt_multiaddrs": [a.strip() for a in os.environ["ALT"].split(",") if a.strip()],
  "listen_addrs": json.loads(os.environ["ADDRS"] or "[]"),
  "registry_id": "logos:%s:%s" % (os.environ["REF"], os.environ["CFG"]),
  "registry_config": os.environ["CFG"],
  "payer": os.environ["WAL"] or None,
  "auth_types": json.loads(os.environ["TYPES"]),
  "open": False,
  "max_rate_limit": int(os.environ["MAXR"]),
  "protocol": "/logos/rln/membership/1.0.0",
  "served": os.environ["SERVED"] == "true",
  "funded": os.environ["FUNDED"] == "true",
  "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as f:
    json.dump(out, f, indent=2); f.write("\n")
os.replace(tmp, sys.argv[1])
PY
}
write_out_json "" false false
al_say "allocator.json published (unserved, unfunded): $OUT_JSON"

# ---------------------------------------------------------------- 5. wallet
# The lez wallet syncs at bring-up; its payer is readable before the first
# sync. Wait for `ready` with no deadline: the sequencer may be slow, and an
# allocator that exits here just restarts without serving.
PAYER=""
wallet_wait() {
    local st state detail last=""
    while :; do
        # A daemon that dies here would otherwise be waited on forever.
        [ -n "$(ctl_daemon_pid)" ] || al_die "daemon died while waiting for the wallet"
        st=$(al_call liblogos_lez_rln_module wallet_status | al_res) || st=""
        state=$(al_field "$st" state); detail=$(al_field "$st" detail)
        [ "$st" = "$last" ] || { al_say "wallet_status: ${st:-<empty>}"; last="$st"; }
        case "$state" in
            ready) PAYER=$(al_field "$st" payer); return 0 ;;
            failed) al_die "lez wallet failed: ${detail:-?}" ;;
        esac
        case "$detail" in
            *"no network selected"*)
                al_say "wallet unbound: use_network $REGISTRY_REFERENCE -> $(al_call liblogos_lez_rln_module use_network "$REGISTRY_REFERENCE" | al_res)" ;;
        esac
        sleep 5
    done
}
wallet_wait
al_say "wallet ready; payer $PAYER — fund it with native balance on the ${REGISTRY_REFERENCE} zone (no faucet)"
write_out_json "$PAYER" false false

# ---------------------------------------------------------------- 6. serve
read_allowlist() { # -> JSON array of 0x… addresses
    python3 -I - "$ALLOWLIST" <<'PY'
import json, sys
addrs = []
try:
    for line in open(sys.argv[1]):
        line = line.split("#", 1)[0].strip().lower()
        if line.startswith("0x") and len(line) == 42:
            addrs.append(line)
except FileNotFoundError:
    pass
print(json.dumps(addrs, separators=(",", ":")))
PY
}
read_allowlist_logos() { # -> JSON array of 64-hex public keys (0x stripped, lowercase)
    python3 -I - "$ALLOWLIST_LOGOS" <<'PY'
import json, re, sys
keys = []
try:
    for n, raw in enumerate(open(sys.argv[1]), 1):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if line.startswith("0x"):
            line = line[2:]
        if re.fullmatch(r"[0-9a-f]{64}", line):
            if line not in keys:
                keys.append(line)
        else:
            sys.stderr.write("allowlist-logos.txt line %d dropped (not 64 hex): %.20s\n" % (n, raw.strip()))
except FileNotFoundError:
    pass
print(json.dumps(keys, separators=(",", ":")))
PY
}
read_allowlist_lez() { # -> JSON array of account ids (64 hex or base58, passed as given; the verifier decodes)
    python3 -I - "$ALLOWLIST_LEZ" <<'PY'
import json, re, sys
ids = []
try:
    for n, raw in enumerate(open(sys.argv[1]), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", line):
            line = line.lower()
            if line.startswith("0x"):
                line = line[2:]
        elif not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,50}", line):
            sys.stderr.write("allowlist-lez.txt line %d dropped (not 64 hex or base58): %.20s\n" % (n, raw.strip()))
            continue
        if line not in ids:
            ids.append(line)
except FileNotFoundError:
    pass
print(json.dumps(ids, separators=(",", ":")))
PY
}
serve_json() {
    CFG="$REGISTRY_CONFIG" NUL="$NULLIFIERS" MAXR="$MAX_RATE_LIMIT" NODE="$POW_NODE_URL" AUD="$POW_AUDIENCE" \
    AUDIT="$DATA/pow-claim-audit.jsonl" ALLOW="$(read_allowlist)" CAS="$KEYCARD_CAS_JSON" \
    LOGOS_ON="$LOGOS_ALLOWLIST" LOGOS_KEYS="$(read_allowlist_logos)" \
    LEZ_ON="$LEZ_ALLOWLIST" LEZ_IDS="$(read_allowlist_lez)" python3 -I -c '
import json, os
av = {"eth-allowlist": {"module": "eth_auth_module",
                        "config": {"allowlist": json.loads(os.environ["ALLOW"])}}}
if os.environ["LOGOS_ON"] != "0":
    av["logos-allowlist"] = {"module": "logos_auth_module",
                             "config": {"allowlist": json.loads(os.environ["LOGOS_KEYS"])}}
if os.environ["LEZ_ON"] != "0":
    av["lez-allowlist"] = {"module": "lez_auth_module",
                           "config": {"allowlist": json.loads(os.environ["LEZ_IDS"])}}
if os.environ["NODE"]:
    av["pow-claim"] = {"module": "pow_claim_auth_module", "config": {
        "node_url": os.environ["NODE"], "audience": os.environ["AUD"], "min_payout": 0,
        "allow_direct_ownership": True, "allow_spend_locator": False,
        "http_timeout_ms": 5000, "audit_log": os.environ["AUDIT"]}}
cas = json.loads(os.environ["CAS"])
if cas:
    av["keycard-attestation"] = {"module": "keycard_auth_module",
                                 "config": {"trusted_cas": cas}}
o ={"config": os.environ["CFG"], "wallet": "", "authVerifiers": av,
     "consumedNullifiersPath": os.environ["NUL"], "maxRateLimit": int(os.environ["MAXR"])}
print(json.dumps(o, separators=(",", ":")))
'
}
do_serve() {
    local body res
    body=$(serve_json) || al_die "serve body could not be built"
    printf '%s\n' "$body" > "$SERVE_JSON"
    res=$(al_call rln_gifter_module serve "$body" | al_res) || res=""
    case "$res" in
        *mounted*true*) al_say "serve: $res (allowlist: $(read_allowlist))" ;;
        *) al_die "serve did not mount: ${res:-<empty>}" ;;
    esac
}
# The eth allowlist may be empty at first: eth requests are then answered
# with the verifier's "config.allowlist is empty" until an address is added
# (still a complete libp2p round trip). pow-claim needs no per-tester setup.
do_serve
[ "$(read_allowlist)" != "[]" ] || al_say "WARNING: $ALLOWLIST lists no address yet — eth-allowlist requests will be answered 'allowlist is empty' until one is added"
[ "$LOGOS_ALLOWLIST" = 0 ] || [ "$(read_allowlist_logos 2>/dev/null)" != "[]" ] || al_say "WARNING: $ALLOWLIST_LOGOS lists no key yet — logos-allowlist requests will be answered 'allowlist is empty' until one is added"
[ "$LEZ_ALLOWLIST" = 0 ] || [ "$(read_allowlist_lez 2>/dev/null)" != "[]" ] || al_say "WARNING: $ALLOWLIST_LEZ lists no account id yet — lez-allowlist requests will be answered 'allowlist is empty' until one is added"
allow_mtimes() { # one token over the three watched files; any change differs
    local f
    for f in "$ALLOWLIST" "$ALLOWLIST_LOGOS" "$ALLOWLIST_LEZ"; do
        printf '%s,' "$(stat -c %Y "$f" 2>/dev/null || echo 0)"
    done
}
ALLOW_MTIME=$(allow_mtimes)
write_out_json "$PAYER" true false
al_say "serving $(auth_types_json) on $ADVERTISE_ADDR for registry logos:${REGISTRY_REFERENCE}:${REGISTRY_CONFIG}"

# ---------------------------------------------------------------- 7. supervise
# SIGHUP also forces a re-serve (e.g. after editing the allowlist). Liveness
# = daemon pid + a TCP connect on the listen port; three consecutive misses
# of either (not one: a busy host, or a `daemon status` call that times out,
# must not bounce the service) exit for a restart.
RESERVE=0
trap 'RESERVE=1' HUP
FUNDED=false
BAL_LAST=""
MISSES=0
DMISS=0
while :; do
    sleep "$HEALTH_EVERY_S" &
    wait $! 2>/dev/null
    if [ -n "$(ctl_daemon_pid)" ]; then
        DMISS=0
    else
        DMISS=$((DMISS + 1))
        al_say "daemon status reports no running daemon (miss $DMISS/3)"
        if [ "$DMISS" -ge 3 ]; then
            al_say "daemon is gone — exiting so the container restarts and re-serves"
            stop_daemon; exit 1
        fi
        continue
    fi
    if al_port_open "$LISTEN_PORT"; then
        MISSES=0
    else
        MISSES=$((MISSES + 1))
        al_say "nothing accepts on port $LISTEN_PORT (miss $MISSES/3)"
        if [ "$MISSES" -ge 3 ]; then
            al_say "listener gone — exiting for a restart"
            stop_daemon; exit 1
        fi
    fi
    mt=$(allow_mtimes)
    if [ "$mt" != "$ALLOW_MTIME" ] || [ "$RESERVE" = 1 ]; then
        al_say "allowlist (eth/logos/lez) changed (or SIGHUP): re-serving"
        ALLOW_MTIME="$mt"; RESERVE=0
        do_serve
    fi
    bal=$(al_res_field liblogos_lez_rln_module get_native_balance balance "")
    if [ -n "$bal" ] && [ "$bal" != "$BAL_LAST" ]; then
        al_say "payer $PAYER native balance: $bal"
        BAL_LAST="$bal"
        if [ "$FUNDED" = false ] && [ "$bal" -ge "$MIN_NATIVE_BALANCE" ] 2>/dev/null && [ "$MIN_NATIVE_BALANCE" -gt 0 ] 2>/dev/null; then
            FUNDED=true
            al_say "payer funded (>= $MIN_NATIVE_BALANCE)"
            write_out_json "$PAYER" true true
        fi
    fi
done
