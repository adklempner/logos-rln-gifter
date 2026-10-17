#!/usr/bin/env bash
# tools/allocator/docker/client-entrypoint.sh — the CLIENT side of the
# allocation protocol in the same image: load the client modules, bring up a
# libp2p node, and send one request to the allocator named in client.env.
#
# This is the connectivity + module-loading probe for a tester machine. It
# does not need a funded payer, a registry or the RLN module: it speaks to
# the allocator over libp2p exactly as liblogos_rln_module would, and
# classifies the reply:
#   exit 0  the allocator answered (its reply is printed: "address not
#           allowlisted" = reachable, not allowlisted yet; "insufficient_
#           balance" = allowlisted AND the allocator reached its registry;
#           "attestation verification failed" = the keycard verifier refused)
#   exit 2  no libp2p connectivity (the client's own "protocolRequest:"
#           error), or no reply within the CLI deadline
#   exit 1  something on this side failed (module load, node, producer
#           "auth provider …", malformed commitment / payload); nothing dialled
# CLIENT_AUTH_PAYLOAD (hex) sends a precomputed payload instead of naming a
# producer; CLIENT_IDENTITY_COMMITMENT fixes the commitment (a keycard
# attestation is bound to one). CLIENT_KEEP=1 keeps the container running
# afterwards for `docker compose exec client logosctl …` experiments.
#
# CLIENT_MODE=delivery (delivery-compose.yml) instead runs a long-lived
# delivery_module node that obtains its RLN membership through the allocator
# and uses it: client-delivery.sh, which leaves this script before any of the
# probe below runs.
set -uo pipefail

. /usr/local/lib/allocator/lib-ctl.sh

CLIENT_MODE="${CLIENT_MODE:-probe}"
case "$CLIENT_MODE" in
    probe|delivery) ;;
    *) al_die "CLIENT_MODE must be probe or delivery, got '$CLIENT_MODE'" ;;
esac
DATA="${CLIENT_DATA:-/var/lib/allocator-client}"
ALLOCATOR_PEER_ID="${ALLOCATOR_PEER_ID:?ALLOCATOR_PEER_ID is required (allocator.json gifter_peer_id)}"
ALLOCATOR_MULTIADDR="${ALLOCATOR_MULTIADDR:?ALLOCATOR_MULTIADDR is required (allocator.json gifter_multiaddr)}"
AUTH_TYPE="${CLIENT_AUTH_TYPE:-eth-allowlist}"
AUTH_PROVIDER="${CLIENT_AUTH_PROVIDER:-eth_sign_module}"
AUTH_ARGS="${CLIENT_AUTH_ARGS:-}"
RATE="${CLIENT_RATE:-100}"
# A precomputed auth payload (hex, e.g. a keycard attestation TLV) is sent
# verbatim as authPayload: no producer module is loaded or named.
AUTH_PAYLOAD="${CLIENT_AUTH_PAYLOAD:-}"
[ -z "$AUTH_PAYLOAD" ] || { AUTH_PROVIDER=""; AUTH_ARGS=""; }
# A payload bound to a commitment (keycard) needs that commitment sent.
IDC_FIXED=$(printf '%s' "${CLIENT_IDENTITY_COMMITMENT:-}" | tr -d '[:space:]' | tr 'A-F' 'a-f')
IDC_FIXED="${IDC_FIXED#0x}"
ADDR=""

export LOGOSCTL_CONFIG_DIR="${LOGOSCTL_CONFIG_DIR:-$DATA/session}"
export QT_QPA_PLATFORM=offscreen
mkdir -p "$DATA" "$LOGOSCTL_CONFIG_DIR"
if [ ! -f "$LOGOSCTL_CONFIG_DIR/.modules_dirs_set" ]; then
    printf 'version: 2\nmodules_dirs:\n  - %s\n' "${MODULES_DIR:-/opt/modules}" > /tmp/daemon.yaml
    logosctl daemon config set /tmp/daemon.yaml || al_die "logosctl daemon config set failed"
    : > "$LOGOSCTL_CONFIG_DIR/.modules_dirs_set"
fi
# Delivery mode only: its event watchers.
WATCH_PIDS=""
stop_watchers() {
    # shellcheck disable=SC2086  # a list of pids
    [ -z "$WATCH_PIDS" ] || kill $WATCH_PIDS 2>/dev/null
}
trap 'logosctl daemon stop >/dev/null 2>&1; stop_watchers; exit 0' TERM INT
trap stop_watchers EXIT

# ---------------------------------------------------------------- delivery mode
# The env the daemon must inherit (wallet home, sequencer, rln presets) is
# set before it starts; cd_main returns only through al_die.
if [ "$CLIENT_MODE" = delivery ]; then
    . /usr/local/lib/allocator/client-delivery.sh
    cd_env_pre_daemon
    rm -f "$LOGOSCTL_CONFIG_DIR/daemon/state.json"
    ctl_daemon_start
    cd_main
    exit 1
fi

# ---------------------------------------------------------------- daemon + modules
# A fresh container can never have a live daemon; a stale pid left on the
# volume by the previous container may alias a live process in this one.
rm -f "$LOGOSCTL_CONFIG_DIR/daemon/state.json"
ctl_daemon_start
# libp2p first (the gifter opens its client to it on load); the producer the
# request will name must be loaded before the request.
ctl_load libp2p_module
ctl_load rln_gifter_module
[ -z "$AUTH_PROVIDER" ] || ctl_load "$AUTH_PROVIDER"
al_say "modules: $(ctl --json module ls 2>/dev/null | python3 -I -c 'import json,sys
try:
    print(" ".join("%s@%s" % (m["name"], m.get("version","")) for m in json.load(sys.stdin) if m.get("status") == "loaded"))
except Exception: print("?")')"

# ---------------------------------------------------------------- node
# Ephemeral port, no key persistence: a client's PeerId is not an identity
# anyone pins. 0.0.0.0 so the allocator's reply path works from any interface.
PEER=$(al_libp2p_up_any "/ip4/0.0.0.0/tcp/0")
al_say "client peer id $PEER"

# ---------------------------------------------------------------- producer
# A private_key in CLIENT_AUTH_ARGS is imported into the module first, so the
# printed address is the one that will sign (the module's own key is minted
# fresh when the host gives it no persistence path, which logosctl does for
# a `run --rm` client; a fixed key keeps the allowlist entry stable).
case "$AUTH_PROVIDER" in
    eth_sign_module)
        PK=$(ARGS="$AUTH_ARGS" python3 -I -c 'import json, os
try: print(json.loads(os.environ["ARGS"]).get("private_key", "") or "")
except Exception: print("")')
        if [ -n "$PK" ]; then
            ADDR=$(al_field "$(al_call eth_sign_module import_key "$PK" | al_res)" address)
            [ -n "$ADDR" ] || al_die "eth_sign_module.import_key refused the private_key in CLIENT_AUTH_ARGS"
            al_say "eth-allowlist address of the supplied key (give this to the allocator operator): $ADDR"
        else
            ADDR=$(al_res_field eth_sign_module address address)
            [ -n "$ADDR" ] || al_die "eth_sign_module.address answered nothing"
            al_say "eth-allowlist address (give this to the allocator operator): $ADDR — minted per run unless the module has a persistence path; set CLIENT_AUTH_ARGS={\"private_key\":\"0x…\"} for a stable one"
        fi ;;
esac

# ---------------------------------------------------------------- request
# A canonical BN254 commitment (31 random bytes + a small top byte): the
# requester refuses anything else before dialling.
# CLIENT_IDENTITY_COMMITMENT overrides it.
IDC="${IDC_FIXED:-$(openssl rand -hex 31)0a}"
BODY=$(IDC="$IDC" PEER="$ALLOCATOR_PEER_ID" MADDR="$ALLOCATOR_MULTIADDR" AT="$AUTH_TYPE" PROV="$AUTH_PROVIDER" ARGS="$AUTH_ARGS" PAY="$AUTH_PAYLOAD" RATE="$RATE" python3 -I -c '
import json, os
o = {"gifterPeerId": os.environ["PEER"], "gifterMultiaddr": os.environ["MADDR"],
     "identityCommitment": os.environ["IDC"], "rate": int(os.environ["RATE"])}
if os.environ["AT"] != "none":
    o["authType"] = os.environ["AT"]
    if os.environ["PAY"]:
        o["authPayload"] = os.environ["PAY"]
    elif os.environ["PROV"]:
        o["authProvider"] = os.environ["PROV"]
    if os.environ["ARGS"]:
        o["authArgs"] = json.loads(os.environ["ARGS"])
print(json.dumps(o, separators=(",", ":")))
') || al_die "request body could not be built (CLIENT_AUTH_ARGS not JSON?)"
al_say "request -> $ALLOCATOR_PEER_ID @ $ALLOCATOR_MULTIADDR ($AUTH_TYPE via ${AUTH_PROVIDER:-raw authPayload}, commitment $IDC)"
send_request() { # sets RES and ELAPSED
    local t0 t1 env_out
    t0=$(date +%s)
    env_out=$(CALL_TIMEOUT="${CALL_TIMEOUT:-240}" al_call rln_gifter_module request "$BODY") || env_out=""
    t1=$(date +%s)
    RES=$(printf '%s' "$env_out" | al_res)
    ELAPSED=$((t1 - t0))
    al_say "reply after $ELAPSED s: ${RES:-<no reply>}"
}
send_request
# The logosctl call deadline (~20 s, lib-ctl.sh) is shorter than a hosted
# testnet registration (measured: the first testnet grant answered nothing at
# 19 s and had landed by 90 s). An empty reply therefore means "unknown", not
# "failed": wait, re-send the SAME body (same credential, same commitment),
# and read `credential already used` as the proof that the first attempt was
# granted. A credential that was not consumed simply gets its real reply now.
RETRIED=0
if [ -z "$RES" ]; then
    W="${CLIENT_CONFIRM_WAIT_S:-120}"
    al_say "no reply within the CLI deadline; waiting ${W} s, then re-sending the same request to learn the outcome"
    sleep "$W"
    RETRIED=1
    CALL_TIMEOUT=240 send_request
fi
printf '%s\n' "${RES:-}" > "$DATA/last-reply.json"

RC=0
# The gifter client prefixes its own libp2p failures with "protocolRequest:"
# and producer failures with "auth provider "; everything else came back from
# the allocator, including its own timeouts (sequencer, pow node), so free-form
# words like "timed out" or "dial" are NOT taken for a connectivity failure.
case "$RES" in
    *'"error":"protocolRequest:'*)
        al_say "RESULT: NO LIBP2P CONNECTIVITY to the allocator (check ALLOCATOR_MULTIADDR, the allocator's port mapping and firewall): $RES"; RC=2 ;;
    *'"error":"auth provider '*|*"id_commitment hex"*|*"authPayload hex"*|*"mutually exclusive"*|*"needs authPayload"*)
        al_say "RESULT: LOCAL FAILURE — $RES"; RC=1 ;;
    *"attestation verification failed"*)
        al_say "RESULT: CONNECTED — keycard verifier refused the attestation (CA not trusted or bad payload)" ;;
    *"not allowlisted"*)
        al_say "RESULT: CONNECTED — the allocator verified the request and refused this address; ask the operator to allowlist $ADDR" ;;
    *"allowlist is empty"*)
        al_say "RESULT: CONNECTED — the allocator answered; its eth allowlist is still empty, ask the operator to add $ADDR" ;;
    *"insufficient_balance"*)
        al_say "RESULT: CONNECTED and ALLOWLISTED — the allocator reached its registry; its payer is not funded yet" ;;
    *"credential already used"*)
        if [ "$RETRIED" = 1 ]; then
            al_say "RESULT: GRANTED on the first attempt (the CLI deadline hid the reply; the re-send was refused as already used) — commitment $IDC"
        else
            al_say "RESULT: CONNECTED — this credential (address / claim / card) already received its membership"
        fi ;;
    *"leaf_index"*|*"leafIndex"*)
        al_say "RESULT: CONNECTED — membership granted: $RES" ;;
    # After "credential already used": that reply names keycard-attestation too.
    *"attestation"*)
        al_say "RESULT: CONNECTED — keycard verifier refused the attestation (CA not trusted or bad payload)" ;;
    # The logosctl call deadline (~20 s, lib-ctl.sh) vs the allocator's 150 s
    # confirm budget: whether a slow GRANT on the hosted testnet lands here is
    # unverified.
    "")
        al_say "RESULT: no reply twice (CLI deadline) — outcome unknown; check the allocator log for commitment $IDC"; RC=2 ;;
    *)
        al_say "RESULT: CONNECTED — allocator replied: $RES" ;;
esac

if [ "${CLIENT_KEEP:-0}" = 1 ]; then
    al_say "CLIENT_KEEP=1: staying up (docker compose exec client logosctl …)"
    while :; do sleep 3600 & wait $!; done
fi
logosctl daemon stop >/dev/null 2>&1
exit "$RC"
