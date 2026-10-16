#!/usr/bin/env bash
# node2-up.sh — bring up a FOLLOWER logos-blockchain node (node 2) in its own
# logoscore daemon, syncing from a running node 1 (node-up.sh run).
#
# Usage: node2-up.sh --node1-run RUN_A [--no-wait]   start node 2; last stdout line = run dir
#        node2-up.sh --down RUN_B                     stop node 2's daemon
#
# Env: POC_RUN_DIR (required, fresh dir for node 2), POC2_HTTP_PORT (18081),
#      POC2_P2P_PORT (13001), POC2_BLEND_PORT (3401), POC2_WAIT_S (300),
#      EXTRA_LGX (space-separated), BM_LGX, LOGOSCORE, POC_KEEP_ON_FAIL.
# Never touches runs/latest. Writes <B>/env.sh and <B>/node2-up.json (timings, arg form, patch).
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$POC_DIR/lib/logoscore.sh"
NODEQ="$POC_DIR/lib/nodeq.py"

if [ "${1:-}" = "--down" ]; then
    run="${2:-}"
    [ -n "$run" ] && [ -d "$run" ] || poc_die "usage: node2-up.sh --down RUN_B"
    run="$(cd "$run" && pwd -P)"
    [ -f "$run/env.sh" ] && . "$run/env.sh"
    POC_RUN_DIR="$run"; POC_DAEMON_PID=""
    daemon_stop "$run"
    exit 0
fi

RUN_A=""; NO_WAIT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --node1-run) RUN_A="${2:-}"; shift 2 ;;
        --no-wait) NO_WAIT=1; shift ;;
        *) poc_die "unknown argument $1" ;;
    esac
done
[ -n "$RUN_A" ] && [ -f "$RUN_A/env.sh" ] || poc_die "--node1-run RUN_A (with env.sh) required"
RUN_A="$(cd "$RUN_A" && pwd -P)"
[ -n "${POC_RUN_DIR:-}" ] || poc_die "POC_RUN_DIR (node 2 run dir) is required"
B="$POC_RUN_DIR"
[ ! -e "$B/daemon.pid" ] || poc_die "$B already has a daemon.pid; pick a fresh POC_RUN_DIR"
mkdir -p "$B/node" "$B/samples"
B="$(cd "$B" && pwd -P)"
[ "$B" != "$RUN_A" ] || poc_die "node 2 run dir must differ from node 1's"

HTTP2="${POC2_HTTP_PORT:-18081}"
P2P2="${POC2_P2P_PORT:-13001}"
BLEND2="${POC2_BLEND_PORT:-3401}"
WAIT_S="${POC2_WAIT_S:-300}"

# node 1 facts come from its env.sh (read in a subshell: it would clobber POC_RUN_DIR etc.)
eval "$(. "$RUN_A/env.sh"; printf 'A_URL=%q A_LOGOSCORE=%q A_P2P=%q\n' "$POC_NODE_URL" "$LOGOSCORE" "$POC_P2P_PORT")"
LOGOSCORE="${LOGOSCORE:-$A_LOGOSCORE}"
[ -x "$LOGOSCORE" ] || poc_die "no logoscore at $LOGOSCORE"
if [ -z "${BM_LGX:-}" ]; then
    BM_LGX=$(find -L "$POC_DIR/runs/bm-lgx/" -maxdepth 1 -name '*.lgx' 2>/dev/null | head -1)
fi
[ -f "${BM_LGX:-}" ] || poc_die "no blockchain_module .lgx (BM_LGX or runs/bm-lgx/*.lgx)"
command -v curl >/dev/null || poc_die "curl not found"

busy() { lsof -nP -iUDP:"$1" >/dev/null 2>&1 || lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
for port in "$P2P2" "$BLEND2" "$HTTP2"; do
    if busy "$port"; then
        { lsof -nP -iUDP:"$port"; lsof -nP -iTCP:"$port" -sTCP:LISTEN; } >&2 || true
        poc_die "port $port is busy (node 2 needs POC2_P2P_PORT=$P2P2 UDP, POC2_BLEND_PORT=$BLEND2 UDP, POC2_HTTP_PORT=$HTTP2 TCP)"
    fi
done

# --- node 1 must answer; get its PeerId
python3 -I "$NODEQ" --node-url "$A_URL" info >/dev/null || poc_die "node 1 ($A_URL) does not answer /cryptarchia/info"
PEER1=$(python3 -I "$NODEQ" --node-url "$A_URL" netinfo | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["peer_id"] or "")')
[ -n "$PEER1" ] || poc_die "node 1 /network/info has no peer_id"
poc_say "node 1 PeerId (/network/info): $PEER1"
gp=$(POC_RUN_DIR="$RUN_A" CALL_TIMEOUT=30 lc_call blockchain_module get_peer_id "$RUN_A/node/node-config.yaml" 2>/dev/null | POC_RUN_DIR="$RUN_A" jres | jval || true)
if [ "$gp" = "$PEER1" ]; then poc_say "get_peer_id agrees"; else poc_say "WARN get_peer_id -> '${gp:-<none>}' (differs from /network/info; using /network/info)"; fi
MADDR="/ip4/127.0.0.1/udp/$A_P2P/quic-v1/p2p/$PEER1"

# --- modules + daemon (POC_RUN_DIR now = node 2's)
POC_RUN_DIR="$B"
MODULES_DIR="$B/modules"
mkdir -p "$MODULES_DIR"
install_lgx "$BM_LGX" "$MODULES_DIR"
for extra in ${EXTRA_LGX:-}; do install_lgx "$extra" "$MODULES_DIR"; done
daemon_start "$B" "$MODULES_DIR"
UP_OK=0
trap '[ "$UP_OK" = 1 ] || [ "${POC_KEEP_ON_FAIL:-0}" = 1 ] || daemon_stop "$B"' EXIT
URL2="http://127.0.0.1:$HTTP2"

lc_load blockchain_module

# --- generate_user_config: probe the argument form
USER_CFG="$B/node/user_config.yaml"
GJSON=$(python3 -I -c '
import json, sys
b, a, h, p, bl, maddr = sys.argv[1:7]
print(json.dumps({"output": b + "/node/user_config.yaml", "net_port": int(p), "blend_port": int(bl),
                  "http_addr": "127.0.0.1:" + h, "initial_peers": [maddr],
                  "state_path": b + "/node/state", "storage_path": b + "/node/db",
                  "logs_path": b + "/node/logs"}, separators=(",", ":")))' "$B" "$A_URL" "$HTTP2" "$P2P2" "$BLEND2" "$MADDR")
gen_ok() { # stdin: envelope
    python3 -I -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if line.startswith("{"):
        try: d = json.loads(line)
        except Exception: continue
        r = d.get("result")
        if isinstance(r, str):
            try: r = json.loads(r)
            except Exception: pass
        sys.exit(0 if d.get("status") == "ok" and isinstance(r, dict) and r.get("success") else 1)
sys.exit(1)'
}
ARG_FORM=""
for form in bare argfile encoded; do
    rm -f "$USER_CFG" "$B/node/keystore.yaml"
    case "$form" in
        bare)    out=$(CALL_TIMEOUT=60 lc_call blockchain_module generate_user_config "$GJSON" || true) ;;
        argfile) out=$(CALL_TIMEOUT=60 lc_call blockchain_module generate_user_config "$(argfile gen "$GJSON")" || true) ;;
        encoded) out=$(CALL_TIMEOUT=60 lc_call blockchain_module generate_user_config "$(python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$GJSON")" || true) ;;
    esac
    poc_say "generate_user_config [$form] -> ${out:-<no output>}"
    if printf '%s' "$out" | gen_ok && [ -s "$USER_CFG" ] && [ -s "$B/node/keystore.yaml" ]; then ARG_FORM="$form"; break; fi
done
[ -n "$ARG_FORM" ] || poc_die "generate_user_config failed with every arg form"
poc_say "generate_user_config arg form that worked: $ARG_FORM"

PATCHED="$B/node/user_config.patched.yaml"
python3 -I "$POC_DIR/lib/node2_config.py" --in "$USER_CFG" --out "$PATCHED" \
    --initial-peer "$MADDR" --http "127.0.0.1:$HTTP2" > "$B/node2-config-summary.json" \
    || poc_die "node2_config.py failed"

cat > "$B/env.sh" <<EOF
export LOGOSCORE='$LOGOSCORE'
export POC_RUN_DIR='$B'
export POC_DAEMON_PID='$POC_DAEMON_PID'
export POC_NODE2_URL='$URL2'
export POC_NODE1_PEER_ID='$PEER1'
export POC_MODULES_DIR='$MODULES_DIR'
export POC2_HTTP_PORT='$HTTP2'
export POC2_P2P_PORT='$P2P2'
export POC2_BLEND_PORT='$BLEND2'
EOF

DEP="$RUN_A/node/deployment.yaml"
[ -f "$DEP" ] || poc_die "no node 1 patched deployment at $DEP"
T0=$(date +%s)
poc_say "start $PATCHED $DEP"
out=$(CALL_TIMEOUT=120 lc_call blockchain_module start "$PATCHED" "$DEP" || true)
poc_say "start -> ${out:-<no output>}"
printf '%s' "$out" | gen_ok || poc_die "start failed: $out"

T_HEIGHT=""; T_ONLINE=""; ONLINE_JSON="null"; LAGS="[]"
if [ "$NO_WAIT" = 1 ]; then
    poc_say "--no-wait: not waiting for Online"
else
    # height > 0
    while :; do
        el=$(( $(date +%s) - T0 ))
        h=$(python3 -I "$NODEQ" --node-url "$URL2" info 2>/dev/null \
            | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin)["cryptarchia_info"]["height"])
except Exception: print(-1)' || echo -1)
        if [ "$h" -gt 0 ] 2>/dev/null; then T_HEIGHT=$el; poc_say "height $h after ${el}s"; break; fi
        [ "$el" -lt "$WAIT_S" ] || poc_die "node 2 height still $h after ${WAIT_S}s (see $B/node/logs, $B/daemon.log)"
        [ $((el % 10)) -lt 2 ] && poc_say "t=${el}s node2 height=$h"
        sleep 2
    done
    rem=$(( WAIT_S - ( $(date +%s) - T0 ) )); [ "$rem" -gt 5 ] || rem=5
    ONLINE_JSON=$(python3 -I "$NODEQ" --node-url "$URL2" wait-online --timeout "$rem") \
        || poc_die "node 2 never reached Online within ${WAIT_S}s (see $B/node/logs, $B/daemon.log)"
    T_ONLINE=$(( $(date +%s) - T0 ))
    poc_say "Online after ${T_ONLINE}s: $ONLINE_JSON"

    NI=$(python3 -I "$NODEQ" --node-url "$URL2" netinfo)
    poc_say "node 2 netinfo: $NI"
    printf '%s' "$NI" | python3 -I -c '
import json, sys
peer = sys.argv[1]
d = json.load(sys.stdin)
sys.exit(0 if peer in (d.get("connected_peers") or []) else 1)' "$PEER1" \
        || poc_die "node 1 ($PEER1) is not among node 2's connected peers: $NI"

    : > "$B/samples/lag.jsonl"
    for i in 1 2 3; do
        python3 -I -c '
import json, sys
sys.path.insert(0, sys.argv[1])
import nodeq
_, c1 = nodeq.cinfo(sys.argv[2]); _, c2 = nodeq.cinfo(sys.argv[3])
print(json.dumps({"node1_lib_slot": c1["lib_slot"], "node2_lib_slot": c2["lib_slot"],
                  "lib_slot_lag": c1["lib_slot"] - c2["lib_slot"],
                  "node1_height": c1["height"], "node2_height": c2["height"],
                  "node1_tip": c1["tip"], "node2_tip": c2["tip"]}))' \
            "$POC_DIR/lib" "$A_URL" "$URL2" >> "$B/samples/lag.jsonl" || true
        [ "$i" = 3 ] || sleep 10
    done
    cat "$B/samples/lag.jsonl" >&2
    LAGS=$(python3 -I -c '
import json, sys
print(json.dumps([json.loads(l) for l in open(sys.argv[1]) if l.strip()]))' "$B/samples/lag.jsonl")
fi

python3 -I -c '
import json, sys
a = sys.argv
out = {"arg_form": a[1], "node1_peer_id": a[2], "initial_peer": a[3], "node2_started_epoch": int(a[4]),
       "t_height_gt0_s": int(a[5]) if a[5] else None, "t_online_s": int(a[6]) if a[6] else None,
       "online": json.loads(a[7]), "lib_lag_samples": json.loads(a[8]),
       "config": json.load(open(a[9])), "generate_user_config_json": json.loads(a[10])}
json.dump(out, open(a[11], "w"), indent=1)' \
    "$ARG_FORM" "$PEER1" "$MADDR" "$T0" "$T_HEIGHT" "$T_ONLINE" "$ONLINE_JSON" "$LAGS" \
    "$B/node2-config-summary.json" "$GJSON" "$B/node2-up.json"

poc_say "node 2 up: pid $POC_DAEMON_PID, $URL2, env $B/env.sh; stop with $0 --down $B"
UP_OK=1
printf '%s\n' "$B"
