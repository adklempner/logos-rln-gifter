#!/usr/bin/env bash
# node-up.sh — bring up a single logos-blockchain node inside logoscore
# (blockchain_module, standalone config + fast-mining deployment).
#
# Usage: node-up.sh [--no-wait]     start a fresh node, wait for height > 0
#        node-up.sh --down [RUN]    stop the daemon of RUN (default: runs/latest)
#
# Env: POC_RUN_DIR (default runs/<YYYYmmdd-HHMMSS>), POC_HTTP_PORT (18080),
#      POC_P2P_PORT (13000; standalone default 3000 often clashes with other local nodes),
#      POC_K (auto-claim key), LOGOSCORE, BM_LGX, EXTRA_LGX (space-separated),
#      POC_REWARD_POOL (1000000), POC_RATE_NUM (3000; see lib/node_config.py), POC_WAIT_S (180).
# Writes <run>/env.sh for later scripts to source; runs/latest -> <run>.
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$POC_DIR/lib/logoscore.sh"

LB_REV=2c652646d74354b2877620bf0bc53b4c4d3f18e4
LB_REPO="${LB_REPO:-$POC_DIR/../../../logos-blockchain}"

if [ "${1:-}" = "--down" ]; then
    run="${2:-$POC_DIR/runs/latest}"
    [ -d "$run" ] || poc_die "no run dir $run"
    run="$(cd "$run" && pwd -P)"
    [ -f "$run/env.sh" ] && . "$run/env.sh"
    POC_RUN_DIR="$run"; POC_DAEMON_PID=""
    daemon_stop "$run"
    exit 0
fi
NO_WAIT=0
[ "${1:-}" = "--no-wait" ] && NO_WAIT=1

POC_HTTP_PORT="${POC_HTTP_PORT:-18080}"
POC_P2P_PORT="${POC_P2P_PORT:-13000}"
POC_K="${POC_K:-e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07}"
POC_REWARD_POOL="${POC_REWARD_POOL:-1000000}"
LOGOSCORE="${LOGOSCORE:-$POC_DIR/runs/logos/bin/logoscore}"
[ -x "$LOGOSCORE" ] || poc_die "no logoscore at $LOGOSCORE (nix build github:logos-co/logos-logoscore-cli/d015a40c5f1c9c8ec1de5575d057410e856f8bd9 -o runs/logos)"
if [ -z "${BM_LGX:-}" ]; then
    BM_LGX=$(find -L "$POC_DIR/runs/bm-lgx/" -maxdepth 1 -name '*.lgx' 2>/dev/null | head -1)
fi
[ -f "${BM_LGX:-}" ] || poc_die "no blockchain_module .lgx (BM_LGX or runs/bm-lgx/*.lgx)"
command -v curl >/dev/null || poc_die "curl not found"

# --- preflight: p2p swarm (UDP, POC_P2P_PORT), 3400 (blend quic UDP, fixed by the
# genesis SDP locator), HTTP (TCP). lsof with two -i specs exits 1 unless BOTH match,
# so each protocol is probed on its own.
busy() { lsof -nP -iUDP:"$1" >/dev/null 2>&1 || lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
for port in "$POC_P2P_PORT" 3400 "$POC_HTTP_PORT"; do
    if busy "$port"; then
        { lsof -nP -iUDP:"$port"; lsof -nP -iTCP:"$port" -sTCP:LISTEN; } >&2 || true
        poc_die "port $port is busy (3400 is fixed by the standalone genesis; set POC_P2P_PORT/POC_HTTP_PORT, or stop the other node: node-up.sh --down)"
    fi
done

POC_RUN_DIR="${POC_RUN_DIR:-$POC_DIR/runs/$(date +%Y%m%d-%H%M%S)}"
[ ! -e "$POC_RUN_DIR/daemon.pid" ] || poc_die "$POC_RUN_DIR already has a daemon.pid; pick a fresh POC_RUN_DIR"
mkdir -p "$POC_RUN_DIR/node" "$POC_RUN_DIR/samples"
POC_RUN_DIR="$(cd "$POC_RUN_DIR" && pwd -P)"
MODULES_DIR="$POC_RUN_DIR/modules"
ln -sfn "$POC_RUN_DIR" "$POC_DIR/runs/latest"
poc_say "run dir $POC_RUN_DIR"

# --- configs
git -C "$LB_REPO" show "$LB_REV:nodes/node/standalone-node-config.yaml" > "$POC_RUN_DIR/node/node-config.orig.yaml" \
    || poc_die "cannot read standalone-node-config.yaml @ $LB_REV from $LB_REPO"
git -C "$LB_REPO" show "$LB_REV:nodes/node/standalone-deployment-config.yaml" > "$POC_RUN_DIR/node/deployment.orig.yaml" \
    || poc_die "cannot read standalone-deployment-config.yaml @ $LB_REV"
NODE_CFG="$POC_RUN_DIR/node/node-config.yaml"
DEP_CFG="$POC_RUN_DIR/node/deployment.yaml"
python3 -I "$POC_DIR/lib/node_config.py" \
    --node-in "$POC_RUN_DIR/node/node-config.orig.yaml" --dep-in "$POC_RUN_DIR/node/deployment.orig.yaml" \
    --node-out "$NODE_CFG" --dep-out "$DEP_CFG" --run-dir "$POC_RUN_DIR" \
    --http-port "$POC_HTTP_PORT" --p2p-port "$POC_P2P_PORT" --claim-key "$POC_K" --reward-pool "$POC_REWARD_POOL" --rate-num "${POC_RATE_NUM:-3000}" >&2

# --- modules + daemon
mkdir -p "$MODULES_DIR"
install_lgx "$BM_LGX" "$MODULES_DIR"
for extra in ${EXTRA_LGX:-}; do install_lgx "$extra" "$MODULES_DIR"; done
daemon_start "$POC_RUN_DIR" "$MODULES_DIR"
NODE_UP_OK=0
# Failure after this point: stop this run's daemon (POC_KEEP_ON_FAIL=1 keeps it for inspection).
trap '[ "$NODE_UP_OK" = 1 ] || [ "${POC_KEEP_ON_FAIL:-0}" = 1 ] || daemon_stop "$POC_RUN_DIR"' EXIT

cat > "$POC_RUN_DIR/env.sh" <<EOF
export LOGOSCORE='$LOGOSCORE'
export POC_RUN_DIR='$POC_RUN_DIR'
export POC_HTTP_PORT='$POC_HTTP_PORT'
export POC_P2P_PORT='$POC_P2P_PORT'
export POC_K='$POC_K'
export POC_DAEMON_PID='$POC_DAEMON_PID'
export POC_MODULES_DIR='$MODULES_DIR'
export POC_NODE_URL='http://127.0.0.1:$POC_HTTP_PORT'
EOF

lc_load blockchain_module
probe=$(CALL_TIMEOUT=30 lc_call blockchain_module get_cryptarchia_info || true)
poc_say "pre-start probe get_cryptarchia_info -> ${probe:-<no output>}"

poc_say "start $NODE_CFG $DEP_CFG"
out=$(CALL_TIMEOUT=120 lc_call blockchain_module start "$NODE_CFG" "$DEP_CFG" || true)
poc_say "start -> ${out:-<no output>}"
printf '%s' "$out" | python3 -I -c '
import json, sys
env = None
for line in sys.stdin:
    line = line.strip()
    if line.startswith("{"):
        try: env = json.loads(line); break
        except Exception: pass
r = env.get("result") if isinstance(env, dict) and env.get("status") == "ok" else None
if isinstance(r, str):
    try: r = json.loads(r)
    except Exception: pass
sys.exit(0 if isinstance(r, dict) and r.get("success") else 1)' || poc_die "start failed: $out"

URL="http://127.0.0.1:$POC_HTTP_PORT"
if [ "$NO_WAIT" = 1 ]; then
    poc_say "--no-wait: not waiting for blocks"
else
    waited=0; height=0
    budget="${POC_WAIT_S:-180}"
    while [ "$waited" -lt "$budget" ]; do
        height=$(curl -s --max-time 5 "$URL/cryptarchia/info" 2>/dev/null \
            | python3 -I -c 'import json,sys
try: print(json.load(sys.stdin)["cryptarchia_info"]["height"])
except Exception: print(-1)') || height=-1
        [ "$height" -gt 0 ] 2>/dev/null && break
        [ $((waited % 10)) -eq 0 ] && poc_say "t=${waited}s height=$height"
        sleep 2; waited=$((waited + 2))
    done
    [ "$height" -gt 0 ] 2>/dev/null || poc_die "height still $height after ${budget}s (see $POC_RUN_DIR/node/logs, daemon.log)"
    poc_say "height $height after ${waited}s"
fi
poc_say "/cryptarchia/info: $(curl -s --max-time 5 "$URL/cryptarchia/info" || true)"
poc_say "/pow/status: $(curl -s --max-time 5 "$URL/pow/status" || true)"
poc_say "node up: pid $POC_DAEMON_PID, $URL, source $POC_RUN_DIR/env.sh; stop with $0 --down $POC_RUN_DIR"
NODE_UP_OK=1
printf '%s\n' "$POC_RUN_DIR"
