# shellcheck shell=bash
# tools/allocator/docker/lib-ctl.sh — the allocator helpers of ../lib.sh, for
# the released logosctl instead of a nix-built logoscore.
#
# What differs from lib.sh: there is no RUN dir — logosctl keeps its session
# under $LOGOSCTL_CONFIG_DIR (exported once by the entrypoint), modules are
# installed by the package manager at image build (no al_install_lgx), and
# `logosctl --json call` prints the same {"status":"ok","result":…} envelope
# logoscore does (logosctl 0.3.0 merged logoscore, lgpd and lgpm), so al_res /
# al_field are unchanged. The daemon inherits the environment of the shell
# that starts it — the lez module reads LEZ_RLN_* / LEE_WALLET_HOME_DIR from
# there.
#
# Trap carried over: the CLI abandons a call after ~20 s while the module
# keeps running; CALL_TIMEOUT only bounds our own wait.

al_say() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "allocator: $*" >&2; }
al_die() {
    printf '%s %s\n' "$(date -u +%H:%M:%S)" "allocator: FAIL: $*" >&2
    local log="${LOGOSCTL_CONFIG_DIR:-}/logs/daemon.log"
    if [ -f "$log" ]; then
        printf '%s\n' "---- daemon log tail ----" >&2
        tail -n 30 "$log" >&2
    fi
    exit 1
}

# Usage: ctl <args…>  — logosctl against the session, with a budget.
ctl() { timeout "${CALL_TIMEOUT:-60}" logosctl "$@"; }

# Usage: al_call <module> <method> [args…]  -> raw CLI JSON envelope
al_call() { ctl --json call "$@" 2>/dev/null; }

# CLI envelope {"status":"ok","result":…} -> result (compact JSON or raw string).
al_res() {
    python3 -I -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("status") == "ok" and "result" in d:
        r = d["result"]
        print(r if isinstance(r, str) else json.dumps(r, separators=(",", ":")))
        break
'
}

# Usage: al_field <json> <key>  -> top-level field, unwrapping {success,value}
# and a JSON-encoded string result; "" if absent.
al_field() {
    printf '%s' "$1" | python3 -I -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    d = json.loads(raw)
    if isinstance(d, str):
        d = json.loads(d)
    if isinstance(d, dict) and "value" in d and "success" in d:
        d = d["value"]
        if isinstance(d, str):
            d = json.loads(d)
    v = d.get(sys.argv[1], "") if isinstance(d, dict) else ""
except Exception:
    v = ""
print(v if isinstance(v, str) else json.dumps(v, separators=(",", ":")))
' "$2"
}

# Usage: al_res_field <module> <method> <key> [args…]  -> one field of a call's result
al_res_field() {
    local mod="$1" meth="$2" key="$3"; shift 3
    al_field "$(al_call "$mod" "$meth" "$@" | al_res)" "$key"
}

# Usage: al_value <json>  -> the raw `value` of a {success,value} result
# (string as-is, anything else compact JSON); a JSON-encoded string result is
# decoded first, and input that is no such envelope is printed unchanged.
# On {"success":false} prints the error and returns 1; "" input returns 1.
al_value() {
    printf '%s' "$1" | python3 -I -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    d = json.loads(raw)
    if isinstance(d, str):
        try:
            d = json.loads(d)
        except Exception:
            print(d); sys.exit(0)
except Exception:
    print(raw); sys.exit(0)
def out(v):
    print(v if isinstance(v, str) else json.dumps(v, separators=(",", ":")))
if isinstance(d, dict) and "success" in d and ("value" in d or "error" in d):
    if not d.get("success"):
        out(d.get("error") or "success:false"); sys.exit(1)
    out(d.get("value", "")); sys.exit(0)
out(d)
'
}

# Usage: al_json_get <json> <dotted.path>  -> the value at path ("" if absent)
# Unwraps a JSON-encoded string and {success,value} at every level; integer
# segments index lists (negative from the end), e.g. memberships.-1.state.
al_json_get() {
    printf '%s' "$1" | python3 -I -c '
import json, sys
def unwrap(d):
    while True:
        if isinstance(d, str):
            try:
                d = json.loads(d)
                continue
            except Exception:
                return d
        if isinstance(d, dict) and "success" in d and "value" in d:
            d = d["value"]
            continue
        return d
try:
    d = unwrap(json.loads(sys.stdin.read().strip()))
    for seg in [s for s in sys.argv[1].split(".") if s]:
        if isinstance(d, list):
            d = d[int(seg)]
        elif isinstance(d, dict):
            d = d.get(seg, "")
        else:
            d = ""
        d = unwrap(d)
except Exception:
    d = ""
if d is None:
    d = ""
print(d if isinstance(d, str) else json.dumps(d, separators=(",", ":")))
' "$2"
}

# Usage: al_poll <budget_s> <interval_s> <fn> [args…]
# Runs fn until it returns 0 (done -> 0) or 2 (fatal -> 2); any other status
# retries every interval until the budget is spent (-> 1). fn runs in this
# shell, so the globals it sets are visible to the caller.
al_poll() {
    local budget="$1" every="$2" t0 rc
    shift 2
    t0=$(date +%s)
    while :; do
        "$@"; rc=$?
        case "$rc" in
            0) return 0 ;;
            2) return 2 ;;
        esac
        [ $(( $(date +%s) - t0 )) -lt "$budget" ] || return 1
        sleep "$every"
    done
}

# ---------------------------------------------------------------- daemon

# Usage: ctl_daemon_pid  -> pid when the daemon reports running, else ""
ctl_daemon_pid() {
    ctl daemon status --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin).get("daemon", {})
    print(d.get("pid", "") if d.get("status") == "running" else "")
except Exception:
    print("")
' 2>/dev/null
}

# Usage: ctl_daemon_start  — detached; returns once it has bound its transports.
ctl_daemon_start() {
    local t=0 pid
    logosctl daemon start --detach </dev/null || al_die "logosctl daemon start failed"
    while [ "$t" -lt 60 ]; do
        pid=$(ctl_daemon_pid)
        [ -n "$pid" ] && { al_say "daemon running (pid $pid)"; return 0; }
        sleep 1; t=$((t + 1))
    done
    al_die "daemon not running 60 s after start"
}

# Usage: ctl_load <module>  — load and insist it answers introspection.
ctl_load() {
    local mod="$1" out
    out=$(ctl --json module load "$mod" 2>&1) || al_die "module load $mod failed: $out"
    case "$out" in
        *'"status":"ok"'*|*'"status": "ok"'*) ;;
        *'rror'*) al_die "module load $mod: $out" ;;
    esac
    al_say "loaded $mod"
}

# ---------------------------------------------------------------- libp2p

# Usage: al_node_key <key_file>  -> hex private key, minted once and persisted.
# The PeerId derives from this key: keep the file for the allocator's
# lifetime. Format: the libp2p protobuf PrivateKey envelope
# `08 02 12 20 || 32 random bytes` (Secp256k1), 72 hex chars — minted locally
# because newPrivateKey answers {"success":false} on some libp2p builds.
al_node_key() {
    local file="$1" key
    if [ -s "$file" ]; then
        tr -d '[:space:]' < "$file"
        return 0
    fi
    key="08021220$(openssl rand -hex 32)"
    ( umask 077; printf '%s\n' "$key" > "$file" ) || al_die "cannot write node key to $file"
    al_say "minted node key -> $file"
    printf '%s' "$key"
}

# Usage: al_libp2p_up <listen_multiaddr> <privkey_hex>  -> echoes peerId
# Mesh-free node: the allocator needs no gossipsub, kad or service discovery.
# createNode answers success:true and falls back to DEFAULTS (fresh key,
# random port) when it rejects part of its config; the only evidence is
# peerInfo, so the listen port must be among the bound addrs (a wildcard
# bind is reported per interface, hence the port match).
al_libp2p_up() {
    local addr="$1" key="$2" cfg env pinfo peer port addrs
    cfg="{\"addrs\":[\"$addr\"],\"transport\":\"tcp\",\"mountGossipsub\":false,\"mountKad\":false,\"mountServiceDiscovery\":false,\"privKey\":\"$key\"}"
    env=$(al_call libp2p_module createNode "$cfg") || al_die "libp2p createNode failed"
    al_say "createNode: $(printf '%s' "$env" | al_res)"
    env=$(al_call libp2p_module start) || al_die "libp2p start failed"
    al_say "start: $(printf '%s' "$env" | al_res)"
    pinfo=$(al_call libp2p_module peerInfo | al_res) || pinfo=""
    peer=$(al_field "$pinfo" peerId)
    [ -n "$peer" ] || al_die "no peerId in peerInfo: ${pinfo:-<empty>}"
    port="${addr##*/tcp/}"
    addrs=$(al_field "$pinfo" addrs)
    case "$addrs" in
        *"/tcp/$port\""*) ;;
        *) al_die "libp2p is not listening on port $port (createNode fell back to defaults?): addrs=$addrs" ;;
    esac
    printf '%s' "$peer"
}

# Usage: al_libp2p_up_any <listen_multiaddr>  -> echoes peerId; no key, any
# port (tcp/0): for a client whose PeerId nobody pins.
al_libp2p_up_any() {
    local addr="$1" cfg env pinfo peer
    cfg="{\"addrs\":[\"$addr\"],\"transport\":\"tcp\",\"mountGossipsub\":false,\"mountKad\":false,\"mountServiceDiscovery\":false}"
    env=$(al_call libp2p_module createNode "$cfg") || al_die "libp2p createNode failed"
    al_say "createNode: $(printf '%s' "$env" | al_res)"
    env=$(al_call libp2p_module start) || al_die "libp2p start failed"
    pinfo=$(al_call libp2p_module peerInfo | al_res) || pinfo=""
    peer=$(al_field "$pinfo" peerId)
    [ -n "$peer" ] || al_die "no peerId in peerInfo: ${pinfo:-<empty>}"
    al_say "listening on $(al_field "$pinfo" addrs)"
    printf '%s' "$peer"
}

# Usage: al_port_open <port>  -> 0 when something accepts on 127.0.0.1:<port>
# Liveness is probed on the socket, NOT through libp2p_module.peerInfo: once
# rln_gifter_module has mounted its protocol, peerInfo RPCs hang or fail
# intermittently (measured: 4 of 6 from a second client, 20 s timeouts),
# while the listener keeps serving. Read the PeerId before serve, never after.
al_port_open() {
    python3 -I -c 'import socket, sys
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("127.0.0.1", int(sys.argv[1]))); s.close(); sys.exit(0)
except Exception:
    sys.exit(1)' "$1"
}
