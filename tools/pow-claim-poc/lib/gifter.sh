# shellcheck shell=bash
# tools/pow-claim-poc/lib/gifter.sh — drive libp2p_module + rln_gifter_module on one
# of several logoscore daemons. Source AFTER lib/logoscore.sh.
#
# Every helper takes an explicit run dir and calls `POC_RUN_DIR=<run> lc_call …`, so
# one script can drive two daemons (gifter B, client A).
#
# CLI arg form (R15): rln_gifter_module's methods take one Rust String param; the
# logoscore CLI passes a bare JSON object argument through verbatim. Do NOT use
# @argfile for these: an argfile object arrives brace-stripped.

# Usage: gf_result <envelope-json>  -> module reply (JSON string inside "result")
gf_result() { printf '%s' "$1" | jres; }

# Usage: gf_field <json> <key>  -> top-level field (unwraps {success,value}; "" if absent)
gf_field() {
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

# Usage: gf_libp2p_up <run> <listen_multiaddr>  -> echoes the node's peerId
gf_libp2p_up() {
    local run="$1" addr="$2" env pinfo peer
    env=$(POC_RUN_DIR="$run" lc_call libp2p_module createNode "{\"addrs\":[\"$addr\"]}") \
        || POC_RUN_DIR="$run" poc_die "libp2p createNode failed ($run)"
    poc_say "createNode[$run]: $(gf_result "$env")"
    env=$(POC_RUN_DIR="$run" lc_call libp2p_module start) \
        || POC_RUN_DIR="$run" poc_die "libp2p start failed ($run)"
    poc_say "start[$run]: $(gf_result "$env")"
    pinfo=$(POC_RUN_DIR="$run" lc_call libp2p_module peerInfo) || pinfo=""
    peer=$(gf_field "$(gf_result "$pinfo")" peerId)
    [ -n "$peer" ] || POC_RUN_DIR="$run" poc_die "no peerId in peerInfo: ${pinfo:-<empty>}"
    printf '%s' "$peer"
}

# Usage: gf_serve_raw <run> <json>  -> module reply (no assertion; for probes)
gf_serve_raw() {
    local env
    env=$(POC_RUN_DIR="$1" lc_call rln_gifter_module serve "$2") || env=""
    gf_result "$env"
}

# Usage: gf_serve <run> <json>  -> module reply; dies unless it reports mounted:true
gf_serve() {
    local res
    res=$(gf_serve_raw "$1" "$2")
    case "$res" in
        *mounted*true*) poc_say "serve[$1]: $res"; printf '%s' "$res" ;;
        *) POC_RUN_DIR="$1" poc_die "serve did not mount: ${res:-<empty>}" ;;
    esac
}

# Usage: gf_request <run> <json> <tag>
# Saves <run>/requests/<tag>.env.json (raw CLI envelope), <tag>.res.json (module reply),
# <tag>.latency (seconds). Echoes the "error" string if present, else the reply.
# Returns 0 if a reply arrived (error or not), 1 on CLI timeout / empty envelope.
gf_request() {
    local run="$1" body="$2" tag="$3" dir env res t0 t1 err
    dir="$run/requests"; mkdir -p "$dir"
    printf '%s' "$body" > "$dir/$tag.req.json"
    t0=$(date +%s)
    # lc_call discards stderr; call directly so CLI-side errors land in <tag>.stderr.
    env=$(_with_timeout "${GF_REQUEST_TIMEOUT:-240}" env -u TMPDIR LOGOSCORE_CONFIG_DIR="$run/config" \
        "$LOGOSCORE" --json call rln_gifter_module request "$body" 2>"$dir/$tag.stderr") || env=""
    t1=$(date +%s)
    printf '%s' "$((t1 - t0))" > "$dir/$tag.latency"
    printf '%s\n' "$env" > "$dir/$tag.env.json"
    res=$(gf_result "$env")
    printf '%s\n' "$res" > "$dir/$tag.res.json"
    if [ -z "$res" ]; then
        # non-ok envelope, e.g. the CLI's fixed ~20 s deadline: {"code":"RPC_FAILED",…}
        poc_say "request[$tag] $((t1 - t0))s: no reply; CLI: ${env:-<empty>}"
        return 1
    fi
    poc_say "request[$tag] $((t1 - t0))s: $res"
    err=$(gf_field "$res" error)
    if [ -n "$err" ]; then printf '%s' "$err"; else printf '%s' "$res"; fi
}

# Usage: gf_latency <run> <tag>  -> seconds recorded by gf_request
gf_latency() { cat "$1/requests/$2.latency" 2>/dev/null || printf ''; }

# Usage: gf_check_lp_logs <run>  -> prints matching lines (never fails)
gf_check_lp_logs() {
    grep -a 'lp_client_create failed for' "$1/daemon.log" 2>/dev/null || true
}
