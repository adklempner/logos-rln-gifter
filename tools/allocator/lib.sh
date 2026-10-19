# shellcheck shell=bash
# tools/allocator/lib.sh — drive one or more logoscore daemons that host an RLN
# membership allocator (rln_gifter_module.serve) or its client half.
#
# Vendored and trimmed from tools/pow-claim-poc/lib/{logoscore,gifter}.sh, which
# were themselves vendored from logos-rln-e2e/harness/lib. Kept separate so this
# directory stands alone (the PoC tree is untracked work by another agent).
#
# Conventions:
#   * every daemon-touching helper takes an explicit RUN dir as first argument;
#     RUN/config is LOGOSCORE_CONFIG_DIR, RUN/daemon.log the daemon's output,
#     RUN/modules the flattened module dir, RUN/persist the persistence path.
#   * rln_gifter_module's methods take ONE Rust String parameter; the logoscore
#     CLI passes a bare JSON object through verbatim. Never @argfile for these:
#     an argfile object arrives brace-stripped.
#   * `logoscore call` has a fixed ~20 s transport deadline. A reply that takes
#     longer is lost by the CLI (the module keeps running). CALL_TIMEOUT only
#     bounds our own wait.

al_say() { printf '%s\n' "allocator: $*" >&2; }
al_die() {
    printf '%s\n' "allocator: FAIL: $*" >&2
    if [ -n "${AL_LOG_ON_DIE:-}" ] && [ -f "$AL_LOG_ON_DIE" ]; then
        printf '%s\n' "---- daemon log tail ($AL_LOG_ON_DIE) ----" >&2
        tail -n 30 "$AL_LOG_ON_DIE" >&2
    fi
    exit 1
}

# timeout(1) is coreutils; stock macOS has neither it nor gtimeout.
_al_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
    else
        [ -n "${_AL_TIMEOUT_WARNED:-}" ] || { _AL_TIMEOUT_WARNED=1; al_say "WARN: no timeout/gtimeout on PATH: calls run without a deadline"; }
        "$@"
    fi
}

# The bundler names variants linux-amd64 / linux-arm64 / darwin-arm64, with a
# -dev suffix for the nix dev builds a nix-built logoscore loads (the released
# logosctl loads the portable, suffix-less ones). liblogos accepts
# linux-x86_64 as an alias of linux-amd64, but the bundles never carry it.
al_lgx_platform() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64)  printf 'darwin-arm64' ;;
        Darwin-x86_64) printf 'darwin-amd64' ;;
        Linux-x86_64)  printf 'linux-amd64' ;;
        Linux-aarch64) printf 'linux-arm64' ;;
        *) al_die "unsupported platform $(uname -s)-$(uname -m)" ;;
    esac
}

# Usage: al_install_lgx <bundle.lgx> <modules_dir>
# Flattens the bundle into <modules_dir>/<name>/{manifest.json,<variant files>,variant}.
# (Equivalent to `lgpm --allow-unsigned install`, without needing lgpm.)
al_install_lgx() {
    local lgx="$1" dest="$2" name tmp plat variant nvar
    [ -f "$lgx" ] || al_die "install_lgx: no bundle at $lgx"
    name=$(tar xzOf "$lgx" manifest.json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    [ -n "$name" ] || al_die "install_lgx: cannot read name from $lgx"
    tmp=$(mktemp -d)
    tar xzf "$lgx" -C "$tmp" || al_die "install_lgx: cannot unpack $lgx"
    # Dev variant first (what a nix-built logoscore loads), then the portable
    # one, then a single-variant bundle whatever it is called.
    plat=$(al_lgx_platform)
    if [ -d "$tmp/variants/$plat-dev" ]; then
        variant="$plat-dev"
    elif [ -d "$tmp/variants/$plat" ]; then
        variant="$plat"
    else
        nvar=$(find "$tmp/variants" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
        [ "$nvar" = "1" ] || al_die "install_lgx: $lgx has no variants/$plat(-dev)"
        variant=$(basename "$(find "$tmp/variants" -mindepth 1 -maxdepth 1 -type d | head -1)")
    fi
    rm -rf "${dest:?}/$name"
    mkdir -p "$dest/$name"
    cp "$tmp/manifest.json" "$dest/$name/"
    cp -RL "$tmp/variants/$variant/"* "$dest/$name/" \
        || al_die "install_lgx: cannot stage variants/$variant from $lgx"
    printf '%s' "$variant" > "$dest/$name/variant"
    rm -rf "$tmp"
    al_say "installed $name ($variant) into $dest"
}

# Usage: al_daemon_start <run_dir> [extra env assignments…]
# Starts `logoscore -D -m RUN/modules --persistence-path RUN/persist`. Extra
# KEY=VALUE arguments land in the daemon's environment (the registry module's
# LEZ_RLN_* / LEE_WALLET_HOME_DIR knobs go here).
al_daemon_start() {
    local run="$1"; shift
    local cfg log pid _t
    [ -n "${LOGOSCORE:-}" ] || al_die "daemon_start: LOGOSCORE unset"
    cfg="$run/config"; log="$run/daemon.log"
    mkdir -p "$cfg" "$run/persist"
    al_say "starting logoscore daemon (log: $log)"
    # env -i: Qt strips DYLD_* otherwise, and daemon+client must agree on the
    # effective TMPDIR (QLocalSocket path) — clients run with `env -u TMPDIR`.
    (cd "$run" && exec env -i HOME="$HOME" PATH="$PATH" LOGOSCORE_CONFIG_DIR="$cfg" \
        RUST_BACKTRACE=full QT_QPA_PLATFORM=offscreen "$@" \
        "$LOGOSCORE" -m "$run/modules" --persistence-path "$run/persist" -D </dev/null >>"$log" 2>&1) &
    pid=$!
    disown "$pid" 2>/dev/null || true
    printf '%s' "$pid" > "$run/daemon.pid"
    _t=0
    while [ ! -f "$cfg/client/config.json" ] && [ "$_t" -lt 60 ]; do sleep 1; _t=$((_t + 1)); done
    [ -f "$cfg/client/config.json" ] || AL_LOG_ON_DIE="$log" al_die "daemon produced no client config"
    _t=0
    while [ "$_t" -lt 60 ]; do
        _al_timeout 5 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$cfg" "$LOGOSCORE" --quiet --json list-modules 2>/dev/null \
            | grep -q '"capability_module".*"loaded"' && break
        sleep 1; _t=$((_t + 1))
    done
    sleep 2
    al_say "daemon up (pid $pid, run $run)"
}

# Usage: al_daemon_stop <run_dir>   (waits ≤30 s, then SIGKILL)
al_daemon_stop() {
    local run="$1" pid _t
    pid=$(cat "$run/daemon.pid" 2>/dev/null || true)
    [ -n "$pid" ] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        _t=0
        while kill -0 "$pid" 2>/dev/null && [ "$_t" -lt 30 ]; do sleep 1; _t=$((_t + 1)); done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$run/daemon.pid"
    al_say "daemon $pid stopped ($run)"
}

# Usage: al_load <run_dir> <module>
al_load() {
    local run="$1" mod="$2"
    al_say "load-module $mod"
    _al_timeout 60 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$run/config" "$LOGOSCORE" --json load-module "$mod" \
        >>"$run/daemon.log" 2>&1 || AL_LOG_ON_DIE="$run/daemon.log" al_die "load-module $mod failed"
}

# Usage: al_call <run_dir> <module> <method> [args…]  -> raw CLI JSON envelope
al_call() {
    local run="$1" mod="$2" meth="$3"; shift 3
    _al_timeout "${CALL_TIMEOUT:-60}" env -u TMPDIR LOGOSCORE_CONFIG_DIR="$run/config" \
        "$LOGOSCORE" --json call "$mod" "$meth" "$@" 2>/dev/null
}

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

# ---------------------------------------------------------------- libp2p

# Usage: al_node_key <key_file> [run_dir]  -> hex private key, minted once and persisted.
# The PeerId derives from this key: keep the file for the allocator's lifetime
# and out of any wipeable work dir. Format: the libp2p protobuf PrivateKey
# envelope `08 02 12 20 || 32 random bytes` (Secp256k1), 72 hex chars — the
# same bytes libp2p_module.newPrivateKey returns, minted locally because that
# call answers {"success":false} on some builds (upstream 1.0.0). A run dir
# is only consulted as a fallback when openssl is missing.
al_node_key() {
    local file="$1" run="${2:-}" key
    if [ -s "$file" ]; then
        tr -d '[:space:]' < "$file"
        return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
        key="08021220$(openssl rand -hex 32)"
        ( umask 077; printf '%s\n' "$key" > "$file" ) || al_die "cannot write node key to $file"
        al_say "minted node key locally -> $file"
        printf '%s' "$key"
        return 0
    fi
    [ -n "$run" ] || al_die "node key $file missing, no openssl, and no daemon to mint one"
    key=$(al_call "$run" libp2p_module newPrivateKey | al_res | python3 -I -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    d = json.loads(raw)
    if isinstance(d, dict) and "value" in d:
        d = d["value"]
    print(d if isinstance(d, str) else "")
except Exception:
    print(raw)
')
    [ -n "$key" ] || AL_LOG_ON_DIE="$run/daemon.log" al_die "newPrivateKey returned nothing"
    ( umask 077; printf '%s\n' "$key" > "$file" ) || al_die "cannot write node key to $file"
    al_say "minted node key -> $file"
    printf '%s' "$key"
}

# Usage: al_libp2p_up <run_dir> <listen_multiaddr> [privkey_hex]  -> echoes peerId
# Mesh-free node: the allocator needs no gossipsub, kad or service discovery.
al_libp2p_up() {
    local run="$1" addr="$2" key="${3:-}" cfg env pinfo peer
    cfg="{\"addrs\":[\"$addr\"],\"transport\":\"tcp\",\"mountGossipsub\":false,\"mountKad\":false,\"mountServiceDiscovery\":false"
    [ -z "$key" ] || cfg="$cfg,\"privKey\":\"$key\""
    cfg="$cfg}"
    env=$(al_call "$run" libp2p_module createNode "$cfg") || AL_LOG_ON_DIE="$run/daemon.log" al_die "libp2p createNode failed"
    al_say "createNode: $(printf '%s' "$env" | al_res)"
    env=$(al_call "$run" libp2p_module start) || AL_LOG_ON_DIE="$run/daemon.log" al_die "libp2p start failed"
    al_say "start: $(printf '%s' "$env" | al_res)"
    pinfo=$(al_call "$run" libp2p_module peerInfo | al_res) || pinfo=""
    peer=$(al_field "$pinfo" peerId)
    [ -n "$peer" ] || AL_LOG_ON_DIE="$run/daemon.log" al_die "no peerId in peerInfo: ${pinfo:-<empty>}"
    # createNode answers success:true and falls back to DEFAULTS (fresh key,
    # random port) when it rejects part of its config. The only evidence is
    # peerInfo: a fixed listen port must be among the bound addrs. A wildcard
    # bind (0.0.0.0 / ::) is reported per interface, so match on the port.
    case "$addr" in
        */tcp/0) ;;
        /ip4/0.0.0.0/*|/ip6/::/*)
           local port addrs; port="${addr##*/tcp/}"; addrs=$(al_field "$pinfo" addrs)
           case "$addrs" in
               *"/tcp/$port\""*) ;;
               *) AL_LOG_ON_DIE="$run/daemon.log" al_die "libp2p is not listening on port $port (createNode fell back to defaults?): addrs=$addrs" ;;
           esac ;;
        *) local addrs; addrs=$(al_field "$pinfo" addrs)
           case "$addrs" in
               *"\"$addr\""*) ;;
               *) AL_LOG_ON_DIE="$run/daemon.log" al_die "libp2p is not listening on $addr (createNode fell back to defaults?): addrs=$addrs" ;;
           esac ;;
    esac
    printf '%s' "$peer"
}

# Usage: al_peer_addrs <run_dir>  -> compact JSON array of the node's addrs
al_peer_addrs() {
    local pinfo
    pinfo=$(al_call "$1" libp2p_module peerInfo | al_res) || pinfo=""
    al_field "$pinfo" addrs
}

# ---------------------------------------------------------------- gifter

# Usage: al_serve <run_dir> <serve_json>  -> module reply; dies unless mounted:true
al_serve() {
    local run="$1" body="$2" res
    res=$(al_call "$run" rln_gifter_module serve "$body" | al_res) || res=""
    case "$res" in
        *mounted*true*) al_say "serve: $res"; printf '%s' "$res" ;;
        *) AL_LOG_ON_DIE="$run/daemon.log" al_die "serve did not mount: ${res:-<empty>}" ;;
    esac
}

# Usage: al_request <run_dir> <request_json> <tag>
# Saves RUN/requests/<tag>.{req,env,res}.json + .latency. Echoes the module's
# "error" string if present, else the reply. Returns 1 when no reply arrived
# (e.g. the CLI's ~20 s deadline).
al_request() {
    local run="$1" body="$2" tag="$3" dir env res t0 t1 err
    dir="$run/requests"; mkdir -p "$dir"
    printf '%s' "$body" > "$dir/$tag.req.json"
    t0=$(date +%s)
    env=$(_al_timeout "${AL_REQUEST_TIMEOUT:-240}" env -u TMPDIR LOGOSCORE_CONFIG_DIR="$run/config" \
        "$LOGOSCORE" --json call rln_gifter_module request "$body" 2>"$dir/$tag.stderr") || env=""
    t1=$(date +%s)
    printf '%s' "$((t1 - t0))" > "$dir/$tag.latency"
    printf '%s\n' "$env" > "$dir/$tag.env.json"
    res=$(printf '%s' "$env" | al_res)
    printf '%s\n' "$res" > "$dir/$tag.res.json"
    if [ -z "$res" ]; then
        al_say "request[$tag] $((t1 - t0))s: no reply; CLI: ${env:-<empty>}"
        return 1
    fi
    al_say "request[$tag] $((t1 - t0))s: $res"
    err=$(al_field "$res" error)
    if [ -n "$err" ]; then printf '%s' "$err"; else printf '%s' "$res"; fi
}
