# shellcheck shell=bash
# tools/pow-claim-poc/lib/logoscore.sh — single-node logoscore driving.
#
# Vendored and simplified from logos-rln-e2e/harness/lib/ (do not source those):
#   compat.sh  say/die                       -> poc_say/poc_die
#   lgx.sh     lgx_platform, install_lgx
#   daemon.sh  daemon_start, daemon_stop, daemon_load_modules -> lc_load
#   json.sh    _with_timeout, argfile, call_json -> lc_call, jres, jval
# One daemon per run dir; no containers, watchers or wallet homes.
#
# Env: LOGOSCORE (CLI path), POC_RUN_DIR (run dir; config at $POC_RUN_DIR/config),
#      POC_DAEMON_PID (set by daemon_start), CALL_TIMEOUT (default 60 s).

poc_say() { printf '%s\n' "poc: $*" >&2; }
poc_die() {
    printf '%s\n' "poc: FAIL: $*" >&2
    if [ -n "${POC_RUN_DIR:-}" ] && [ -f "$POC_RUN_DIR/daemon.log" ]; then
        printf '%s\n' "---- daemon log tail ----" >&2
        tail -n 30 "$POC_RUN_DIR/daemon.log" >&2
    fi
    exit 1
}

# timeout(1) is coreutils; stock macOS has neither it nor gtimeout.
_with_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
    else "$@"
    fi
}

lgx_platform() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64)  printf 'darwin-arm64-dev' ;;
        Linux-x86_64)  printf 'linux-x86_64-dev' ;;
        Linux-aarch64) printf 'linux-aarch64-dev' ;;
        *) poc_die "unsupported platform $(uname -s)-$(uname -m)" ;;
    esac
}

# Usage: install_lgx <bundle.lgx> <modules_dir>
# Flattens the bundle into <modules_dir>/<name>/{manifest.json,<variant files>,variant}.
install_lgx() {
    local lgx="$1" dest="$2" name tmp plat variant nvar
    [ -f "$lgx" ] || poc_die "install_lgx: no bundle at $lgx"
    name=$(tar xzOf "$lgx" manifest.json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["name"])')
    [ -n "$name" ] || poc_die "install_lgx: cannot read name from $lgx"
    tmp=$(mktemp -d)
    tar xzf "$lgx" -C "$tmp" || poc_die "install_lgx: cannot unpack $lgx"
    plat=$(lgx_platform)
    if [ -d "$tmp/variants/$plat" ]; then
        variant="$plat"
    else
        nvar=$(find "$tmp/variants" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
        [ "$nvar" = "1" ] || poc_die "install_lgx: $lgx has no variants/$plat"
        variant=$(basename "$(find "$tmp/variants" -mindepth 1 -maxdepth 1 -type d | head -1)")
    fi
    rm -rf "${dest:?}/$name"
    mkdir -p "$dest/$name"
    cp "$tmp/manifest.json" "$dest/$name/"
    # -L: the tarball's entries point into /nix/store.
    cp -RL "$tmp/variants/$variant/"* "$dest/$name/" \
        || poc_die "install_lgx: cannot stage variants/$variant from $lgx"
    printf '%s' "$variant" > "$dest/$name/variant"
    rm -rf "$tmp"
    poc_say "installed $name ($variant) into $dest"
}

# Usage: daemon_start <run_dir> <modules_dir>
daemon_start() {
    local run="$1" mods="$2" cfg log _t
    [ -n "${LOGOSCORE:-}" ] || poc_die "daemon_start: LOGOSCORE unset"
    POC_RUN_DIR="$run"
    cfg="$run/config"; log="$run/daemon.log"
    mkdir -p "$cfg" "$run/persist"
    poc_say "starting logoscore daemon (log: $log)"
    # env -i: Qt strips DYLD_* otherwise, and daemon+client must agree on the
    # effective TMPDIR (QLocalSocket path) — clients run with `env -u TMPDIR`.
    # exec: $! must be the daemon itself.
    (cd "$run" && exec env -i HOME="$HOME" PATH="$PATH" LOGOSCORE_CONFIG_DIR="$cfg" \
        RUST_BACKTRACE=full QT_QPA_PLATFORM=offscreen \
        "$LOGOSCORE" -m "$mods" --persistence-path "$run/persist" -D </dev/null >>"$log" 2>&1) &
    POC_DAEMON_PID=$!
    disown "$POC_DAEMON_PID" 2>/dev/null || true
    printf '%s' "$POC_DAEMON_PID" > "$run/daemon.pid"
    _t=0
    while [ ! -f "$cfg/client/config.json" ] && [ "$_t" -lt 60 ]; do sleep 1; _t=$((_t + 1)); done
    [ -f "$cfg/client/config.json" ] || poc_die "daemon produced no client config"
    _t=0
    while [ "$_t" -lt 60 ]; do
        _with_timeout 5 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$cfg" "$LOGOSCORE" --quiet --json list-modules 2>/dev/null \
            | grep -q '"capability_module".*"loaded"' && break
        sleep 1; _t=$((_t + 1))
    done
    sleep 3
    poc_say "daemon up (pid $POC_DAEMON_PID)"
}

# Usage: daemon_stop [run_dir]   (stops the node first, then the daemon; waits ≤30 s)
daemon_stop() {
    local run="${1:-${POC_RUN_DIR:-}}" pid _t
    [ -n "$run" ] || return 0
    pid="${POC_DAEMON_PID:-}"
    [ -n "$pid" ] || pid=$(cat "$run/daemon.pid" 2>/dev/null || true)
    [ -n "$pid" ] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        POC_RUN_DIR="$run" CALL_TIMEOUT=30 lc_call blockchain_module stop >/dev/null 2>&1 || true
        kill "$pid" 2>/dev/null || true
        _t=0
        while kill -0 "$pid" 2>/dev/null && [ "$_t" -lt 30 ]; do sleep 1; _t=$((_t + 1)); done
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$run/daemon.pid"
    poc_say "daemon $pid stopped"
}

# Usage: lc_load <module>
lc_load() {
    poc_say "load-module $1"
    _with_timeout 60 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$POC_RUN_DIR/config" "$LOGOSCORE" --json load-module "$1" \
        >>"$POC_RUN_DIR/daemon.log" 2>&1 || poc_die "load-module $1 failed"
}

# Usage: lc_call <module> <method> [args…]   -> raw CLI JSON envelope on stdout
# Digit-leading strings (hex) must go via argfile or the CLI coerces them to numbers.
lc_call() {
    local mod="$1" meth="$2"; shift 2
    _with_timeout "${CALL_TIMEOUT:-60}" env -u TMPDIR LOGOSCORE_CONFIG_DIR="$POC_RUN_DIR/config" \
        "$LOGOSCORE" --json call "$mod" "$meth" "$@" 2>/dev/null
}

# Usage: argfile <name> <content>   -> prints @<path>
argfile() {
    local dir="$POC_RUN_DIR/args"
    mkdir -p "$dir"
    printf '%s' "$2" > "$dir/$1.arg"
    printf '@%s' "$dir/$1.arg"
}

# CLI envelope {"status":"ok","result":…} -> result (compact JSON or raw string).
jres() {
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

# LogosResult {success,value,error} -> value on success / error otherwise; else passthrough.
jval() { python3 -I -c '
import json, sys
raw = sys.stdin.read().strip()
try:
    d = json.loads(raw)
except Exception:
    print(raw); sys.exit()
if isinstance(d, str):
    try:
        d = json.loads(d)
    except Exception:
        print(d); sys.exit()
if isinstance(d, dict) and "success" in d and ("value" in d or "error" in d):
    out = d.get("value") if d.get("success") else d.get("error")
    print(out if isinstance(out, str) else json.dumps(out, separators=(",", ":")))
else:
    print(raw)
'; }
