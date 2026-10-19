#!/usr/bin/env bash
# tools/allocator/run-allocator.sh — stand up (or stop) an RLN membership
# allocator: one logoscore daemon hosting libp2p_module + liblogos_lez_rln_module
# + rln_gifter_module (+ your verifier modules), with a PERSISTED libp2p
# identity so the published PeerId survives restarts.
#
# This is docs/running-an-allocator.md §6 as a script. The chain leg (a funded,
# synced payer) is the operator's: this script waits for the registry module's
# wallet and optionally for a balance, it does not fund anything.
#
#   run-allocator.sh up      install bundles, start daemon, load, libp2p up,
#                            wait for the wallet, serve, write allocator.json
#   run-allocator.sh serve   re-issue `serve` against the running daemon
#                            (config refresh: new verifier set / wallet / cap)
#   run-allocator.sh status  print allocator.json and whether the daemon lives
#   run-allocator.sh down    stop the daemon (identity key and nullifier file stay)
#
# Configuration is environment; $ALLOCATOR_HOME/allocator.env is sourced first
# if present (env set by the caller wins).
#
#   LOGOSCORE          logoscore CLI                                   (required)
#   LIBP2P_LGX         libp2p_module bundle                            (required)
#   GIFTER_LGX         rln_gifter_module bundle                        (required)
#   LEZ_RLN_LGX        liblogos_lez_rln_module bundle                  (required)
#   EXTRA_LGX          space-separated extra bundles (verifier modules)
#   EXTRA_MODULES      space-separated module names to load before serve
#   ALLOCATOR_HOME     state dir (default ./allocator-home):
#                        node_key.hex            the libp2p identity -> PeerId
#                        consumed_nullifiers.txt spent credentials
#                        allocator.json          what to hand to clients
#                        run/                    daemon config, log, modules, pid
#   LISTEN_ADDR        libp2p listen multiaddr (default /ip4/0.0.0.0/tcp/9000)
#   ADVERTISE_ADDR     the multiaddr published to clients; defaults to
#                      LISTEN_ADDR unless that binds 0.0.0.0 (then required)
#   REGISTRY_CONFIG    registry ConfigState account for serve.config  (required)
#   PAYER              serve.wallet; "" (default) = the registry module's own payer
#   AUTH_VERIFIERS     JSON object for serve.authVerifiers; unset = OPEN gifter
#   MAX_RATE_LIMIT     serve.maxRateLimit (default 100)
#   WALLET_WAIT_S      wait for wallet_status state=ready (default 600; 0 = skip,
#                      for chainless runs against a stub registry module)
#   MIN_NATIVE_BALANCE if set, also wait until the payer holds at least this
#   DAEMON_ENV         space-separated KEY=VALUE for the daemon's environment:
#                      LEZ_RLN_SEQUENCER / LEZ_RLN_NETWORK / LEZ_RLN_PAYER /
#                      LEZ_RLN_PAYER_KEY / LEE_WALLET_HOME_DIR … Unless it names
#                      LEE_WALLET_HOME_DIR, the lez wallet (the PAYER SEED) lives
#                      in $ALLOCATOR_HOME/wallet-home — outside run/, which `up`
#                      partly wipes. (LEZ_RLN_TREE_ID_HEX is not read by the lez
#                      module; the registry's tree comes from its ConfigState.)
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/lib.sh"

CMD="${1:-up}"
ALLOCATOR_HOME="${ALLOCATOR_HOME:-$PWD/allocator-home}"
# allocator.env may only FILL IN what the environment left unset.
if [ -f "$ALLOCATOR_HOME/allocator.env" ]; then
    _saved=$(export -p)
    # shellcheck source=/dev/null
    . "$ALLOCATOR_HOME/allocator.env"
    eval "$_saved"
fi
RUN="$ALLOCATOR_HOME/run"
KEY_FILE="$ALLOCATOR_HOME/node_key.hex"
NULLIFIERS="$ALLOCATOR_HOME/consumed_nullifiers.txt"
OUT_JSON="$ALLOCATOR_HOME/allocator.json"
LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/9000}"
MAX_RATE_LIMIT="${MAX_RATE_LIMIT:-100}"
WALLET_WAIT_S="${WALLET_WAIT_S:-600}"
PAYER="${PAYER:-}"
export LOGOSCORE="${LOGOSCORE:-}"

need() { eval "[ -n \"\${$1:-}\" ]" || al_die "$1 is required (env or $ALLOCATOR_HOME/allocator.env)"; }

advertise_addr() {
    if [ -n "${ADVERTISE_ADDR:-}" ]; then printf '%s' "$ADVERTISE_ADDR"; return; fi
    case "$LISTEN_ADDR" in
        */ip4/0.0.0.0/*|*/ip6/::/*) al_die "LISTEN_ADDR binds every interface; set ADVERTISE_ADDR to the multiaddr clients should dial" ;;
        *) printf '%s' "$LISTEN_ADDR" ;;
    esac
}

serve_json() {
    AV="${AUTH_VERIFIERS:-}" CFG="$REGISTRY_CONFIG" WAL="$PAYER" NUL="$NULLIFIERS" MAXR="$MAX_RATE_LIMIT" \
    python3 -I -c '
import json, os
o = {"config": os.environ["CFG"], "wallet": os.environ["WAL"],
     "consumedNullifiersPath": os.environ["NUL"], "maxRateLimit": int(os.environ["MAXR"])}
av = os.environ.get("AV", "")
if av:
    o["authVerifiers"] = json.loads(av)
print(json.dumps(o, separators=(",", ":")))
'
}

write_out_json() { # <peerId> <advertise_addr> <peerinfo_addrs_json>
    PEER="$1" ADDR="$2" ADDRS="$3" AV="${AUTH_VERIFIERS:-}" CFG="$REGISTRY_CONFIG" WAL="$PAYER" \
    MAXR="$MAX_RATE_LIMIT" PIDF="$RUN/daemon.pid" HOME_DIR="$ALLOCATOR_HOME" \
    python3 -I - "$OUT_JSON" <<'PY'
import json, os, sys, time
av = os.environ.get("AV", "")
types = sorted(json.loads(av).keys()) if av else []
out = {
  "gifter_peer_id": os.environ["PEER"],
  "gifter_multiaddr": os.environ["ADDR"],
  "listen_addrs": json.loads(os.environ["ADDRS"] or "[]"),
  "registry_config": os.environ["CFG"],
  "payer": os.environ["WAL"] or None,
  "auth_types": types,
  "open": not types,
  "max_rate_limit": int(os.environ["MAXR"]),
  "protocol": "/logos/rln/membership/1.0.0",
  "home": os.environ["HOME_DIR"],
  "daemon_pid": int(open(os.environ["PIDF"]).read().strip() or 0),
  "served_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
}
json.dump(out, open(sys.argv[1], "w"), indent=2)
print(json.dumps(out, indent=2))
PY
}

wait_wallet() {
    local t=0 st payer bal
    [ "$WALLET_WAIT_S" -gt 0 ] 2>/dev/null || { al_say "WALLET_WAIT_S=0: not waiting for the registry wallet"; return 0; }
    al_say "waiting for liblogos_lez_rln_module wallet_status state=ready (<= ${WALLET_WAIT_S}s)"
    while [ "$t" -lt "$WALLET_WAIT_S" ]; do
        st=$(al_call "$RUN" liblogos_lez_rln_module wallet_status | al_res) || st=""
        case "$st" in *'"state":"ready"'*) break ;; esac
        sleep 5; t=$((t + 5))
    done
    case "$st" in *'"state":"ready"'*) ;; *) AL_LOG_ON_DIE="$RUN/daemon.log" al_die "wallet not ready after ${WALLET_WAIT_S}s: ${st:-<empty>}" ;; esac
    payer=$(al_field "$st" payer)
    al_say "wallet ready; module payer: ${payer:-<none>}; serve.wallet: ${PAYER:-<module payer>}"
    if [ -n "${MIN_NATIVE_BALANCE:-}" ]; then
        al_say "waiting for native balance >= $MIN_NATIVE_BALANCE on ${PAYER:-$payer}"
        t=0
        while [ "$t" -lt "$WALLET_WAIT_S" ]; do
            bal=$(al_call "$RUN" liblogos_lez_rln_module get_native_balance "$PAYER" | al_res) || bal=""
            bal=$(al_field "$bal" balance)
            case "$bal" in ''|*[!0-9]*) ;; *) [ "$bal" -ge "$MIN_NATIVE_BALANCE" ] 2>/dev/null && break ;; esac
            sleep 10; t=$((t + 10))
        done
        case "$bal" in ''|*[!0-9]*) al_die "could not read the payer's native balance" ;; esac
        [ "$bal" -ge "$MIN_NATIVE_BALANCE" ] || al_die "payer balance $bal < $MIN_NATIVE_BALANCE after ${WALLET_WAIT_S}s"
        al_say "payer balance: $bal"
    fi
}

cmd_up() {
    need LOGOSCORE; need LIBP2P_LGX; need GIFTER_LGX; need LEZ_RLN_LGX; need REGISTRY_CONFIG
    [ -x "$LOGOSCORE" ] || al_die "LOGOSCORE not executable: $LOGOSCORE"
    local adv; adv=$(advertise_addr) || exit 1
    if [ -f "$RUN/daemon.pid" ] && kill -0 "$(cat "$RUN/daemon.pid")" 2>/dev/null; then
        al_die "a daemon is already running for $ALLOCATOR_HOME (pid $(cat "$RUN/daemon.pid")); use 'serve' to refresh or 'down' first"
    fi
    [ -n "${AUTH_VERIFIERS:-}" ] || al_say "WARNING: AUTH_VERIFIERS unset — this is an OPEN gifter; it pays for any commitment it is sent"
    mkdir -p "$ALLOCATOR_HOME" "$RUN"
    rm -rf "$RUN/modules" "$RUN/config"
    mkdir -p "$RUN/modules"
    al_install_lgx "$LIBP2P_LGX" "$RUN/modules"
    al_install_lgx "$LEZ_RLN_LGX" "$RUN/modules"
    al_install_lgx "$GIFTER_LGX" "$RUN/modules"
    local x
    for x in ${EXTRA_LGX:-}; do al_install_lgx "$x" "$RUN/modules"; done

    # shellcheck disable=SC2086
    # The lez module defaults its wallet home to <persistence>/wallet-home
    # under run/persist; keep the payer seed beside the node key instead.
    case " ${DAEMON_ENV:-} " in
        *" LEE_WALLET_HOME_DIR="*) al_daemon_start "$RUN" ${DAEMON_ENV:-} ;;
        *) al_daemon_start "$RUN" "LEE_WALLET_HOME_DIR=$ALLOCATOR_HOME/wallet-home" ${DAEMON_ENV:-} ;;
    esac
    # libp2p first: the gifter opens its client to it on load; the registry
    # module and every verifier before serve.
    al_load "$RUN" libp2p_module
    al_load "$RUN" liblogos_lez_rln_module
    for x in ${EXTRA_MODULES:-}; do al_load "$RUN" "$x"; done
    al_load "$RUN" rln_gifter_module

    local key peer addrs prev
    key=$(al_node_key "$KEY_FILE" "$RUN") || exit 1
    peer=$(al_libp2p_up "$RUN" "$LISTEN_ADDR" "$key") || exit 1
    addrs=$(al_peer_addrs "$RUN")
    al_say "libp2p up: $peer listening $addrs"
    # The PeerId is what clients pin. If a previous run published one from the
    # same key file, this run must come up as the same peer or createNode
    # silently ignored privKey (see lib.sh al_libp2p_up).
    if [ -f "$OUT_JSON" ]; then
        prev=$(al_field "$(cat "$OUT_JSON")" gifter_peer_id)
        if [ -n "$prev" ] && [ "$prev" != "$peer" ]; then
            AL_LOG_ON_DIE="$RUN/daemon.log" al_die "PeerId changed: $OUT_JSON published $prev, this run is $peer — privKey not applied, or node_key.hex was replaced"
        fi
    fi

    wait_wallet
    al_serve "$RUN" "$(serve_json)" >/dev/null || exit 1
    al_say "allocator up — hand clients gifter_peer_id + gifter_multiaddr from $OUT_JSON"
    write_out_json "$peer" "$adv" "$addrs"
}

cmd_serve() {
    need LOGOSCORE; need REGISTRY_CONFIG
    if ! { [ -f "$RUN/daemon.pid" ] && kill -0 "$(cat "$RUN/daemon.pid")" 2>/dev/null; }; then
        al_die "no running daemon for $ALLOCATOR_HOME"
    fi
    [ -f "$OUT_JSON" ] || al_die "no $OUT_JSON — run 'up' first"
    local adv peer addrs
    adv=$(advertise_addr) || exit 1
    al_serve "$RUN" "$(serve_json)" >/dev/null || exit 1
    peer=$(al_field "$(cat "$OUT_JSON")" gifter_peer_id)
    addrs=$(al_peer_addrs "$RUN")
    write_out_json "$peer" "$adv" "$addrs"
}

cmd_status() {
    if [ -f "$RUN/daemon.pid" ] && kill -0 "$(cat "$RUN/daemon.pid")" 2>/dev/null; then
        al_say "daemon running (pid $(cat "$RUN/daemon.pid"))"
    else
        al_say "daemon not running"
    fi
    [ -f "$OUT_JSON" ] && cat "$OUT_JSON"
    [ -s "$NULLIFIERS" ] && al_say "consumed nullifiers: $(wc -l < "$NULLIFIERS" | tr -d ' ')"
    return 0
}

cmd_down() {
    need LOGOSCORE
    al_daemon_stop "$RUN"
    rm -rf "$RUN/modules"
}

case "$CMD" in
    up)     cmd_up ;;
    serve)  cmd_serve ;;
    status) cmd_status ;;
    down)   cmd_down ;;
    *) al_die "usage: run-allocator.sh up|serve|status|down" ;;
esac
