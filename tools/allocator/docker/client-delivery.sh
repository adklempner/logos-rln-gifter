# shellcheck shell=bash
# shellcheck disable=SC2034  # WATCH_PIDS is read by client-entrypoint.sh's stop trap
# tools/allocator/docker/client-delivery.sh — CLIENT_MODE=delivery of
# client-entrypoint.sh: a long-running delivery_module node whose RLN
# membership comes from the allocator (delegated register_membership in
# liblogos_rln_module), then is used: sends carry an RLN proof, receives are
# printed.
#
# Sourced by client-entrypoint.sh (functions only). It relies on the
# entrypoint's globals: DATA, ALLOCATOR_PEER_ID, ALLOCATOR_MULTIADDR,
# AUTH_TYPE, AUTH_PROVIDER, AUTH_ARGS, AUTH_PAYLOAD, RATE, and fills
# WATCH_PIDS, which the entrypoint's stop trap kills.
#
# Order (cd_main): load modules -> watch rln + delivery events -> rln start
# (provision:false) -> lez wallet ready + registry roots -> membership
# (skip / poll / register / park) -> delivery createNode, rlnState Ready,
# start, subscribe -> send (sender) -> status loop. It never returns: fatal
# paths exit through al_die (the container restarts), a membership that
# cannot be obtained without spending another grant PARKS (stays up, prints
# the reason, never re-registers).
#
# Traps carried over from the e2e harness (scenarios/delivery-rln-gifter):
# - delivery's createNode re-calls rln `start` WITHOUT provision:false, so
#   the membership must be active before it, or the module parks a
#   provisioning task on this never-funded payer.
# - the lez wallet must be `ready` (and the registry roots readable) BEFORE
#   register_membership: its confirmation window starts at submit.
# - the rln identifier is hex and the send payload is bytes: both go as
#   @file arguments so the CLI cannot re-type them.
# - nim-libp2p resolves no /dns4 in the container: multiaddrs are IPv4.

# ---------------------------------------------------------------- env

cd_env_pre_daemon() {
    CD_DEF_REGISTRY="logos:testnet:fd322d32a46ddf57eece9db8d68e9b722262d1f770760fca63b8cb9e7775b971"
    CD_DEF_RLNID="5e269b6a19fce081f5808b13442dcbc3522197638dd38df5a28bc4e55236b977"
    CD_DEF_EPOCH=600
    REGISTRY_ID="${REGISTRY_ID:-$CD_DEF_REGISTRY}"
    RLN_IDENTIFIER=$(printf '%s' "${RLN_IDENTIFIER:-$CD_DEF_RLNID}" | tr -d '[:space:]' | tr 'A-F' 'a-f')
    RLN_IDENTIFIER="${RLN_IDENTIFIER#0x}"
    EPOCH_SIZE_SEC="${EPOCH_SIZE_SEC:-$CD_DEF_EPOCH}"
    DELIVERY_REGISTER="${DELIVERY_REGISTER:-1}"
    REG_WAIT_S="${REG_WAIT_S:-600}"
    # Unset = logos.test; set but empty = the flat two-node config.
    DELIVERY_PRESET="${DELIVERY_PRESET-logos.test}"
    DELIVERY_VALIDATE="${DELIVERY_VALIDATE:-0}"
    DELIVERY_EXTIP="${DELIVERY_EXTIP:-}"
    DELIVERY_STATICNODES="${DELIVERY_STATICNODES:-}"
    DELIVERY_CLUSTER_ID="${DELIVERY_CLUSTER_ID:-198}"
    DELIVERY_TOPIC="${DELIVERY_TOPIC:-/rln-gifter/1/delivery-demo/proto}"
    DELIVERY_ROLE="${DELIVERY_ROLE:-receiver}"
    DELIVERY_SEND="${DELIVERY_SEND:-}"
    DELIVERY_SEND_EVERY_S="${DELIVERY_SEND_EVERY_S:-0}"
    DELIVERY_STATUS_EVERY_S="${DELIVERY_STATUS_EVERY_S:-60}"
    DELIVERY_CONNECT_WAIT_S="${DELIVERY_CONNECT_WAIT_S:-600}"
    DELIVERY_EVENT_WAIT_S="${DELIVERY_EVENT_WAIT_S:-90}"
    DELIVERY_RLN_READY_S="${DELIVERY_RLN_READY_S:-180}"
    WALLET_WAIT_S="${WALLET_WAIT_S:-900}"
    ROOTS_WAIT_S="${ROOTS_WAIT_S:-300}"
    # Container-side ports, fixed: delivery-compose.yml publishes these.
    CD_TCP_PORT=30303
    CD_DISCV5_PORT=9000
    CD_EV="${CD_EV:-/usr/local/lib/allocator/client-events.py}"
    # The rln request family arrives under the dispatch name upstream and the
    # plain name on older builds; match both.
    CD_EV_GEN='(rlnGenerateProofRequest|dispatchRlnGenerateProofRequestEvent)'

    case "$REGISTRY_ID" in
        logos:*:*) ;;
        *) al_die "REGISTRY_ID must be logos:<network>:<config hex>, got '$REGISTRY_ID'" ;;
    esac
    case "$RLN_IDENTIFIER" in
        *[!0-9a-f]*|'') al_die "RLN_IDENTIFIER must be 32-byte hex, got '$RLN_IDENTIFIER'" ;;
    esac
    [ "${#RLN_IDENTIFIER}" = 64 ] || al_die "RLN_IDENTIFIER must be 64 hex chars, got ${#RLN_IDENTIFIER}"
    case "$DELIVERY_ROLE" in
        receiver|sender) ;;
        *) al_die "DELIVERY_ROLE must be receiver or sender, got '$DELIVERY_ROLE'" ;;
    esac
    case "$DELIVERY_VALIDATE" in 0|1) ;; *) al_die "DELIVERY_VALIDATE must be 0 or 1" ;; esac
    case "$DELIVERY_REGISTER" in 0|1) ;; *) al_die "DELIVERY_REGISTER must be 0 or 1" ;; esac
    case "$EPOCH_SIZE_SEC$REG_WAIT_S$DELIVERY_SEND_EVERY_S$DELIVERY_STATUS_EVERY_S$DELIVERY_CONNECT_WAIT_S$DELIVERY_EVENT_WAIT_S$DELIVERY_RLN_READY_S$WALLET_WAIT_S$ROOTS_WAIT_S" in
        *[!0-9]*) al_die "EPOCH_SIZE_SEC, *_WAIT_S, *_EVERY_S and DELIVERY_RLN_READY_S must be whole seconds" ;;
    esac
    [ "$DELIVERY_STATUS_EVERY_S" -gt 0 ] || DELIVERY_STATUS_EVERY_S=60
    case "$DELIVERY_EXTIP" in
        ''|*[!0-9.]*) [ -z "$DELIVERY_EXTIP" ] || al_die "DELIVERY_EXTIP must be an IPv4 address, got '$DELIVERY_EXTIP'" ;;
    esac
    CD_NET="${REGISTRY_ID#logos:}"
    CD_NET="${CD_NET%%:*}"

    # The daemon inherits this shell's environment: the lez module reads its
    # wallet config from it. The wallet home is on the volume; this payer is
    # never funded (the allocator pays), so no payer key is passed.
    export LEZ_RLN_SEQUENCER="${LEZ_RLN_SEQUENCER:-https://testnet.lez.logos.co/}"
    export LEE_WALLET_HOME_DIR="$DATA/wallet-home-$CD_NET"
    export NSSA_WALLET_HOME_DIR="$LEE_WALLET_HOME_DIR"
    unset LEZ_RLN_PAYER LEZ_RLN_PAYER_KEY
    ( umask 077; mkdir -p "$LEE_WALLET_HOME_DIR" ) || al_die "cannot create $LEE_WALLET_HOME_DIR"
    # The session dir under $DATA holds the RLN keystore (the membership
    # secret): owner-only.
    chmod 700 "$DATA" 2>/dev/null || true

    CD_RLNID_ARG="$DATA/rln-id.arg"
    printf '%s' "$RLN_IDENTIFIER" > "$CD_RLNID_ARG" || al_die "cannot write $CD_RLNID_ARG"

    # Presets: the shipped logos.test already names the testnet registry and
    # rln identifier (validation off). Anything else (flat config, validation
    # on, another scope) goes through a presets file keyed by the preset name
    # ("" for the flat config), read at createNode.
    CD_PRESETS="$DATA/rln-presets.json"
    if [ "$DELIVERY_PRESET" = logos.test ] && [ "$DELIVERY_VALIDATE" = 0 ] \
        && [ "$REGISTRY_ID" = "$CD_DEF_REGISTRY" ] && [ "$RLN_IDENTIFIER" = "$CD_DEF_RLNID" ] \
        && [ "$EPOCH_SIZE_SEC" = "$CD_DEF_EPOCH" ]; then
        rm -f "$CD_PRESETS"
        unset LOGOS_DELIVERY_RLN_PRESETS
        al_say "rln presets: shipped logos.test (validation off)"
    else
        PRESET="$DELIVERY_PRESET" REG="$REGISTRY_ID" RID="$RLN_IDENTIFIER" EPOCH="$EPOCH_SIZE_SEC" VAL="$DELIVERY_VALIDATE" \
            python3 -I -c '
import json, os, sys
e = os.environ
entry = {"enabled": True, "registry-id": e["REG"], "rln-identifier": e["RID"],
         "epoch-size-sec": int(e["EPOCH"])}
# A named preset gets the switch spelled out (logos.test ships it off); the
# flat entry ("") keeps the module default (validating, as in the e2e
# harness) unless DELIVERY_VALIDATE=1 asks for it explicitly.
if e["PRESET"] or e["VAL"] == "1":
    entry["enable-validation"] = e["VAL"] == "1"
with open(sys.argv[1], "w") as f:
    json.dump({e["PRESET"]: entry}, f)
' "$CD_PRESETS" || al_die "cannot write $CD_PRESETS"
        export LOGOS_DELIVERY_RLN_PRESETS="$CD_PRESETS"
        al_say "rln presets: $CD_PRESETS (preset '${DELIVERY_PRESET}', validation $DELIVERY_VALIDATE): $(cat "$CD_PRESETS")"
    fi
}

# ---------------------------------------------------------------- modules

cd_load() {
    ctl_load libp2p_module
    ctl_load liblogos_lez_rln_module
    ctl_load liblogos_rln_module
    ctl_load rln_gifter_module
    # The producer the delegated request names must live in this daemon; a
    # raw payload, auth_type none or no registration needs none.
    CD_PRODUCER=""
    if [ "$DELIVERY_REGISTER" = 1 ] && [ "$AUTH_TYPE" != none ] && [ -z "$AUTH_PAYLOAD" ] && [ -n "$AUTH_PROVIDER" ]; then
        CD_PRODUCER="$AUTH_PROVIDER"
        ctl_load "$CD_PRODUCER"
    fi
    # Last: its createNode re-starts the rln module, which must be loaded.
    ctl_load delivery_module
    al_say "modules: $(ctl --json module ls 2>/dev/null | python3 -I -c 'import json,sys
try:
    print(" ".join("%s@%s" % (m["name"], m.get("version","")) for m in json.load(sys.stdin) if m.get("status") == "loaded"))
except Exception: print("?")')"
    cd_allowlist_identity
}

# allowlist types: print the id the operator must allowlist (the probe's
# logic; a private_key in CLIENT_AUTH_ARGS is imported for eth/lez so it is
# the signer, otherwise identity reads it, with the args for logos).
cd_allowlist_identity() {
    local pk meth req res id
    [ "$CD_PRODUCER" = allowlist_sign_module ] || return 0
    pk=$(ARGS="$AUTH_ARGS" python3 -I -c 'import json, os
try: print(json.loads(os.environ["ARGS"]).get("private_key", "") or "")
except Exception: print("")')
    case "$AUTH_TYPE" in eth-allowlist|lez-allowlist) ;; *) pk="" ;; esac
    if [ -n "$pk" ]; then
        meth=import_key
        req=$(AT="$AUTH_TYPE" PK="$pk" python3 -I -c 'import json, os
print(json.dumps({"auth_type": os.environ["AT"], "private_key": os.environ["PK"]}, separators=(",", ":")))')
    else
        meth=identity
        req=$(AT="$AUTH_TYPE" ARGS="$AUTH_ARGS" python3 -I -c 'import json, os
try: a = json.loads(os.environ["ARGS"]) if os.environ["ARGS"] else {}
except Exception: a = {}
a = {k: v for k, v in a.items() if k != "private_key"} if isinstance(a, dict) else {}
print(json.dumps({"auth_type": os.environ["AT"], "args": a}, separators=(",", ":")))')
    fi
    res=$(al_call allowlist_sign_module "$meth" "$req" | al_res) || res=""
    id=$(al_field "$res" id)
    if [ -z "$id" ]; then
        al_say "WARNING: allowlist_sign_module.$meth ($AUTH_TYPE) reported no id: ${res:-<no reply>}"
        return 0
    fi
    case "$AUTH_TYPE" in
        lez-allowlist) al_say "lez-allowlist account id (the operator allowlists this): $(al_field "$res" id_base58) (hex $id)${pk:+ (from CLIENT_AUTH_ARGS private_key)}" ;;
        logos-allowlist) al_say "logos-allowlist public key (the operator allowlists this): $id (source $(al_field "$res" source))" ;;
        *) al_say "eth-allowlist address (the operator allowlists this): $id${pk:+ (from CLIENT_AUTH_ARGS private_key)}" ;;
    esac
}

# ---------------------------------------------------------------- events
# `logosctl --json watch <module>` appends to $DATA/events-<module>.jsonl
# (kept across restarts); each run reads from the size the file had when its
# watcher attached. Cursors live in $DATA/ev-cursors/ and are reset per run.

cd_watch_spawn() { # <module>  -> CD_LAST_PID
    ( exec logosctl --json watch "$1" >>"$DATA/events-$1.jsonl" 2>&1 </dev/null ) &
    CD_LAST_PID=$!
}

cd_watch_start() {
    local m f
    rm -rf "$DATA/ev-cursors"
    mkdir -p "$DATA/ev-cursors" || al_die "cannot create $DATA/ev-cursors"
    for m in liblogos_rln_module delivery_module; do
        f="$DATA/events-$m.jsonl"
        touch "$f"
        # Rotate a stream that grew past 50 MB over many restarts.
        if [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -gt 52428800 ]; then
            mv -f "$f" "$f.1"; : > "$f"
        fi
        stat -c %s "$f" > "$DATA/ev-cursors/$m.start" 2>/dev/null || echo 0 > "$DATA/ev-cursors/$m.start"
    done
    cd_watch_spawn liblogos_rln_module; CD_WPID_RLN=$CD_LAST_PID
    cd_watch_spawn delivery_module; CD_WPID_DELIVERY=$CD_LAST_PID
    WATCH_PIDS="$CD_WPID_RLN $CD_WPID_DELIVERY"
    al_say "watching liblogos_rln_module + delivery_module events -> $DATA/events-<module>.jsonl"
}

# A watcher that died (daemon hiccup) is re-attached; its cursor survives.
cd_watch_check() {
    if ! kill -0 "$CD_WPID_RLN" 2>/dev/null; then
        al_say "rln event watcher exited; re-attaching"
        cd_watch_spawn liblogos_rln_module; CD_WPID_RLN=$CD_LAST_PID
    fi
    if ! kill -0 "$CD_WPID_DELIVERY" 2>/dev/null; then
        al_say "delivery event watcher exited; re-attaching"
        cd_watch_spawn delivery_module; CD_WPID_DELIVERY=$CD_LAST_PID
    fi
    WATCH_PIDS="$CD_WPID_RLN $CD_WPID_DELIVERY"
}

# Usage: ev_wait <module> <event-regex> <timeout_s> [substring]
# Prints the first matching event (compact JSON) since this wait's cursor and
# consumes it; returns 1 on timeout. Polls every 2 s.
ev_wait() {
    local key
    key=$(printf '%s' "$2" | tr -c '[:alnum:]' '_')
    python3 -I "$CD_EV" wait "$DATA/events-$1.jsonl" "$DATA/ev-cursors/$1.$key" \
        "$DATA/ev-cursors/$1.start" "$2" "$3" "${4:-}"
}

# Usage: ev_new <module>  — one summary line per event since the last call.
ev_new() {
    python3 -I "$CD_EV" new "$DATA/events-$1.jsonl" "$DATA/ev-cursors/$1.new" "$DATA/ev-cursors/$1.start"
}

# ---------------------------------------------------------------- rln + wallet

cd_rln_start() {
    local out
    out=$(al_value "$(al_call liblogos_rln_module start \
        "{\"epoch_size_sec\":$EPOCH_SIZE_SEC,\"registries\":[\"$REGISTRY_ID\"],\"provision\":false}" | al_res)")
    case "$out" in
        *'"started":true'*) al_say "rln module started on $REGISTRY_ID (epoch ${EPOCH_SIZE_SEC}s, provision off)" ;;
        *) al_die "rln start failed: ${out:-<empty>}" ;;
    esac
}

cd_wallet_check() {
    local st state detail
    [ -n "$(ctl_daemon_pid)" ] || { CD_WHY="daemon died while waiting for the wallet"; return 2; }
    st=$(al_call liblogos_lez_rln_module wallet_status | al_res)
    state=$(al_field "$st" state); detail=$(al_field "$st" detail)
    [ "$st" = "$CD_WLAST" ] || { al_say "wallet_status: ${st:-<empty>}"; CD_WLAST="$st"; }
    case "$state" in
        ready) return 0 ;;
        failed) CD_WHY="lez wallet failed: ${detail:-?}"; return 2 ;;
    esac
    case "$detail" in
        *"no network selected"*)
            if [ "$CD_USENET" = 0 ]; then
                CD_USENET=1
                al_say "wallet unbound: use_network $CD_NET -> $(al_call liblogos_lez_rln_module use_network "$CD_NET" | al_res)"
            fi ;;
    esac
    return 1
}

cd_roots_check() {
    local r
    r=$(al_value "$(al_call liblogos_rln_module get_valid_roots "$REGISTRY_ID" | al_res)")
    case "$r" in
        *'"valid_roots":["'*) return 0 ;;
    esac
    return 1
}

# Wallet ready, then the registry read path warm — both before any
# register_membership (its confirmation window starts at submit).
cd_wallet_wait() {
    local t0 rc
    CD_WLAST=""; CD_USENET=0; CD_WHY=""
    t0=$(date +%s)
    al_poll "$WALLET_WAIT_S" 5 cd_wallet_check; rc=$?
    case "$rc" in
        2) al_die "$CD_WHY" ;;
        1) al_die "lez wallet not ready after ${WALLET_WAIT_S}s (last: ${CD_WLAST:-<empty>})" ;;
    esac
    al_say "wallet ready after $(( $(date +%s) - t0 ))s"
    t0=$(date +%s)
    al_poll "$ROOTS_WAIT_S" 5 cd_roots_check \
        || al_die "registry roots not readable after ${ROOTS_WAIT_S}s (wallet still syncing?)"
    al_say "registry read path warm after $(( $(date +%s) - t0 ))s"
}

# ---------------------------------------------------------------- membership

cd_ms_read() { # -> CD_MS, CD_STATE
    CD_MS=$(al_value "$(al_call liblogos_rln_module get_membership_state "$REGISTRY_ID" "@$CD_RLNID_ARG" | al_res)") || CD_MS=""
    CD_STATE=$(al_field "$CD_MS" state)
}

cd_ms_known() { cd_ms_read; [ -n "$CD_STATE" ]; }

cd_ms_await_check() {
    cd_ms_read
    [ "$CD_STATE" = "$CD_SLAST" ] || { al_say "membership state: ${CD_STATE:-<none>}"; CD_SLAST="$CD_STATE"; }
    case "$CD_STATE" in
        active|grace_period) return 0 ;;
        failed) return 2 ;;
    esac
    return 1
}

# The newest membership of this scope in get_memberships (highest
# submitted_at; the last listed when none carries it), as compact JSON.
cd_newest_membership() {
    al_call liblogos_rln_module get_memberships "$REGISTRY_ID" | al_res | python3 -I -c '
import json, sys
def unwrap(d):
    while True:
        if isinstance(d, str):
            try:
                d = json.loads(d); continue
            except Exception:
                return d
        if isinstance(d, dict) and "success" in d and "value" in d:
            d = d["value"]; continue
        return d
try:
    d = unwrap(json.loads(sys.stdin.read().strip() or "{}"))
    ms = [m for m in (d.get("memberships") or []) if isinstance(m, dict)]
except Exception:
    ms = []
rid = sys.argv[1]
mine = [m for m in ms if str(m.get("rln_identifier", rid)).lower().removeprefix("0x") == rid] or ms
if mine:
    best = max(enumerate(mine), key=lambda im: (im[1].get("submitted_at") or -1, im[0]))[1]
    print(json.dumps(best, separators=(",", ":")))
' "$RLN_IDENTIFIER"
}

cd_failed_reason() {
    local r
    r=$(al_field "$(cd_newest_membership)" failed_reason)
    [ -n "$r" ] || r=$(al_field "$CD_MS" failed_reason)
    printf '%s' "${r:-<no failed_reason>}"
}

# Refusals that spent nothing: the allocator refused before paying, or the
# request never reached it. Re-registering after one is safe.
cd_reason_reusable() {
    case "$1" in
        *"not allowlisted"*|*"allowlist is empty"*|*"empty allowlist"*|*insufficient_balance*|*"not final"*|*"protocolRequest:"*) return 0 ;;
    esac
    return 1
}

cd_ms_log() {
    local m
    CD_LEAF=$(al_field "$CD_MS" leaf_index)
    m=$(cd_newest_membership)
    CD_IDC=$(al_json_get "$m" credential.identity_commitment)
    al_say "membership $CD_STATE at leaf ${CD_LEAF:-?} (identity commitment ${CD_IDC:-?}, registry $REGISTRY_ID)"
}

# Usage: cd_park <reason>  — stay up, print the reason every status tick,
# never register again. Returns only if the membership turns active (a slow
# pending one); a daemon gone for 3 ticks exits for a restart.
cd_park() {
    local reason="$1" dmiss=0
    al_say "PARKED: $reason"
    printf '%s\n' "$reason" > "$DATA/parked.txt"
    while :; do
        sleep "$DELIVERY_STATUS_EVERY_S" &
        wait $!
        if [ -n "$(ctl_daemon_pid)" ]; then
            dmiss=0
        else
            dmiss=$((dmiss + 1))
            al_say "daemon status reports no running daemon (miss $dmiss/3)"
            if [ "$dmiss" -ge 3 ]; then
                al_say "daemon is gone — exiting for a restart"
                logosctl daemon stop >/dev/null 2>&1; exit 1
            fi
            continue
        fi
        cd_ms_read
        case "$CD_STATE" in
            active|grace_period)
                rm -f "$DATA/parked.txt"
                al_say "membership is now $CD_STATE — leaving park"
                cd_ms_log
                return 0 ;;
        esac
        al_say "PARKED (membership ${CD_STATE:-<none>}): $reason"
    done
}

# Poll to active; failed or timed out -> park.
cd_await_active() {
    local rc reason
    CD_SLAST=""
    al_say "waiting for the membership to go active (budget ${REG_WAIT_S}s)"
    al_poll "$REG_WAIT_S" 10 cd_ms_await_check; rc=$?
    case "$rc" in
        0)
            cd_ms_log
            TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)" ST="$CD_STATE" LEAF="$CD_LEAF" IDC="$CD_IDC" python3 -I -c '
import json, os
e = os.environ
print(json.dumps({"ts": e["TS"], "state": e["ST"], "leaf_index": e["LEAF"], "identity_commitment": e["IDC"]},
                 separators=(",", ":")))
' >> "$DATA/registrations.jsonl" ;;
        2)
            reason=$(cd_failed_reason)
            if cd_reason_reusable "$reason"; then
                cd_park "registration failed without spending a grant: $reason — fix it on the allocator side, then restart this container to register again"
            else
                cd_park "registration failed: $reason — the grant may be spent; not re-registering (manual review: logosctl call liblogos_rln_module get_memberships $REGISTRY_ID)"
            fi ;;
        *) cd_park "membership still ${CD_STATE:-<none>} after ${REG_WAIT_S}s; watching for it to go active" ;;
    esac
}

cd_register() {
    local opts reply
    if [ -z "${CD_LIBP2P_PEER:-}" ]; then
        # The gifter client dials the allocator through this daemon's libp2p.
        CD_LIBP2P_PEER=$(al_libp2p_up_any "/ip4/0.0.0.0/tcp/0")
        al_say "libp2p peer id $CD_LIBP2P_PEER (dials the allocator)"
    fi
    opts=$(RATE="$RATE" PEER="$ALLOCATOR_PEER_ID" MADDR="$ALLOCATOR_MULTIADDR" AT="$AUTH_TYPE" \
        PROV="$CD_PRODUCER" ARGS="$AUTH_ARGS" PAY="$AUTH_PAYLOAD" python3 -I -c '
import json, os
e = os.environ
o = [{"key": "rate_limit", "value": str(int(e["RATE"]))},
     {"key": "delegated", "value": "true"},
     {"key": "gifter_peer_id", "value": e["PEER"]},
     {"key": "gifter_multiaddr", "value": e["MADDR"]}]
if e["AT"] != "none":
    o.append({"key": "auth_type", "value": e["AT"]})
    if e["PAY"]:
        o.append({"key": "auth_payload", "value": e["PAY"]})
    elif e["PROV"]:
        o.append({"key": "auth_provider", "value": e["PROV"]})
    if e["ARGS"]:
        json.loads(e["ARGS"])
        o.append({"key": "auth_args", "value": e["ARGS"]})
print(json.dumps(o, separators=(",", ":")))
') || al_die "registration options could not be built (CLIENT_RATE not a number or CLIENT_AUTH_ARGS not JSON?)"
    al_say "register_membership -> $ALLOCATOR_PEER_ID @ $ALLOCATOR_MULTIADDR ($AUTH_TYPE via ${CD_PRODUCER:-raw auth_payload}, rate $RATE)"
    reply=$(al_call liblogos_rln_module register_membership "$REGISTRY_ID" "@$CD_RLNID_ARG" "$opts" | al_res)
    TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)" REG="$REGISTRY_ID" AT="$AUTH_TYPE" PROV="${CD_PRODUCER:-}" \
        PEER="$ALLOCATOR_PEER_ID" REPLY="$reply" python3 -I -c '
import json, os
e = os.environ
print(json.dumps({"ts": e["TS"], "registry": e["REG"], "auth_type": e["AT"], "auth_provider": e["PROV"],
                  "gifter_peer_id": e["PEER"], "reply": e["REPLY"]}, separators=(",", ":")))
' >> "$DATA/registrations.jsonl"
    case "$reply" in
        *'"state":"pending"'*|*'"state":"active"'*|*'\"state\":\"pending\"'*|*'\"state\":\"active\"'*)
            al_say "register_membership accepted: $reply" ;;
        "")
            # Async on the module side: an empty reply is the CLI deadline,
            # not a refusal. Never re-send — poll the state instead.
            al_say "register_membership: no reply within the CLI deadline; not re-sending, polling the state" ;;
        *)
            cd_park "register_membership refused before submitting: $reply"
            return 0 ;;
    esac
    cd_await_active
}

# Leaves with an active membership (or, for a receiver with
# DELIVERY_REGISTER=0, with none).
cd_membership() {
    local reason
    CD_LEAF=""; CD_IDC=""
    al_poll 120 5 cd_ms_known || al_die "get_membership_state answered nothing for 120 s: ${CD_MS:-<empty>}"
    al_say "membership state at start: $CD_STATE"
    case "$CD_STATE" in
        active|grace_period)
            cd_ms_log ;;
        unknown)
            if [ "$DELIVERY_REGISTER" = 1 ]; then
                cd_register
            elif [ "$DELIVERY_ROLE" = receiver ]; then
                al_say "no membership and DELIVERY_REGISTER=0: receiving only. delivery's rln start may park an awaiting_funding task on this payer — never fund it"
            else
                cd_park "no membership for $REGISTRY_ID and DELIVERY_REGISTER=0: a sender needs one"
            fi ;;
        failed)
            reason=$(cd_failed_reason)
            if [ "$DELIVERY_REGISTER" = 1 ] && cd_reason_reusable "$reason"; then
                al_say "previous registration failed without spending a grant ($reason): registering again"
                cd_register
            else
                cd_park "membership failed: $reason — not re-registering (a grant may be spent; manual review)"
            fi ;;
        *)
            # pending and any in-flight state: wait for it.
            cd_await_active ;;
    esac
}

# ---------------------------------------------------------------- delivery

cd_delivery_conf() {
    PRESET="$DELIVERY_PRESET" EXTIP="$DELIVERY_EXTIP" STATIC="$DELIVERY_STATICNODES" \
        TCP="$CD_TCP_PORT" UDP="$CD_DISCV5_PORT" CLUSTER="$DELIVERY_CLUSTER_ID" python3 -I -c '
import json, os, re
e = os.environ
static = [s for s in re.split(r"[,\s]+", e["STATIC"]) if s]
tcp, udp = int(e["TCP"]), int(e["UDP"])
if e["PRESET"]:
    o = {"logLevel": "INFO", "tcp-port": tcp, "discv5-udp-port": udp,
         "nat": ("extip:" + e["EXTIP"]) if e["EXTIP"] else "none"}
    if static:
        o["staticnodes"] = static
    conf = {"mode": "Core", "preset": e["PRESET"], "messagingOverrides": o}
else:
    # The e2e flat shape (delivery_node_conf), listening on all interfaces.
    conf = {"logLevel": "INFO", "listenAddress": "0.0.0.0", "tcpPort": tcp,
            "clusterId": e["CLUSTER"], "numShardsInNetwork": 1, "relay": True,
            "store": False, "filter": False, "lightpush": False, "peerExchange": False,
            "discv5Discovery": False, "reliabilityEnabled": True}
    if e["EXTIP"]:
        conf["nat"] = "extip:" + e["EXTIP"]
    if static:
        conf["staticnodes"] = static
print(json.dumps(conf, separators=(",", ":")))
'
}

# Usage: cd_dmust <method> <label> [args…]  -> value of a delivery call; dies
# unless it answered success:true.
cd_dmust() {
    local meth="$1" label="$2" res
    shift 2
    res=$(al_call delivery_module "$meth" "$@" | al_res)
    case "$res" in
        *'"success":true'*) al_value "$res" ;;
        *) al_die "delivery $label failed: ${res:-<empty>}" ;;
    esac
}

cd_rln_ready_check() {
    local st state msg got bad=""
    st=$(al_call delivery_module rlnState | al_res)
    case "$st" in
        *'"success":false'*) CD_WHY="rlnState answered: $st"; return 2 ;;
    esac
    state=$(al_field "$st" state); msg=$(al_field "$st" message)
    [ "$state" = "$CD_RLAST" ] || { al_say "rlnState: ${st:-<empty>}"; CD_RLAST="$state"; }
    case "$state" in
        Ready)
            got=$(al_field "$st" registryId)
            [ -z "$got" ] || [ "$got" = "$REGISTRY_ID" ] || bad="registryId is $got, expected $REGISTRY_ID"
            got=$(al_field "$st" rlnIdentifier | tr 'A-F' 'a-f'); got="${got#0x}"
            [ -n "$bad" ] || [ -z "$got" ] || [ "$got" = "$RLN_IDENTIFIER" ] || bad="rlnIdentifier is $got, expected $RLN_IDENTIFIER"
            got=$(al_field "$st" epochSizeSec)
            [ -n "$bad" ] || [ -z "$got" ] || [ "$got" = "$EPOCH_SIZE_SEC" ] || bad="epochSizeSec is $got, expected $EPOCH_SIZE_SEC"
            if [ -n "$bad" ]; then
                CD_WHY="delivery resolved a different RLN scope: $bad (peers on another scope reject each other's proofs)"
                return 2
            fi
            return 0 ;;
        Failed) CD_WHY="rlnState Failed: ${msg:-<no message>}"; return 2 ;;
        Disabled) CD_WHY="rlnState Disabled: ${msg:-no preset resolved} (did the presets file reach the daemon?)"; return 2 ;;
    esac
    return 1
}

cd_delivery_up() {
    local conf rc addrs
    conf=$(cd_delivery_conf) || al_die "delivery config could not be built"
    printf '%s' "$conf" > "$DATA/delivery-config.arg"
    al_say "delivery createNode: $conf"
    cd_dmust createNode createNode "@$DATA/delivery-config.arg" >/dev/null
    CD_RLAST=""; CD_WHY=""
    al_poll "$DELIVERY_RLN_READY_S" 5 cd_rln_ready_check; rc=$?
    case "$rc" in
        2) al_die "$CD_WHY" ;;
        1) al_die "rlnState never reached Ready within ${DELIVERY_RLN_READY_S}s" ;;
    esac
    al_say "rlnState Ready (scope $REGISTRY_ID / $RLN_IDENTIFIER / ${EPOCH_SIZE_SEC}s)"
    cd_dmust start start >/dev/null
    ev_wait delivery_module nodeStarted 60 >/dev/null || al_die "no nodeStarted event within 60 s of delivery start"
    CD_DPEER=$(cd_dmust getNodeInfo "getNodeInfo MyPeerId" MyPeerId)
    [ -n "$CD_DPEER" ] || al_die "delivery reported an empty MyPeerId"
    addrs=$(al_value "$(al_call delivery_module getNodeInfo MyMultiaddresses | al_res)") || addrs=""
    al_say "delivery peer $CD_DPEER"
    al_say "delivery multiaddrs ${addrs:-<unread>} (container tcp $CD_TCP_PORT, discv5 udp $CD_DISCV5_PORT${DELIVERY_EXTIP:+, extip $DELIVERY_EXTIP})"
    cd_dmust subscribe subscribe "$DELIVERY_TOPIC" >/dev/null
    al_say "subscribed to $DELIVERY_TOPIC as $DELIVERY_ROLE"
}

cd_conn_check() {
    CD_CONN=$(al_value "$(al_call delivery_module getConnectionStatus | al_res)") || CD_CONN=""
    case "$CD_CONN" in
        ""|*Disconnected*) return 1 ;;
    esac
    return 0
}

cd_quota() { # -> CD_QREM, CD_QLIM
    local q
    q=$(al_value "$(al_call liblogos_rln_module get_epoch_quota "$REGISTRY_ID" "@$CD_RLNID_ARG" "str:$(date +%s)" | al_res)") || q=""
    CD_QREM=$(al_field "$q" remaining)
    CD_QLIM=$(al_field "$q" rate_limit)
}

# One send; prints a RESULT line. Never fatal.
cd_send() {
    local text res reqid gen prop err hash qb
    CD_SENDS=$((CD_SENDS + 1))
    CD_LAST_SEND=$(date +%s)
    if [ "$CD_SENDS" = 1 ]; then
        al_say "waiting for a delivery connection (budget ${DELIVERY_CONNECT_WAIT_S}s)"
        if al_poll "$DELIVERY_CONNECT_WAIT_S" 10 cd_conn_check; then
            al_say "connection status: $CD_CONN"
        else
            al_say "connection status still ${CD_CONN:-<none>} after ${DELIVERY_CONNECT_WAIT_S}s; sending anyway"
        fi
        al_say "letting the relay mesh settle (15 s)"
        sleep 15
    fi
    cd_quota; qb="${CD_QREM:-?}"
    text="${DELIVERY_SEND:-hello from $(hostname) on an RLN membership granted by $ALLOCATOR_PEER_ID} #$CD_SENDS $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s' "$text" > "$DATA/payload.arg"
    res=$(al_call delivery_module send "$DELIVERY_TOPIC" "@$DATA/payload.arg" | al_res)
    case "$res" in
        *'"success":true'*) reqid=$(al_value "$res") ;;
        *) al_say "RESULT: SEND FAILED: ${res:-<empty>}"; return 1 ;;
    esac
    al_say "send #$CD_SENDS on $DELIVERY_TOPIC: request $reqid (\"$text\")"
    gen=$(ev_wait delivery_module "$CD_EV_GEN" "$DELIVERY_EVENT_WAIT_S") || gen=""
    [ -z "$gen" ] || al_say "proof generation requested: $gen"
    prop=$(ev_wait delivery_module messagePropagated "$DELIVERY_EVENT_WAIT_S" "$reqid") || prop=""
    if [ -z "$prop" ]; then
        err=$(ev_wait delivery_module messageError 1 "$reqid") || err=""
        al_say "RESULT: NOT PROPAGATED request $reqid within ${DELIVERY_EVENT_WAIT_S}s${gen:+ (a proof was requested)}${err:+: $err}"
        return 1
    fi
    hash=$(al_json_get "$prop" data.arg1)
    cd_quota
    if [ -n "$gen" ]; then
        al_say "RESULT: SENT WITH RLN PROOF hash=$hash quota $qb→${CD_QREM:-?} leaf ${CD_LEAF:-?}"
    else
        al_say "RESULT: PROPAGATED WITHOUT A PROOF REQUEST hash=$hash quota $qb→${CD_QREM:-?} leaf ${CD_LEAF:-?}"
    fi
    TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)" REQ="$reqid" HASH="$hash" PROOF="${gen:+1}" QB="$qb" QA="${CD_QREM:-}" TEXT="$text" \
        python3 -I -c '
import json, os
e = os.environ
print(json.dumps({"ts": e["TS"], "request_id": e["REQ"], "hash": e["HASH"], "proof": e["PROOF"] == "1",
                  "quota_before": e["QB"], "quota_after": e["QA"], "payload": e["TEXT"]}, separators=(",", ":")))
' >> "$DATA/sends.jsonl"
    return 0
}

cd_print_events() {
    local m line
    for m in liblogos_rln_module delivery_module; do
        while IFS= read -r line; do
            case "$line" in
                RECEIVED*) CD_RECEIVED=$((CD_RECEIVED + 1)); al_say "$line" ;;
                VALIDATE*) CD_VALIDATED=$((CD_VALIDATED + 1)) ;;
                *) al_say "$line" ;;
            esac
        done < <(ev_new "$m")
    done
}

cd_status_loop() {
    local dmiss=0 now
    while :; do
        sleep "$DELIVERY_STATUS_EVERY_S" &
        wait $!
        if [ -n "$(ctl_daemon_pid)" ]; then
            dmiss=0
        else
            dmiss=$((dmiss + 1))
            al_say "daemon status reports no running daemon (miss $dmiss/3)"
            if [ "$dmiss" -ge 3 ]; then
                al_say "daemon is gone — exiting for a restart (an active membership is not registered again)"
                logosctl daemon stop >/dev/null 2>&1; exit 1
            fi
            continue
        fi
        cd_watch_check
        cd_print_events
        cd_conn_check
        cd_quota
        cd_ms_read
        al_say "status: $DELIVERY_ROLE conn=${CD_CONN:-?} membership=${CD_STATE:-?} leaf=${CD_LEAF:-?} quota=${CD_QREM:-?}/${CD_QLIM:-?} received=$CD_RECEIVED validated=$CD_VALIDATED sent=$CD_SENDS peer=${CD_DPEER:-?}"
        if [ "$DELIVERY_ROLE" = sender ] && [ "$DELIVERY_SEND_EVERY_S" -gt 0 ]; then
            now=$(date +%s)
            [ $(( now - CD_LAST_SEND )) -lt "$DELIVERY_SEND_EVERY_S" ] || cd_send
        fi
    done
}

# ---------------------------------------------------------------- main

cd_main() {
    CD_SENDS=0; CD_RECEIVED=0; CD_VALIDATED=0; CD_LAST_SEND=$(date +%s)
    CD_LIBP2P_PEER=""; CD_DPEER=""; CD_CONN=""; CD_QREM=""; CD_QLIM=""
    cd_load
    cd_watch_start
    cd_rln_start
    cd_wallet_wait
    cd_membership
    cd_delivery_up
    [ "$DELIVERY_ROLE" != sender ] || cd_send
    cd_status_loop
}
