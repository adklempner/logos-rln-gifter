#!/usr/bin/env bash
# tools/allocator/docker/verify-local.sh — prove the container end to end on
# the machine that built it; an unfunded payer is enough, a funded local
# payer turns the refusals into grants.
#
# Needs: the compose service up (`docker compose up -d --build`), and on the
# host a nix-built logoscore plus the -dev bundles verify-chainless.sh uses
# (LOGOSCORE, LIBP2P_LGX, GIFTER_LGX, ETH_SIGN_LGX resolve the same way).
# The host port is HOST_PORT from the environment, default 9000, as in
# compose.yml (the advertised port may be a public/forwarded one).
#
# Asserts:
#   D1 allocator.json published with served:true and the expected auth types
#      (eth-allowlist; keycard-attestation unless KEYCARD_TRUSTED_CAS=none;
#      logos-allowlist / lez-allowlist unless LOGOS_ALLOWLIST / LEZ_ALLOWLIST=0)
#   D2 the published port answers from the host and peerInfo in the container
#      shows the persisted PeerId
#   D3 `docker compose restart` keeps the PeerId and re-serves
#   D4 killing the daemon inside the container makes the container restart and
#      re-serve (PeerId unchanged)
#   D5 adding this client's eth_sign_module address to allowlist.txt is picked
#      up (re-serve logged) without a restart
#   D6 an eth-allowlist request from the client passes the verifier and reaches
#      the registry: a GRANT (leaf_index, nullifier count +1), or "credential
#      already used" / insufficient_balance (unfunded payer; count unchanged)
#   D7 the client routes auth_type verbatim (client-side refusal; the
#      allocator's pow verifier is not exercised here)
#   D8 keycard-attestation, synthetic, through the CLIENT CONTAINER
#      (client-compose.yml), only on a local zone with the test CA
#      runs/keycard-test-ca.hex trusted in KEYCARD_TRUSTED_CAS (else SKIP):
#      D8a a card under an untrusted CA is refused, nothing consumed
#      D8b a fresh card under the test CA is granted (its nullifier persisted)
#          or refused insufficient_balance
#      D8c (after a D8b grant) the same card, new commitment: credential
#          already used
#   D9 logos-allowlist through the CLIENT CONTAINER: logos_sign_module with
#      node_url http://host.docker.internal:18080 (the follower in ./node, one
#      PoWClaim key; else SKIP). The key K the client prints is appended to
#      config/allowlist-logos.txt, the re-serve awaited:
#      D9a unlisted K is refused, D9b listed K: GRANT or insufficient_balance,
#      D9c (after a grant) the same K again: credential already used
#   D10 lez-allowlist through the client container: a fresh key (openssl rand
#      -hex 32, kept in this run's dir under runs/) given as CLIENT_AUTH_ARGS
#      private_key; the base58 account id it prints is appended to
#      config/allowlist-lez.txt:
#      D10a unlisted refused, D10b listed (base58): GRANT or insufficient_
#      balance, D10c (after a grant) replay: credential already used,
#      D10d a second key listed by its 64-hex account id: GRANT or insufficient
# D6, D8, D9 and D10 spend the payer and consume credentials: skipped unless
# the registry ref is local or ALLOW_SPEND=1. Teardown removes this run's
# `# verify-local` stamps (and the client address / logos key / lez ids if
# this run added them) from config/allowlist{,-logos,-lez}.txt.
# Env: CLIENT_PORT (default 0 = ephemeral), KEEP=1 leaves the client daemon up,
# HOST_PORT (default 9000), ALLOW_SPEND=1.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AL="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$AL/../.." && pwd)"
. "$AL/lib.sh"

POC="$REPO/tools/pow-claim-poc"
# artifacts.env supplies the libp2p bundle only; its gifter/eth paths are bare
# store paths nix GC may have taken, so this repo's result-lgx links win.
if [ -f "$POC/runs/artifacts.env" ]; then
    _l="${LIBP2P_LGX:-}"; _g="${GIFTER_LGX:-}"; _e="${ETH_SIGN_LGX:-}"
    # shellcheck source=/dev/null
    . "$POC/runs/artifacts.env"
    LIBP2P_LGX="${_l:-$LIBP2P_LGX}"; GIFTER_LGX="$_g"; ETH_SIGN_LGX="$_e"
fi
LOGOSCORE="${LOGOSCORE:-$POC/runs/logos/bin/logoscore}"
GIFTER_LGX="${GIFTER_LGX:-$(find "$REPO/rust/rln-gifter-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
ETH_SIGN_LGX="${ETH_SIGN_LGX:-$(find "$REPO/rust/eth-sign-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
export LOGOSCORE
for v in LOGOSCORE LIBP2P_LGX GIFTER_LGX ETH_SIGN_LGX; do
    eval "[ -e \"\${$v:-}\" ]" || al_die "$v missing: $(eval "printf '%s' \"\${$v:-<unset>}\"")"
done

COMPOSE="docker compose -f $HERE/compose.yml"
WORK="$HERE/runs/$(date +%Y%m%d-%H%M%S)"
CLIENT="$WORK/client"
mkdir -p "$CLIENT/modules"
FAILS=0; RESULTS=""
check() { if [ "$1" = 1 ]; then al_say "PASS $2 $3"; RESULTS="$RESULTS$2=pass "; else al_say "FAIL $2 $3"; RESULTS="$RESULTS$2=FAIL "; FAILS=$((FAILS + 1)); fi; }
skip() { al_say "SKIP $1 $2"; RESULTS="$RESULTS$1=skip "; }
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
# D6 and D8 spend the payer and consume credentials: local zone only unless
# ALLOW_SPEND=1.
may_spend() { [ "$REF" = local ] || [ "${ALLOW_SPEND:-0}" = 1 ]; }
ADDR=""; ADDED=0
# Lines this run appended to the logos / lez allowlists (removed in teardown).
LOGOS_LINES=""; LEZ_LINES=""

env_get() { sed -n "s/^$1=//p" "$HERE/allocator.env" 2>/dev/null | tail -1 | tr -d "\"' \r"; }
alloc_json() { $COMPOSE exec -T allocator cat /var/lib/allocator/allocator.json 2>/dev/null; }
# consumed_nullifiers-<ref>.txt, ref = the middle field of registry_id.
nul_lines() { $COMPOSE exec -T allocator cat "/var/lib/allocator/consumed_nullifiers-${REF}.txt" 2>/dev/null; }
nul_count() { nul_lines | grep -c . | tr -d ' '; }
alloc_logs() { $COMPOSE logs --no-color --tail "${1:-50}" allocator 2>/dev/null; }
wait_log() { # <pattern> <seconds> <since>  — a log line matching, logged after <since>
    local pat="$1" secs="$2" since="$3" t=0
    while [ "$t" -lt "$secs" ]; do
        $COMPOSE logs --no-color --since "$since" allocator 2>/dev/null | grep -q -- "$pat" && return 0
        sleep 3; t=$((t + 3))
    done
    return 1
}
wait_served() { # <seconds> [previous updated_at]  — a NEW served:true publish
    local t=0 j
    while [ "$t" -lt "$1" ]; do
        j=$(alloc_json)
        if [ "$(al_field "$j" served)" = true ] && [ "$(al_field "$j" updated_at)" != "${2:-}" ]; then
            printf '%s' "$j"; return 0
        fi
        sleep 3; t=$((t + 3))
    done
    return 1
}

teardown() {
    # The allowlist is a shared host file: drop this run's stamps, and the
    # client address only when this run added it (it may be hand-listed).
    local al="$HERE/config/allowlist.txt"
    if [ -f "$al" ]; then
        if [ "$ADDED" = 1 ] && [ -n "$ADDR" ]; then
            sed -i.bak "/^$ADDR\$/d;/^# verify-local /d" "$al"
        else
            sed -i.bak "/^# verify-local /d" "$al"
        fi
        rm -f "$al.bak"
    fi
    local f l
    for f in logos:$LOGOS_LINES lez:$LEZ_LINES; do
        al="$HERE/config/allowlist-${f%%:*}.txt"
        [ -f "$al" ] || continue
        for l in $(printf '%s' "${f#*:}" | tr ',' ' '); do
            sed -i.bak "/^$l\$/d" "$al"
        done
        sed -i.bak "/^# verify-local /d" "$al"
        rm -f "$al.bak"
    done
    if [ "${KEEP:-0}" = 1 ]; then al_say "KEEP=1: client left up ($WORK)"; return; fi
    al_daemon_stop "$CLIENT" || true
    rm -rf "$CLIENT/modules"
}
trap teardown EXIT

# ---------------------------------------------------------------- D1/D2
al_say "==== D1 allocator.json served"
J=$(wait_served 600) || al_die "allocator never reported served:true (logs: $(alloc_logs 20 | tail -5))"
PEER1=$(al_field "$J" gifter_peer_id); MADDR=$(al_field "$J" gifter_multiaddr); TYPES=$(al_field "$J" auth_types)
# The host-published port (compose.yml maps ${HOST_PORT:-9000}:9000).
PORT="${HOST_PORT:-9000}"
REF=$(al_field "$J" registry_id | cut -d: -f2)
KC_WANT=1; [ "$(env_get KEYCARD_TRUSTED_CAS | tr 'A-Z' 'a-z')" = none ] && KC_WANT=0
ok=0; [ -n "$PEER1" ] && contains "$TYPES" eth-allowlist && ok=1
[ "$KC_WANT" = 0 ] || contains "$TYPES" keycard-attestation || ok=0
[ "$(env_get LOGOS_ALLOWLIST)" = 0 ] || contains "$TYPES" logos-allowlist || ok=0
[ "$(env_get LEZ_ALLOWLIST)" = 0 ] || contains "$TYPES" lez-allowlist || ok=0
check "$ok" D1 "peer $PEER1 @ $MADDR, auth_types $TYPES, registry ref $REF, host port $PORT"
al_say "==== D2 port reachable from the host; modules loaded in the container"
# No peerInfo here: it is unreliable once the gifter has mounted (see
# lib-ctl.sh al_port_open); the PeerId is asserted through allocator.json.
reach=0; python3 -I -c "import socket;socket.create_connection(('127.0.0.1',$PORT),timeout=5).close()" 2>/dev/null && reach=1
ST=$($COMPOSE exec -T allocator logosctl status 2>&1)
ok=0; [ "$reach" = 1 ] && contains "$ST" '"name":"rln_gifter_module","status":"loaded"' && contains "$ST" '"name":"libp2p_module","status":"loaded"' && ok=1
check "$ok" D2 "host port $PORT open=$reach, gifter+libp2p loaded=$(contains "$ST" '"name":"rln_gifter_module","status":"loaded"' && echo yes || echo no)"

# ---------------------------------------------------------------- D3 restart
al_say "==== D3 compose restart keeps the PeerId and re-serves"
STAMP=$(al_field "$J" updated_at)
$COMPOSE restart allocator >/dev/null 2>&1 || al_die "compose restart failed"
J=$(wait_served 600 "$STAMP") || al_die "not served after restart"
PEER2=$(al_field "$J" gifter_peer_id)
check "$([ "$PEER2" = "$PEER1" ] && echo 1 || echo 0)" D3 "peer after restart $PEER2"

# ---------------------------------------------------------------- D4 daemon death
al_say "==== D4 daemon killed inside the container -> container restarts and re-serves"
STAMP=$(al_field "$J" updated_at)
$COMPOSE exec -T allocator logosctl daemon stop >/dev/null 2>&1 || true
if J=$(wait_served 600 "$STAMP"); then
    PEER3=$(al_field "$J" gifter_peer_id)
    check "$([ "$PEER3" = "$PEER1" ] && echo 1 || echo 0)" D4 "re-served after daemon death, peer $PEER3"
else
    check 0 D4 "no re-serve after daemon death: $(alloc_logs 10 | tail -3)"
fi

# ---------------------------------------------------------------- client
al_say "==== client daemon (host, nix logoscore + -dev bundles)"
al_install_lgx "$LIBP2P_LGX" "$CLIENT/modules"
al_install_lgx "$GIFTER_LGX" "$CLIENT/modules"
al_install_lgx "$ETH_SIGN_LGX" "$CLIENT/modules"
al_daemon_start "$CLIENT"
al_load "$CLIENT" libp2p_module
al_load "$CLIENT" rln_gifter_module
al_load "$CLIENT" eth_sign_module
al_libp2p_up "$CLIENT" "/ip4/127.0.0.1/tcp/${CLIENT_PORT:-0}" >/dev/null
ADDR=$(al_field "$(al_call "$CLIENT" eth_sign_module address | al_res)" address)
[ -n "$ADDR" ] || al_die "no eth_sign_module address"
al_say "client eth address $ADDR"
# The container dials nothing; the client dials the host-published port.
DIAL="/ip4/127.0.0.1/tcp/$PORT"

# ---------------------------------------------------------------- D5 allowlist
al_say "==== D5 allowlist edit re-serves without a restart"
# The client's address may already be listed from an earlier run; the stamp
# comment guarantees the file changes, which is what the loop watches.
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
grep -q "$ADDR" "$HERE/config/allowlist.txt" 2>/dev/null || { printf '%s\n' "$ADDR" >> "$HERE/config/allowlist.txt"; ADDED=1; }
printf '# verify-local %s\n' "$SINCE" >> "$HERE/config/allowlist.txt"
if wait_log "re-serving" 120 "$SINCE"; then
    LISTED=$(alloc_logs 40 | grep "serve: " | tail -1)
    check "$(contains "$LISTED" "$ADDR" && echo 1 || echo 0)" D5 "re-served; allowlist now carries $ADDR"
else
    check 0 D5 "no re-serve within 120 s"
fi

req_json() { # <idc> <auth_type> <provider> [args_json]
    IDC="$1" AT="$2" PROV="$3" ARGS="${4:-}" PEER="$PEER1" ADDRM="$DIAL" python3 -I -c '
import json, os
o = {"gifterPeerId": os.environ["PEER"], "gifterMultiaddr": os.environ["ADDRM"],
     "identityCommitment": os.environ["IDC"], "rate": 100,
     "authType": os.environ["AT"], "authProvider": os.environ["PROV"]}
if os.environ["ARGS"]:
    o["authArgs"] = json.loads(os.environ["ARGS"])
print(json.dumps(o, separators=(",", ":")))
'
}
rand_commitment() { printf '%s0a' "$(openssl rand -hex 31)"; }

# ---------------------------------------------------------------- D6 eth request
al_say "==== D6 eth-allowlist request -> accepted by the verifier -> registry grants or refuses insufficient_balance"
if ! may_spend; then
    skip D6 "registry ref is $REF, not local: a grant spends the payer (ALLOW_SPEND=1 to run)"
else
    IDC=$(rand_commitment)
    NUL0=$(nul_count)
    R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist eth_sign_module)" d6) || R=""
    NUL1=$(nul_count)
    ok=0; what="unexpected reply"
    if contains "$R" "leaf_index"; then
        what="GRANT"; [ "$NUL1" = $((NUL0 + 1)) ] && ok=1
    elif contains "$R" "credential already used"; then
        what="credential already used"; [ "$NUL1" = "$NUL0" ] && ok=1
    elif contains "$R" "insufficient_balance"; then
        what="insufficient_balance (payer unfunded)"; [ "$NUL1" = "$NUL0" ] && ok=1
    fi
    check "$ok" D6 "$what — reply: ${R:-<no reply>} (nullifiers $NUL0 -> $NUL1)"
fi

# ---------------------------------------------------------------- D7 pow-claim request
al_say "==== D7 the client routes auth_type verbatim (client-side refusal; the allocator's pow verifier is not exercised here)"
if contains "$TYPES" pow-claim; then
    IDC=$(rand_commitment)
    R=$(al_request "$CLIENT" "$(req_json "$IDC" pow-claim eth_sign_module '{"node_url":"http://127.0.0.1:1","audience":"","rate_max":100}')" d7) || R=""
    # eth_sign_module has no pow-claim producer: the request fails client-side
    # naming the vector, which still proves the client routes auth_type
    # verbatim. A real producer refusal would come from the allocator's
    # verifier instead.
    check "$(contains "$R" "pow-claim" && echo 1 || echo 0)" D7 "reply: ${R:-<no reply>}"
else
    skip D7 "pow-claim not served (POW_NODE_URL unset)"
fi

# ---------------------------------------------------------------- D8 keycard (synthetic)
# The client CONTAINER (client-compose.yml, same image) sends a minted
# attestation as a raw authPayload; it dials the host-published port through
# the host gateway's IPv4 (nim-libp2p's resolver does not read /etc/hosts, so
# /dns4/host.docker.internal does not resolve inside the container). The test
# CA's private key stays in runs/ (git-ignored).
CLIENT_COMPOSE="docker compose -f $HERE/client-compose.yml"
MINT="$REPO/tools/mint_attest.py"
HOST_V4=$(docker run --rm --entrypoint getent --add-host host.docker.internal:host-gateway \
    rln-allocator:local ahostsv4 host.docker.internal 2>/dev/null | awk 'NR==1{print $1}')
kc_client() { # <tag> <payload hex> <commitment>  -> the client's reply + RESULT lines
    $CLIENT_COMPOSE run --rm -T \
        -e ALLOCATOR_PEER_ID="$PEER1" \
        -e ALLOCATOR_MULTIADDR="/ip4/${HOST_V4:-192.168.65.254}/tcp/$PORT" \
        -e CLIENT_AUTH_TYPE=keycard-attestation \
        -e CLIENT_AUTH_PAYLOAD="$2" \
        -e CLIENT_IDENTITY_COMMITMENT="$3" \
        -e CLIENT_KEEP=0 \
        client > "$WORK/$1.log" 2>&1
    grep -e "reply after" -e "RESULT:" "$WORK/$1.log" | tail -2 | tr '\n' ' '
}
al_say "==== D8 keycard-attestation (synthetic cards, client container)"
CA_FILE="$HERE/runs/keycard-test-ca.hex"
if ! may_spend; then
    skip D8 "registry ref is $REF, not local: a test CA is never trusted on a shared zone (ALLOW_SPEND=1 to run)"
else
    [ -s "$CA_FILE" ] || (umask 077; openssl rand -hex 32 > "$CA_FILE")
    chmod 600 "$CA_FILE"
    CA_PUB=$(python3 -I "$MINT" pub "$(cat "$CA_FILE")")
    TRUSTED=$($COMPOSE exec -T allocator cat /var/lib/allocator/serve.json 2>/dev/null | CA="$CA_PUB" python3 -I -c '
import json, os, sys
try:
    cas = json.load(sys.stdin)["authVerifiers"]["keycard-attestation"]["config"]["trusted_cas"]
except Exception:
    cas = []
print(1 if os.environ["CA"] in cas else 0)')
    if [ "$TRUSTED" != 1 ]; then
        CUR=$(env_get KEYCARD_TRUSTED_CAS)
        [ -n "$CUR" ] && [ "$CUR" != none ] || CUR=029ab99ee1e7a71bdf45b3f9c58c99866ff1294d2c1e304e228a86e10c3343501c
        al_say "D8 SKIP: append ,$CA_PUB to KEYCARD_TRUSTED_CAS in allocator.env and docker compose up -d"
        al_say "         (i.e. KEYCARD_TRUSTED_CAS=$CUR,$CA_PUB — remove it before the allocator is publicly reachable)"
        skip D8 "test CA not trusted by the running allocator"
    else
        # D8a: a card under a CA nobody trusts.
        IDC=$(rand_commitment); NUL0=$(nul_count)
        M=$(python3 -I "$MINT" mint "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$IDC")
        L=$(kc_client d8a "$(al_field "$M" tlv)" "$IDC"); NUL1=$(nul_count)
        ok=0; contains "$L" "keycard verifier refused the attestation" && [ "$NUL1" = "$NUL0" ] && ok=1
        check "$ok" D8a "untrusted CA: ${L:-<no reply, see $WORK/d8a.log>} (nullifiers $NUL0 -> $NUL1)"

        # D8b: a fresh card under the trusted test CA.
        CARD=$(openssl rand -hex 32)
        IDC=$(rand_commitment); NUL0=$(nul_count)
        M=$(python3 -I "$MINT" mint "$(cat "$CA_FILE")" "$CARD" "$IDC")
        KNUL="keycard-attestation:$(al_field "$M" nullifier)"
        L=$(kc_client d8b "$(al_field "$M" tlv)" "$IDC"); NUL1=$(nul_count)
        GRANTED=0; ok=0; what="unexpected reply"
        if contains "$L" "membership granted"; then
            what="GRANT"; GRANTED=1
            nul_lines | grep -qxF "$KNUL" && [ "$NUL1" = $((NUL0 + 1)) ] && ok=1
        elif contains "$L" "insufficient_balance"; then
            what="insufficient_balance (payer unfunded)"; [ "$NUL1" = "$NUL0" ] && ok=1
        fi
        check "$ok" D8b "$what — ${L:-<no reply, see $WORK/d8b.log>} ($KNUL; nullifiers $NUL0 -> $NUL1)"

        # D8c: the same card again, new commitment.
        if [ "$GRANTED" = 1 ]; then
            IDC=$(rand_commitment); NUL0=$(nul_count)
            M=$(python3 -I "$MINT" mint "$(cat "$CA_FILE")" "$CARD" "$IDC")
            L=$(kc_client d8c "$(al_field "$M" tlv)" "$IDC"); NUL1=$(nul_count)
            ok=0; contains "$L" "credential already used" && [ "$NUL1" = "$NUL0" ] && ok=1
            check "$ok" D8c "same card, new commitment: ${L:-<no reply, see $WORK/d8c.log>} (nullifiers $NUL0 -> $NUL1)"
        else
            skip D8c "D8b did not grant"
        fi
    fi
fi

# ---------------------------------------------------------------- D9/D10 logos + lez
# The client container, a producer module and a request; the log keeps the
# line the client prints for the operator (key / account id) and the reply.
ct_client() { # <tag> <auth_type> <provider> <args_json> -> reply + RESULT lines
    $CLIENT_COMPOSE run --rm -T \
        -e ALLOCATOR_PEER_ID="$PEER1" \
        -e ALLOCATOR_MULTIADDR="/ip4/${HOST_V4:-192.168.65.254}/tcp/$PORT" \
        -e CLIENT_AUTH_TYPE="$2" \
        -e CLIENT_AUTH_PROVIDER="$3" \
        -e CLIENT_AUTH_ARGS="$4" \
        -e CLIENT_AUTH_PAYLOAD= \
        -e CLIENT_IDENTITY_COMMITMENT= \
        -e CLIENT_KEEP=0 \
        client > "$WORK/$1.log" 2>&1
    grep -e "reply after" -e "RESULT:" "$WORK/$1.log" | tail -2 | tr '\n' ' '
}
log_field() { # <tag> <sed expr capturing group 1>  — first match in the client log
    sed -n "$2" "$WORK/$1.log" | head -1
}
append_allow() { # <logos|lez> <line>  — append, stamp, wait for the re-serve
    local f="$HERE/config/allowlist-$1.txt" since
    since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\n# verify-local %s\n' "$2" "$since" >> "$f"
    if [ "$1" = logos ]; then LOGOS_LINES="$LOGOS_LINES,$2"; else LEZ_LINES="$LEZ_LINES,$2"; fi
    wait_log "serve: " 120 "$since"
}
# One outcome: ok when it is a grant (nullifiers +1), insufficient_balance or
# already used (nullifiers unchanged). Sets GRANTED and what.
grant_or_refuse() { # <reply> <nul before> <nul after>
    GRANTED=0; ok=0; what="unexpected reply"
    if contains "$1" "membership granted"; then
        what="GRANT"; GRANTED=1; [ "$3" = $(($2 + 1)) ] && ok=1
    elif contains "$1" "insufficient_balance"; then
        what="insufficient_balance (payer unfunded)"; [ "$3" = "$2" ] && ok=1
    fi
}

al_say "==== D9 logos-allowlist (logos_sign_module via the follower node, client container)"
LOGOS_NODE_ARGS='{"node_url":"http://host.docker.internal:18080"}'
if ! contains "$TYPES" logos-allowlist; then
    skip D9 "logos-allowlist not served (LOGOS_ALLOWLIST=0)"
elif ! may_spend; then
    skip D9 "registry ref is $REF, not local: a grant spends the payer (ALLOW_SPEND=1 to run)"
else
    NUL0=$(nul_count)
    L=$(ct_client d9a logos-allowlist logos_sign_module "$LOGOS_NODE_ARGS"); NUL1=$(nul_count)
    LK=$(log_field d9a 's/.*logos-allowlist public key (give this to the allocator operator): \([0-9a-f]\{64\}\) .*/\1/p')
    if [ -z "$LK" ]; then
        skip D9 "no key from logos_sign_module (is the follower node up on 18080 with one PoWClaim key?): $(grep -e 'public_key' -e 'ERROR' "$WORK/d9a.log" | tail -1)"
    else
        ok=0; contains "$L" "not allowlisted" && [ "$NUL1" = "$NUL0" ] && ok=1
        # A key left listed by an earlier run is a legitimate state, not a failure.
        grep -qix "$LK" "$HERE/config/allowlist-logos.txt" 2>/dev/null && ok=1
        check "$ok" D9a "unlisted K ${LK}: ${L:-<no reply, see $WORK/d9a.log>}"
        append_allow logos "$LK" || al_say "D9: no re-serve seen within 120 s"
        NUL0=$(nul_count)
        L=$(ct_client d9b logos-allowlist logos_sign_module "$LOGOS_NODE_ARGS"); NUL1=$(nul_count)
        grant_or_refuse "$L" "$NUL0" "$NUL1"
        contains "$L" "credential already used" && { what="credential already used (K spent by an earlier run)"; [ "$NUL1" = "$NUL0" ] && ok=1; }
        check "$ok" D9b "$what — ${L:-<no reply, see $WORK/d9b.log>} (nullifiers $NUL0 -> $NUL1)"
        if [ "$GRANTED" = 1 ]; then
            NUL0=$(nul_count)
            L=$(ct_client d9c logos-allowlist logos_sign_module "$LOGOS_NODE_ARGS"); NUL1=$(nul_count)
            ok=0; contains "$L" "credential already used" && [ "$NUL1" = "$NUL0" ] && ok=1
            check "$ok" D9c "same K, new commitment: ${L:-<no reply, see $WORK/d9c.log>} (nullifiers $NUL0 -> $NUL1)"
        else
            skip D9c "D9b did not grant"
        fi
    fi
fi

al_say "==== D10 lez-allowlist (lez_sign_module with a fresh key, client container)"
if ! contains "$TYPES" lez-allowlist; then
    skip D10 "lez-allowlist not served (LEZ_ALLOWLIST=0)"
elif ! may_spend; then
    skip D10 "registry ref is $REF, not local: a grant spends the payer (ALLOW_SPEND=1 to run)"
else
    KEY1="$WORK/lez-key-1.hex"; KEY2="$WORK/lez-key-2.hex"
    (umask 077; openssl rand -hex 32 > "$KEY1"; openssl rand -hex 32 > "$KEY2")
    ARGS1="{\"private_key\":\"0x$(cat "$KEY1")\"}"; ARGS2="{\"private_key\":\"0x$(cat "$KEY2")\"}"
    ID_RE='s/.*lez-allowlist account id (give this to the allocator operator): \([1-9A-HJ-NP-Za-km-z]*\) (hex \([0-9a-f]\{64\}\)).*/'
    NUL0=$(nul_count)
    L=$(ct_client d10a lez-allowlist lez_sign_module "$ARGS1"); NUL1=$(nul_count)
    B58=$(log_field d10a "${ID_RE}\\1/p")
    if [ -z "$B58" ]; then
        check 0 D10a "no account id printed by the client: $(grep -e 'lez_sign' -e 'ERROR' "$WORK/d10a.log" | tail -1)"
    else
        ok=0; contains "$L" "not allowlisted" && [ "$NUL1" = "$NUL0" ] && ok=1
        check "$ok" D10a "unlisted $B58: ${L:-<no reply, see $WORK/d10a.log>}"
        append_allow lez "$B58" || al_say "D10: no re-serve seen within 120 s"
        NUL0=$(nul_count)
        L=$(ct_client d10b lez-allowlist lez_sign_module "$ARGS1"); NUL1=$(nul_count)
        grant_or_refuse "$L" "$NUL0" "$NUL1"
        check "$ok" D10b "listed (base58): $what — ${L:-<no reply, see $WORK/d10b.log>} (nullifiers $NUL0 -> $NUL1)"
        if [ "$GRANTED" = 1 ]; then
            NUL0=$(nul_count)
            L=$(ct_client d10c lez-allowlist lez_sign_module "$ARGS1"); NUL1=$(nul_count)
            ok=0; contains "$L" "credential already used" && [ "$NUL1" = "$NUL0" ] && ok=1
            check "$ok" D10c "same account, new commitment: ${L:-<no reply, see $WORK/d10c.log>} (nullifiers $NUL0 -> $NUL1)"
        else
            skip D10c "D10b did not grant"
        fi
        # A second key, allowlisted by the 64-hex form of its account id.
        L=$(ct_client d10d0 lez-allowlist lez_sign_module "$ARGS2")
        HEX2=$(log_field d10d0 "${ID_RE}\\2/p")
        if [ -z "$HEX2" ]; then
            check 0 D10d "no account id printed for the second key"
        else
            append_allow lez "$HEX2" || al_say "D10: no re-serve seen within 120 s"
            NUL0=$(nul_count)
            L=$(ct_client d10d lez-allowlist lez_sign_module "$ARGS2"); NUL1=$(nul_count)
            grant_or_refuse "$L" "$NUL0" "$NUL1"
            check "$ok" D10d "listed (64-hex $HEX2): $what — ${L:-<no reply, see $WORK/d10d.log>} (nullifiers $NUL0 -> $NUL1)"
        fi
    fi
fi

# ---------------------------------------------------------------- summary
al_say "checks: $RESULTS"
if [ "$FAILS" = 0 ]; then al_say "ALL PASS"; else al_die "$FAILS check(s) failed"; fi
