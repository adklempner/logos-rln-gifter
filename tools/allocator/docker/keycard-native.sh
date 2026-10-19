#!/usr/bin/env bash
# keycard-native.sh — a REAL Status Keycard against the allocator, natively.
#
# The client container cannot reach a PC/SC reader, so this runs a host
# logoscore client (nix build + darwin-arm64-dev / linux-*-dev bundles, same
# harness as verify-local.sh) with keycard_capture_module, waits for a card in
# the reader, sends one keycard-attestation request to the allocator named by
# ALLOCATOR_PEER_ID / ALLOCATOR_MULTIADDR (defaults: the local container's
# allocator.json peer id, dialled at /ip4/127.0.0.1/tcp/${HOST_PORT:-9000}),
# then, if the first was granted or already used, a second request with the
# same card (expected: `credential already used`). Exit 1 on any FAIL.
# Env: KEEP=1 leaves the client daemon up,
# CARD_WAIT_S (default 180), LOGOSCORE / LIBP2P_LGX / GIFTER_LGX / KEYCARD_LGX
# override the artifact resolution of verify-local.sh.
set -u
set -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AL="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$AL/../.." && pwd)"
. "$AL/lib.sh"

POC="$REPO/tools/pow-claim-poc"
if [ -f "$POC/runs/artifacts.env" ]; then
    _l="${LIBP2P_LGX:-}"; _g="${GIFTER_LGX:-}"
    # shellcheck source=/dev/null
    . "$POC/runs/artifacts.env"
    LIBP2P_LGX="${_l:-$LIBP2P_LGX}"; GIFTER_LGX="$_g"
fi
LOGOSCORE="${LOGOSCORE:-$POC/runs/logos/bin/logoscore}"
GIFTER_LGX="${GIFTER_LGX:-$(find "$REPO/rust/rln-gifter-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
KEYCARD_LGX="${KEYCARD_LGX:-$(find "$REPO/rust/keycard-capture-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
export LOGOSCORE
for v in LOGOSCORE LIBP2P_LGX GIFTER_LGX KEYCARD_LGX; do
    eval "[ -e \"\${$v:-}\" ]" || al_die "$v missing: $(eval "printf '%s' \"\${$v:-<unset>}\"")"
done

if [ -z "${ALLOCATOR_PEER_ID:-}" ] || [ -z "${ALLOCATOR_MULTIADDR:-}" ]; then
    J=$(docker compose -f "$HERE/compose.yml" exec -T allocator cat /var/lib/allocator/allocator.json 2>/dev/null) \
        || al_die "set ALLOCATOR_PEER_ID and ALLOCATOR_MULTIADDR (no local allocator container to read them from)"
    ALLOCATOR_PEER_ID="${ALLOCATOR_PEER_ID:-$(al_field "$J" gifter_peer_id)}"
    # The local container is dialled on its host-published port (compose.yml
    # maps ${HOST_PORT:-9000}:9000), not the advertised gifter_multiaddr.
    ALLOCATOR_MULTIADDR="${ALLOCATOR_MULTIADDR:-/ip4/127.0.0.1/tcp/${HOST_PORT:-9000}}"
fi
al_say "allocator $ALLOCATOR_PEER_ID @ $ALLOCATOR_MULTIADDR"

WORK="$HERE/runs/$(date +%Y%m%d-%H%M%S)-keycard"
CLIENT="$WORK/client"
mkdir -p "$CLIENT/modules"
cleanup() { [ "${KEEP:-0}" = 1 ] || al_daemon_stop "$CLIENT" || true; }
trap cleanup EXIT

al_install_lgx "$LIBP2P_LGX" "$CLIENT/modules"
al_install_lgx "$GIFTER_LGX" "$CLIENT/modules"
al_install_lgx "$KEYCARD_LGX" "$CLIENT/modules"
al_daemon_start "$CLIENT"
al_load "$CLIENT" libp2p_module
al_load "$CLIENT" rln_gifter_module
al_load "$CLIENT" keycard_capture_module
al_libp2p_up "$CLIENT" "/ip4/127.0.0.1/tcp/0" >/dev/null

# --- wait for a card
t0=$(date +%s)
while :; do
    st=$(al_call "$CLIENT" keycard_capture_module card_status | al_res)
    case "$st" in *'"present":true'*) al_say "card present: $st"; break ;; esac
    el=$(( $(date +%s) - t0 ))
    [ "$el" -lt "${CARD_WAIT_S:-180}" ] || al_die "no card after ${el}s (last card_status: ${st:-<none>})"
    [ $((el % 10)) -lt 3 ] && al_say "waiting for a card in the reader ($st)"
    sleep 3
done

req_json() { # <commitment>
    IDC="$1" PEER="$ALLOCATOR_PEER_ID" ADDRM="$ALLOCATOR_MULTIADDR" python3 -I -c '
import json, os
print(json.dumps({"gifterPeerId": os.environ["PEER"], "gifterMultiaddr": os.environ["ADDRM"],
                  "identityCommitment": os.environ["IDC"], "rate": 100,
                  "authType": "keycard-attestation", "authProvider": "keycard_capture_module"},
                 separators=(",", ":")))'
}
rand_commitment() { printf '%s0a' "$(openssl rand -hex 31)"; }

al_say "==== K1 keycard-attestation request with the real card"
FAILS=0; K1OK=0
R=$(al_request "$CLIENT" "$(req_json "$(rand_commitment)")" k1) || R=""
case "$R" in
    *'"auth_success":true'*|*leaf_index*) al_say "PASS K1 GRANT — $R"; K1OK=1 ;;
    *"credential already used"*)          al_say "PASS K1 this card already holds a membership — $R"; K1OK=1 ;;
    *insufficient_balance*)               al_say "PASS K1 attestation accepted, payer unfunded — $R" ;;
    *)                                    al_say "FAIL K1 — ${R:-<no reply>}"; FAILS=$((FAILS + 1)) ;;
esac
# K2 is meaningful only once the card's credential is consumed.
if [ "$K1OK" = 1 ]; then
    al_say "==== K2 same card, new commitment (expected: credential already used)"
    R2=$(al_request "$CLIENT" "$(req_json "$(rand_commitment)")" k2) || R2=""
    case "$R2" in
        *"credential already used"*) al_say "PASS K2 replay refused — $R2" ;;
        *)                           al_say "FAIL K2 — ${R2:-<no reply>}"; FAILS=$((FAILS + 1)) ;;
    esac
else
    al_say "SKIP K2 (K1 neither granted nor answered credential already used)"
fi
al_say "run dir: $WORK"
[ "$FAILS" = 0 ] || al_die "$FAILS check(s) failed"
