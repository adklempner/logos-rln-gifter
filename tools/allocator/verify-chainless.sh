#!/usr/bin/env bash
# tools/allocator/verify-chainless.sh — prove the operator-side allocator recipe
# without a chain: everything from docs/running-an-allocator.md §6 except the
# registration landing on a registry.
#
# Topology (two logoscore daemons on this host):
#   allocator  run-allocator.sh with a PERSISTED node key, liblogos_lez_rln_module
#              replaced by the PoC stub (register_member answers non-JSON ->
#              RegisterError::NotSubmitted), eth_auth_module as the verifier
#   client     libp2p_module + rln_gifter_module (client half), tcp/0
#
# Asserts:
#   A1 serve mounts with a real authVerifiers entry
#   A2 request without auth_type is refused: unsupported authentication_type
#   A3 garbage payload reaches the verifier and is REJECTED (not errored)
#   A4 a valid EIP-191 signature from a NON-allowlisted key is rejected by name
#   A5 a valid signature from the allowlisted key is ACCEPTED and reaches
#      register_member on the registry module (stub: NotSubmitted) — the full
#      wire path short of the chain; the nullifier is released (file stays empty)
#   A6 restart (down/up, same home): the PeerId is IDENTICAL
#   A7 after the restart the client, still holding the OLD peer id, is served
#   A8 `serve` refresh to an open gifter: an unauthenticated request now reaches
#      register_member
#   A9 the PRODUCER module: the client's eth_sign_module signs the commitment
#      during the request (authProvider, no cast) with its module-owned key;
#      the allocator, re-served with that key's `address` allowlisted, accepts
#      it and reaches register_member once
#   A10 a commitment that is not a canonical BN254 scalar (little-endian) is
#      refused by the REQUESTER before any dial — `invalid_commitment` — and the
#      registry module is never called (the gifter applies the same check on
#      arrival; lez module 5.1.0 refuses it a third time before signing)
#   A11 logos-allowlist: logos_sign_module signs through a real logos-blockchain
#      node (LOGOS_NODE_URL, e.g. http://127.0.0.1:8080; SKIPPED when unset or
#      the logos lgx are missing); an unlisted key is rejected by name, the
#      node's PoWClaim key allowlisted is accepted and reaches register_member
#   A12 lez-allowlist: lez_sign_module's own key; unlisted rejected by name,
#      listed (base58 form, then the hex form) accepted and reaches register_member
#
# Env: LOGOS_AUTH_LGX, LOGOS_SIGN_LGX, LEZ_AUTH_LGX, LEZ_SIGN_LGX (default: the
#      rust/<module>/result-lgx dev bundles), LOGOS_NODE_URL (A11),
#      LOGOSCORE, LIBP2P_LGX, GIFTER_LGX, STUB_LEZ_LGX, ETH_AUTH_LGX, ETH_SIGN_LGX, CAST
#      (foundry's cast, for personal_sign), GIFTER_PORT (61871), KEEP=1 leaves
#      both daemons up. Writes runs/<ts>/summary.json.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
. "$HERE/lib.sh"

POC="$REPO/tools/pow-claim-poc"
# The PoC's artifacts.env supplies only the libp2p and stub bundles; the gifter
# bundle is this repo's own result-lgx (a GC root — the PoC's store path is not).
if [ -f "$POC/runs/artifacts.env" ]; then
    _l="${LIBP2P_LGX:-}"; _s="${STUB_LEZ_LGX:-}"; _g="${GIFTER_LGX:-}"
    # shellcheck source=/dev/null
    . "$POC/runs/artifacts.env"
    LIBP2P_LGX="${_l:-$LIBP2P_LGX}"; STUB_LEZ_LGX="${_s:-$STUB_LEZ_LGX}"; GIFTER_LGX="$_g"
fi
# artifacts.env's stub path is a bare store path that nix GC can take away;
# prefer the PoC's result-lgx link (a GC root) when it exists.
if [ ! -e "${STUB_LEZ_LGX:-}" ]; then
    _stub=$(find "$POC/stub-lez-rln/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)
    [ -z "$_stub" ] || STUB_LEZ_LGX="$_stub"
fi
LOGOSCORE="${LOGOSCORE:-$POC/runs/logos/bin/logoscore}"
GIFTER_LGX="${GIFTER_LGX:-$(find "$REPO/rust/rln-gifter-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
ETH_AUTH_LGX="${ETH_AUTH_LGX:-$(find "$REPO/rust/eth-auth-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
ETH_SIGN_LGX="${ETH_SIGN_LGX:-$(find "$REPO/rust/eth-sign-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
LOGOS_AUTH_LGX="${LOGOS_AUTH_LGX:-$(find "$REPO/rust/logos-auth-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
LOGOS_SIGN_LGX="${LOGOS_SIGN_LGX:-$(find "$REPO/rust/logos-sign-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
LEZ_AUTH_LGX="${LEZ_AUTH_LGX:-$(find "$REPO/rust/lez-auth-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
LEZ_SIGN_LGX="${LEZ_SIGN_LGX:-$(find "$REPO/rust/lez-sign-module/result-lgx/" -maxdepth 1 -name "*.lgx" 2>/dev/null | head -1)}"
CAST="${CAST:-$HOME/.foundry/bin/cast}"
GIFTER_PORT="${GIFTER_PORT:-61871}"
export LOGOSCORE
for v in LOGOSCORE LIBP2P_LGX GIFTER_LGX STUB_LEZ_LGX ETH_AUTH_LGX ETH_SIGN_LGX; do
    eval "[ -e \"\${$v:-}\" ]" || al_die "$v missing: $(eval "printf '%s' \"\${$v:-<unset>}\"")"
done
[ -x "$CAST" ] || al_die "need foundry's cast at $CAST for EIP-191 signatures"
if lsof -nP -iTCP:"$GIFTER_PORT" -sTCP:LISTEN >/dev/null 2>&1; then al_die "TCP $GIFTER_PORT already in use"; fi

TS=$(date +%Y%m%d-%H%M%S)
WORK="$HERE/runs/$TS"
AHOME="$WORK/allocator-home"
CLIENT="$WORK/client"
mkdir -p "$AHOME" "$CLIENT/modules"
FAILS=0; RESULTS=""
check() { # <0/1 ok> <id> <message>
    if [ "$1" = 1 ]; then al_say "PASS $2 $3"; RESULTS="$RESULTS$2=pass "
    else al_say "FAIL $2 $3"; RESULTS="$RESULTS$2=FAIL "; FAILS=$((FAILS + 1)); fi
}
contains() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

# ---------------------------------------------------------------- keys
ALLOW_PK=0x4242424242424242424242424242424242424242424242424242424242424242
OTHER_PK=0x4343434343434343434343434343434343434343434343434343434343434343
ALLOW_ADDR=$("$CAST" wallet address --private-key "$ALLOW_PK" | tr 'A-F' 'a-f')
# personal_sign over the LOWERCASE HEX of the commitment (no 0x: cast must see a
# utf-8 string, not bytes); cast emits 0x||r||s||v with v in {27,28}.
sign_commitment() { "$CAST" wallet sign --private-key "$1" "$2" | sed 's/^0x//'; }
# A canonical BN254 scalar, little-endian: 31 random bytes + a small top byte.
# 32 random bytes exceed r about four times in five, and both the requester
# and the gifter refuse those since the 2026-10-14 pre-check (A10).
rand_commitment() { printf '%s0a' "$(openssl rand -hex 31)"; }

# ---------------------------------------------------------------- allocator up
export ALLOCATOR_HOME="$AHOME" LIBP2P_LGX GIFTER_LGX
EXTRA_LGX="$ETH_AUTH_LGX"; EXTRA_MODULES="eth_auth_module"
# The logos/lez verifiers ride along when their bundles exist (A11/A12).
HAVE_LOGOS=0; HAVE_LEZ=0
if [ -e "${LOGOS_AUTH_LGX:-}" ] && [ -e "${LOGOS_SIGN_LGX:-}" ]; then
    HAVE_LOGOS=1; EXTRA_LGX="$EXTRA_LGX $LOGOS_AUTH_LGX"; EXTRA_MODULES="$EXTRA_MODULES logos_auth_module"
fi
if [ -e "${LEZ_AUTH_LGX:-}" ] && [ -e "${LEZ_SIGN_LGX:-}" ]; then
    HAVE_LEZ=1; EXTRA_LGX="$EXTRA_LGX $LEZ_AUTH_LGX"; EXTRA_MODULES="$EXTRA_MODULES lez_auth_module"
fi
export LEZ_RLN_LGX="$STUB_LEZ_LGX" EXTRA_LGX EXTRA_MODULES
export LISTEN_ADDR="/ip4/127.0.0.1/tcp/$GIFTER_PORT" WALLET_WAIT_S=0 MAX_RATE_LIMIT=100
export REGISTRY_CONFIG="ChainlessConfig11111111111111111111111" PAYER="ChainlessPayer111111111111111111111111"
export AUTH_VERIFIERS="{\"eth-allowlist\":{\"module\":\"eth_auth_module\",\"config\":{\"allowlist\":[\"$ALLOW_ADDR\"]}}}"

teardown() {
    if [ "${KEEP:-0}" = 1 ]; then al_say "KEEP=1: daemons left up ($WORK)"; return; fi
    "$HERE/run-allocator.sh" down >/dev/null 2>&1 || true
    al_daemon_stop "$CLIENT" || true
    rm -rf "$CLIENT/modules"
}
trap teardown EXIT

al_say "==== allocator up (verifier: eth-allowlist, allowlisted $ALLOW_ADDR)"
"$HERE/run-allocator.sh" up > "$WORK/up1.json" || al_die "allocator up failed"
PEER1=$(al_field "$(cat "$AHOME/allocator.json")" gifter_peer_id)
GADDR=$(al_field "$(cat "$AHOME/allocator.json")" gifter_multiaddr)
check "$([ -n "$PEER1" ] && echo 1 || echo 0)" A1 "serve mounted with authVerifiers; peer $PEER1 @ $GADDR"
[ -s "$AHOME/node_key.hex" ] || al_die "no persisted node key"

# ---------------------------------------------------------------- client up
al_say "==== client daemon"
al_install_lgx "$LIBP2P_LGX" "$CLIENT/modules"
al_install_lgx "$GIFTER_LGX" "$CLIENT/modules"
al_install_lgx "$ETH_SIGN_LGX" "$CLIENT/modules"
# logoscore scans the modules dir at daemon start: the A11/A12 producers must
# be installed now, not when their check runs.
[ "${HAVE_LOGOS:-0}" = 1 ] && al_install_lgx "$LOGOS_SIGN_LGX" "$CLIENT/modules"
[ "${HAVE_LEZ:-0}" = 1 ] && al_install_lgx "$LEZ_SIGN_LGX" "$CLIENT/modules"
al_daemon_start "$CLIENT"
al_load "$CLIENT" libp2p_module
al_load "$CLIENT" rln_gifter_module
al_load "$CLIENT" eth_sign_module
CPEER=$(al_libp2p_up "$CLIENT" "/ip4/127.0.0.1/tcp/0")
al_say "client peer $CPEER"

req_json() { # <idc_hex> [auth_type] [payload_hex]
    IDC="$1" AT="${2:-}" AP="${3:-}" PEER="$PEER1" ADDR="$GADDR" python3 -I -c '
import json, os
o = {"gifterPeerId": os.environ["PEER"], "gifterMultiaddr": os.environ["ADDR"],
     "identityCommitment": os.environ["IDC"], "rate": 100}
if os.environ["AT"]:
    o["authType"] = os.environ["AT"]; o["authPayload"] = os.environ["AP"]
print(json.dumps(o, separators=(",", ":")))
'
}
# The producer form: no payload — rln_gifter_module asks <provider>.produce_auth
# for it during the request, bound to this commitment.
req_provider_json() { # <idc_hex> <auth_type> <provider_module> [args_json]
    IDC="$1" AT="$2" PROV="$3" ARGS="${4:-}" PEER="$PEER1" ADDR="$GADDR" python3 -I -c '
import json, os
o = {"gifterPeerId": os.environ["PEER"], "gifterMultiaddr": os.environ["ADDR"],
     "identityCommitment": os.environ["IDC"], "rate": 100,
     "authType": os.environ["AT"], "authProvider": os.environ["PROV"]}
if os.environ["ARGS"]:
    o["authArgs"] = json.loads(os.environ["ARGS"])
print(json.dumps(o, separators=(",", ":")))
'
}
# grep -c prints 0 on no match (and exits 1): never append a second 0.
stub_calls() { local n; n=$(grep -ac 'liblogos_lez_rln_module STUB: register_member' "$AHOME/run/daemon.log" 2>/dev/null); printf '%s' "${n:-0}"; }

# ---------------------------------------------------------------- A2..A5
al_say "==== A2 unauthenticated request against an authenticated gifter"
IDC=$(rand_commitment)
R=$(al_request "$CLIENT" "$(req_json "$IDC")" a2) || R=""
check "$(contains "$R" "unsupported authentication_type" && echo 1 || echo 0)" A2 "refused: ${R:-<no reply>}"

al_say "==== A3 garbage payload reaches the verifier"
IDC=$(rand_commitment)
R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist aaaaaaaaaaaaaaaaaaaa)" a3) || R=""
check "$(contains "$R" "signature verification failed" && echo 1 || echo 0)" A3 "verifier rejected: ${R:-<no reply>}"

al_say "==== A4 valid signature, NON-allowlisted signer"
IDC=$(rand_commitment)
SIG=$(sign_commitment "$OTHER_PK" "$IDC")
R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist "$SIG")" a4) || R=""
check "$(contains "$R" "not allowlisted" && echo 1 || echo 0)" A4 "verifier rejected: ${R:-<no reply>}"

al_say "==== A5 valid signature, allowlisted signer -> register_member (stub)"
N0=$(stub_calls)
IDC=$(rand_commitment)
SIG=$(sign_commitment "$ALLOW_PK" "$IDC")
R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist "$SIG")" a5) || R=""
N1=$(stub_calls)
ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
check "$ok" A5 "accepted by verifier, registry called once ($N0->$N1), stub refused: ${R:-<no reply>}"
check "$([ ! -s "$AHOME/consumed_nullifiers.txt" ] && echo 1 || echo 0)" A5b "nullifier released on NotSubmitted (file empty)"

# ---------------------------------------------------------------- A6/A7 restart
al_say "==== A6 restart the allocator daemon with the same home"
"$HERE/run-allocator.sh" down || al_die "down failed"
sleep 1
"$HERE/run-allocator.sh" up > "$WORK/up2.json" || al_die "allocator re-up failed"
PEER2=$(al_field "$(cat "$AHOME/allocator.json")" gifter_peer_id)
check "$([ "$PEER1" = "$PEER2" ] && echo 1 || echo 0)" A6 "peer id after restart: $PEER2 (before: $PEER1)"

al_say "==== A7 client still holds the old peer id; request after restart"
N0=$(stub_calls)   # fresh log after restart? the log is appended, so count deltas
IDC=$(rand_commitment)
SIG=$(sign_commitment "$ALLOW_PK" "$IDC")
R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist "$SIG")" a7) || R=""
N1=$(stub_calls)
ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
check "$ok" A7 "served after restart: ${R:-<no reply>}"

# ---------------------------------------------------------------- A8 serve refresh -> open
al_say "==== A8 serve refresh: drop the verifier set (open gifter)"
unset AUTH_VERIFIERS
"$HERE/run-allocator.sh" serve > "$WORK/serve-open.json" || al_die "serve refresh failed"
N0=$(stub_calls)
IDC=$(rand_commitment)
R=$(al_request "$CLIENT" "$(req_json "$IDC")" a8) || R=""
N1=$(stub_calls)
ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
check "$ok" A8 "open request reached register_member: ${R:-<no reply>}"

# ---------------------------------------------------------------- A9 producer module
al_say "==== A9 eth_sign_module (producer) signs during the request; allocator re-served with its address"
SIGN_ADDR=$(al_field "$(al_call "$CLIENT" eth_sign_module address | al_res)" address) || SIGN_ADDR=""
ok=0; case "$SIGN_ADDR" in 0x[0-9a-f]*) [ "${#SIGN_ADDR}" = 42 ] && ok=1 ;; esac
check "$ok" A9a "eth_sign_module.address: ${SIGN_ADDR:-<none>}"
export AUTH_VERIFIERS="{\"eth-allowlist\":{\"module\":\"eth_auth_module\",\"config\":{\"allowlist\":[\"$SIGN_ADDR\"]}}}"
"$HERE/run-allocator.sh" serve > "$WORK/serve-sign.json" || al_die "serve refresh (producer allowlist) failed"
N0=$(stub_calls)
IDC=$(rand_commitment)
R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" eth-allowlist eth_sign_module)" a9) || R=""
N1=$(stub_calls)
ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
check "$ok" A9 "producer-signed request accepted, registry called once ($N0->$N1): ${R:-<no reply>}"
# The same producer against a cast-signed key that is NOT the module's: the
# verifier names the module's address, proving the module key did the signing.
IDC=$(rand_commitment)
SIG=$(sign_commitment "$OTHER_PK" "$IDC")
R=$(al_request "$CLIENT" "$(req_json "$IDC" eth-allowlist "$SIG")" a9b) || R=""
check "$(contains "$R" "not allowlisted" && echo 1 || echo 0)" A9b "a foreign key is still refused under the producer allowlist: ${R:-<no reply>}"

# ---------------------------------------------------------------- A10 non-canonical commitment
al_say "==== A10 non-BN254 commitment refused client-side, registry never called"
N0=$(stub_calls)
IDC=$(printf 'ff%.0s' $(seq 1 32))
R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" eth-allowlist eth_sign_module)" a10) || R=""
N1=$(stub_calls)
ok=0; contains "$R" "invalid_commitment" && [ "$N1" = "$N0" ] && ok=1
check "$ok" A10 "refused before any io ($N0->$N1 registry calls): ${R:-<no reply>}"
IDC=$(printf '00%.0s' $(seq 1 32))
R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" eth-allowlist eth_sign_module)" a10b) || R=""
check "$(contains "$R" "invalid_commitment: zero" && echo 1 || echo 0)" A10b "zero commitment refused: ${R:-<no reply>}"

# ---------------------------------------------------------------- A11 logos-allowlist
al_say "==== A11 logos_sign_module (producer) through a logos-blockchain node"
SIGN_K=""
if [ "$HAVE_LOGOS" != 1 ]; then
    al_say "SKIP A11: logos-auth/logos-sign bundles not found (LOGOS_AUTH_LGX, LOGOS_SIGN_LGX)"; RESULTS="${RESULTS}A11=skip "
elif [ -z "${LOGOS_NODE_URL:-}" ]; then
    al_say "SKIP A11: set LOGOS_NODE_URL (a logos-blockchain node with one PoWClaim key, e.g. http://127.0.0.1:8080)"; RESULTS="${RESULTS}A11=skip "
else
    al_load "$CLIENT" logos_sign_module
    NODE_ARGS="{\"node_url\":\"$LOGOS_NODE_URL\"}"
    SIGN_K=$(al_field "$(al_call "$CLIENT" logos_sign_module public_key "$NODE_ARGS" | al_res)" public_key) || SIGN_K=""
    ok=0; [ "${#SIGN_K}" = 64 ] && ok=1
    check "$ok" A11a "logos_sign_module.public_key from $LOGOS_NODE_URL: ${SIGN_K:-<none>}"
    if [ "$ok" = 1 ]; then
        OTHER_K=$(openssl rand -hex 32)
        export AUTH_VERIFIERS="{\"logos-allowlist\":{\"module\":\"logos_auth_module\",\"config\":{\"allowlist\":[\"$OTHER_K\"]}}}"
        "$HERE/run-allocator.sh" serve > "$WORK/serve-logos-other.json" || al_die "serve refresh (logos, unlisted) failed"
        IDC=$(rand_commitment)
        R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" logos-allowlist logos_sign_module "$NODE_ARGS")" a11b) || R=""
        check "$(contains "$R" "not allowlisted" && echo 1 || echo 0)" A11b "node key not on the list is refused by name: ${R:-<no reply>}"
        export AUTH_VERIFIERS="{\"logos-allowlist\":{\"module\":\"logos_auth_module\",\"config\":{\"allowlist\":[\"$SIGN_K\"]}}}"
        "$HERE/run-allocator.sh" serve > "$WORK/serve-logos.json" || al_die "serve refresh (logos allowlist) failed"
        N0=$(stub_calls)
        IDC=$(rand_commitment)
        R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" logos-allowlist logos_sign_module "$NODE_ARGS")" a11) || R=""
        N1=$(stub_calls)
        ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
        check "$ok" A11 "node-signed request accepted, registry called once ($N0->$N1): ${R:-<no reply>}"
    fi
fi

# ---------------------------------------------------------------- A12 lez-allowlist
al_say "==== A12 lez_sign_module (producer): module-owned account key"
LEZ_B58=""
if [ "$HAVE_LEZ" != 1 ]; then
    al_say "SKIP A12: lez-auth/lez-sign bundles not found (LEZ_AUTH_LGX, LEZ_SIGN_LGX)"; RESULTS="${RESULTS}A12=skip "
else
    al_load "$CLIENT" lez_sign_module
    LEZ_RES=$(al_call "$CLIENT" lez_sign_module account_id | al_res) || LEZ_RES=""
    LEZ_HEX=$(al_field "$LEZ_RES" account_id); LEZ_B58=$(al_field "$LEZ_RES" account_id_base58)
    ok=0; [ "${#LEZ_HEX}" = 64 ] && [ -n "$LEZ_B58" ] && ok=1
    check "$ok" A12a "lez_sign_module.account_id: hex ${LEZ_HEX:-<none>} base58 ${LEZ_B58:-<none>}"
    if [ "$ok" = 1 ]; then
        OTHER_ID=$(openssl rand -hex 32)
        export AUTH_VERIFIERS="{\"lez-allowlist\":{\"module\":\"lez_auth_module\",\"config\":{\"allowlist\":[\"$OTHER_ID\"]}}}"
        "$HERE/run-allocator.sh" serve > "$WORK/serve-lez-other.json" || al_die "serve refresh (lez, unlisted) failed"
        IDC=$(rand_commitment)
        R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" lez-allowlist lez_sign_module)" a12b) || R=""
        check "$(contains "$R" "not allowlisted" && echo 1 || echo 0)" A12b "module account not on the list is refused by name: ${R:-<no reply>}"
        # Listed as base58, then (fresh commitment, fresh nullifier release on
        # NotSubmitted) as the 64-hex form of the same account.
        export AUTH_VERIFIERS="{\"lez-allowlist\":{\"module\":\"lez_auth_module\",\"config\":{\"allowlist\":[\"$LEZ_B58\"]}}}"
        "$HERE/run-allocator.sh" serve > "$WORK/serve-lez.json" || al_die "serve refresh (lez allowlist) failed"
        N0=$(stub_calls)
        IDC=$(rand_commitment)
        R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" lez-allowlist lez_sign_module)" a12c) || R=""
        N1=$(stub_calls)
        ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
        check "$ok" A12c "listed by base58: accepted, registry called once ($N0->$N1): ${R:-<no reply>}"
        export AUTH_VERIFIERS="{\"lez-allowlist\":{\"module\":\"lez_auth_module\",\"config\":{\"allowlist\":[\"$LEZ_HEX\"]}}}"
        "$HERE/run-allocator.sh" serve > "$WORK/serve-lez-hex.json" || al_die "serve refresh (lez hex allowlist) failed"
        N0=$(stub_calls)
        IDC=$(rand_commitment)
        R=$(al_request "$CLIENT" "$(req_provider_json "$IDC" lez-allowlist lez_sign_module)" a12d) || R=""
        N1=$(stub_calls)
        ok=0; contains "$R" "register_member" && [ "$((N1 - N0))" = 1 ] && ok=1
        check "$ok" A12d "listed by hex: accepted, registry called once ($N0->$N1): ${R:-<no reply>}"
    fi
fi

# ---------------------------------------------------------------- summary
RES="$RESULTS" FAILS="$FAILS" P1="$PEER1" P2="$PEER2" GADDR="$GADDR" ADDR="$ALLOW_ADDR" \
LL="$LIBP2P_LGX" GL="$GIFTER_LGX" SL="$STUB_LEZ_LGX" EL="$ETH_AUTH_LGX" ESL="$ETH_SIGN_LGX" SA="${SIGN_ADDR:-}" W="$WORK" \
python3 -I - "$WORK/summary.json" <<'PY'
import json, os, sys, glob
e = os.environ
reqs = {}
for f in sorted(glob.glob(e["W"] + "/client/requests/*.res.json")):
    tag = os.path.basename(f)[:-9]
    try: reqs[tag] = json.load(open(f))
    except Exception: reqs[tag] = open(f).read().strip()
    try: reqs[tag + "_latency_s"] = int(open(f[:-9] + ".latency").read())
    except Exception: pass
out = {
  "checks": dict(kv.split("=") for kv in e["RES"].split()),
  "failures": int(e["FAILS"]),
  "peer_id_before_restart": e["P1"], "peer_id_after_restart": e["P2"],
  "gifter_multiaddr": e["GADDR"], "allowlisted_address": e["ADDR"],
  "eth_sign_module_address": e["SA"],
  "requests": reqs,
  "bundles": {"libp2p": e["LL"], "gifter": e["GL"], "stub_lez_rln": e["SL"], "eth_auth": e["EL"], "eth_sign": e["ESL"]},
}
json.dump(out, open(sys.argv[1], "w"), indent=2)
print(json.dumps(out["checks"], indent=1))
PY
al_say "summary: $WORK/summary.json"
if [ "$FAILS" = 0 ]; then al_say "ALL PASS"; else al_die "$FAILS check(s) failed"; fi
