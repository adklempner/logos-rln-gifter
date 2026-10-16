#!/usr/bin/env bash
# tools/pow-claim-poc/gifter-smoke.sh — chainless two-daemon gifter smoke (no nodes).
#
#   B′ (gifter): libp2p_module [+ STUB_LEZ_LGX] + rln_gifter_module, libp2p on tcp/61871
#   A′ (client): libp2p_module + rln_gifter_module, libp2p on tcp/0
#
# Probe 1: serve with an authVerifier naming an unloaded module (does lp_client_create
# fail for absent modules?). Then an open serve, and one `request` from A′ → records the
# exact error string + latency (no LEZ module on B′ ⇒ register NotSubmitted).
# Writes runs/<ts>-smoke/smoke.json and copies it to runs/gifter-smoke.json.
#
# Env: STUB_LEZ_LGX — liblogos_lez_rln_module stub loaded on B′ before the gifter
#      (default: artifacts.env's; R2 contingency). NO_STUB=1 omits it — then the
#      request cannot finish inside the CLI's 20 s deadline (lazy client, 190 s wait).
#      GIFTER_PORT (default 61871).
#
# Measured CLI constraint: `logoscore call` has a fixed ~20 s transport deadline
# ({"code":"RPC_FAILED",…}, rc 4); the module keeps running but its reply is lost.
set -euo pipefail

POC_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$POC_DIR/lib/logoscore.sh"
. "$POC_DIR/lib/gifter.sh"
LOGOSCORE="${LOGOSCORE:-$POC_DIR/runs/logos/bin/logoscore}"
export LOGOSCORE
[ -x "$LOGOSCORE" ] || poc_die "no logoscore at $LOGOSCORE"
[ -f "$POC_DIR/runs/artifacts.env" ] || poc_die "run build-gifter-artifacts.sh first"
_STUB_OVERRIDE="${STUB_LEZ_LGX:-}"
. "$POC_DIR/runs/artifacts.env"
GIFTER_PORT="${GIFTER_PORT:-61871}"
STUB_LEZ_LGX="${_STUB_OVERRIDE:-${STUB_LEZ_LGX:-}}"
[ "${NO_STUB:-0}" = 1 ] && STUB_LEZ_LGX=""

if lsof -nP -iTCP:"$GIFTER_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    poc_die "TCP $GIFTER_PORT already in use"
fi

SMOKE="$POC_DIR/runs/$(date +%Y%m%d-%H%M%S)-smoke"
A="$SMOKE/a"; B="$SMOKE/b"
mkdir -p "$A/modules" "$B/modules"

teardown() {
    POC_DAEMON_PID="" daemon_stop "$A" || true
    POC_DAEMON_PID="" daemon_stop "$B" || true
    # module copies are ~25 MB per daemon; logs/requests stay
    rm -rf "$A/modules" "$B/modules"
}
trap teardown EXIT

for d in "$A" "$B"; do
    install_lgx "$LIBP2P_LGX" "$d/modules"
    install_lgx "$GIFTER_LGX" "$d/modules"
done
[ -z "$STUB_LEZ_LGX" ] || install_lgx "$STUB_LEZ_LGX" "$B/modules"

# ---------- B′ gifter daemon --------------------------------------------------
daemon_start "$B" "$B/modules"
POC_RUN_DIR="$B" lc_load libp2p_module
if [ -n "$STUB_LEZ_LGX" ]; then
    POC_RUN_DIR="$B" lc_load liblogos_lez_rln_module
fi
POC_RUN_DIR="$B" lc_load rln_gifter_module
GPEER=$(gf_libp2p_up "$B" "/ip4/127.0.0.1/tcp/$GIFTER_PORT")
poc_say "gifter peer $GPEER"

# ---------- A′ client daemon --------------------------------------------------
daemon_start "$A" "$A/modules"
POC_RUN_DIR="$A" lc_load libp2p_module
POC_RUN_DIR="$A" lc_load rln_gifter_module
APEER=$(gf_libp2p_up "$A" "/ip4/127.0.0.1/tcp/0")
poc_say "client peer $APEER"

CFG="PoCConfig1111111111111111111111111111"
WAL="PoCWallet1111111111111111111111111111"

# ---------- Probe 1: verifier module not loaded ---------------------------------
PROBE1=$(gf_serve_raw "$B" "{\"config\":\"$CFG\",\"wallet\":\"$WAL\",\"authVerifiers\":{\"x\":{\"module\":\"nonexistent_module\"}}}")
poc_say "probe1 serve (nonexistent verifier): ${PROBE1:-<empty>}"

# ---------- open serve ----------------------------------------------------------
SERVE=$(gf_serve "$B" "{\"config\":\"$CFG\",\"wallet\":\"$WAL\",\"consumedNullifiersPath\":\"$B/consumed.txt\"}")

# ---------- A′ request ------------------------------------------------------------
IDC=$(openssl rand -hex 32)
REQ="{\"gifterPeerId\":\"$GPEER\",\"gifterMultiaddr\":\"/ip4/127.0.0.1/tcp/$GIFTER_PORT\",\"identityCommitment\":\"$IDC\",\"rate\":100}"
REQ_OUT=$(gf_request "$A" "$REQ" open1) || REQ_OUT=""
LAT=$(gf_latency "$A" open1)
REQ_RES=$(cat "$A/requests/open1.res.json" 2>/dev/null || true)
REQ_ERR=$(gf_field "$REQ_RES" error)

LP_A=$(gf_check_lp_logs "$A")
LP_B=$(gf_check_lp_logs "$B")
poc_say "lp log A′: ${LP_A:-<none>}"
poc_say "lp log B′: ${LP_B:-<none>}"
# Each inbound call to the stub logs one currentCallerJson warning: 1 = register only;
# a stream every 2 s means the gifter fell into its get_membership confirm loop.
STUB_CALLS=$(grep -ac '\[liblogos_lez_rln_module\] Warning: QMetaObject::invokeMethod' "$B/daemon.log" || true)
poc_say "inbound calls on stub: ${STUB_CALLS:-0}"
REQ_CLI=$(cat "$A/requests/open1.env.json" 2>/dev/null || true)

S_PROBE1="$PROBE1" S_SERVE="$SERVE" S_GPEER="$GPEER" S_IDC="$IDC" S_RES="$REQ_RES" \
S_ERR="$REQ_ERR" S_LAT="$LAT" S_LPA="$LP_A" S_LPB="$LP_B" S_STUB="$STUB_LEZ_LGX" \
S_LLGX="$LIBP2P_LGX" S_LREV="$LIBP2P_REV" S_GLGX="$GIFTER_LGX" S_GREV="$GIFTER_REV" S_STUBN="${STUB_CALLS:-0}" S_CLI="$REQ_CLI" \
python3 -I - "$SMOKE/smoke.json" <<'PY'
import json, os, sys
e = os.environ
def j(s):
    try: return json.loads(s)
    except Exception: return s
p1 = j(e["S_PROBE1"])
out = {
  "probe1": p1,
  "probe1_lazy_clients": "lp_client_create failed" not in json.dumps(p1),
  "serve_ok": "mounted" in e["S_SERVE"],
  "gifter_peer": e["S_GPEER"],
  "identity_commitment": e["S_IDC"],
  "request_reply": j(e["S_RES"]),
  "request_error": e["S_ERR"] or None,
  "request_latency_s": int(e["S_LAT"] or -1),
  "request_cli_envelope": j(e["S_CLI"].strip()),
  "stub_inbound_calls": int(e["S_STUBN"] or 0),
  "lp_log_lines": {"a": [l for l in e["S_LPA"].splitlines() if l],
                   "b": [l for l in e["S_LPB"].splitlines() if l]},
  "stub_lez_lgx": e["S_STUB"] or None,
  "libp2p_lgx": e["S_LLGX"], "libp2p_rev": e["S_LREV"],
  "gifter_lgx": e["S_GLGX"], "gifter_rev": e["S_GREV"],
}
json.dump(out, open(sys.argv[1], "w"), indent=2)
print(json.dumps(out, indent=2))
PY
cp "$SMOKE/smoke.json" "$POC_DIR/runs/gifter-smoke.json"
poc_say "smoke written: $SMOKE/smoke.json"
[ -n "$REQ_RES" ] || poc_die "no gifter reply (request timed out after ${LAT}s)"
