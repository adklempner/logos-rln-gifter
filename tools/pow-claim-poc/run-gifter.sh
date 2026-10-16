#!/usr/bin/env bash
# run-gifter.sh — PoW-claim auth vector end to end through the RLN gifter, two daemons:
#
#   A (client):  node 1 (blockchain_module, :18080) + pow_claim_capture_module + libp2p + gifter
#   B (gifter):  node 2 (follower, :18081) + libp2p (tcp/61871) + liblogos_lez_rln_module (stub)
#                + pow_claim_auth_module (verifier, against node 2) + rln_gifter_module
#
# Mine + claim on node 1, wait until the claim block is final on both nodes, then drive
# `request` from A to B (provider path, authPayload replays, negatives), then stop node 1
# and show the verifier still accepts using node 2.
#
# The stub registry answers register_member with non-JSON, so an ACCEPTED request ends in
# the register error (NotSubmitted → nullifier released). Positives are evidenced by that
# error + a verifier audit accept line + exactly one inbound stub call.
#
# Env: POC_AUDIENCE (poc), POC_RATE_MAX (100), POC_KEEP (0; 1 leaves both daemons up),
#      POC_EXPECT_REGISTER_ERR (regex; default 'register_member: reply parse'),
#      PCM_LGX, PCA_LGX, LIBP2P_LGX, GIFTER_LGX, STUB_LGX, LOGOSCORE, BM_LGX.
# Writes runs/<ts>-gifter/{a,b,node2-view,summary.json}.
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$POC_DIR/lib/logoscore.sh"
. "$POC_DIR/lib/gifter.sh"
. "$POC_DIR/lib/claim_flow.sh"
export PATH="$PATH:/nix/var/nix/profiles/default/bin"

# ---------------------------------------------------------------- config
_ov_libp2p="${LIBP2P_LGX:-}"; _ov_gifter="${GIFTER_LGX:-}"; _ov_stub="${STUB_LGX:-}"
[ -f "$POC_DIR/runs/artifacts.env" ] && . "$POC_DIR/runs/artifacts.env"
LIBP2P_LGX="${_ov_libp2p:-${LIBP2P_LGX:-/nix/store/gcjv35sb883m2nkv5lsfs5hhv7vvzi4z-logos-libp2p_module-module-lib-lgx-1.0.0/logos-libp2p_module-module-lib.lgx}}"
GIFTER_LGX="${_ov_gifter:-${GIFTER_LGX:-/nix/store/00xms9gahgha8ygvh4d56fczkw83578a-logos-rln_gifter_module-module-lib-lgx-0.3.0/logos-rln_gifter_module-module-lib.lgx}}"
STUB_LGX="${_ov_stub:-${STUB_LEZ_LGX:-/nix/store/3nym2lyqdwxvq9wryp7irpi3a43f7brq-logos-liblogos_lez_rln_module-module-lib-lgx-0.0.1/logos-liblogos_lez_rln_module-module-lib.lgx}}"
PCM_LGX="${PCM_LGX:-/nix/store/dhj8kp98r2hn31yf0aw6xplkw0fbpmh7-logos-pow_claim_capture_module-module-lib-lgx-0.1.0/logos-pow_claim_capture_module-module-lib.lgx}"
PCA_LGX="${PCA_LGX:-/nix/store/l0c5zwc0w8igrixf0rn70p4v25m2y9v4-logos-pow_claim_auth_module-module-lib-lgx-0.1.0/logos-pow_claim_auth_module-module-lib.lgx}"
LOGOSCORE="${LOGOSCORE:-$POC_DIR/runs/logos/bin/logoscore}"
if [ -z "${BM_LGX:-}" ]; then
    BM_LGX=$(find -L "$POC_DIR/runs/bm-lgx/" -maxdepth 1 -name '*.lgx' 2>/dev/null | head -1)
fi
export LOGOSCORE BM_LGX
POC_AUDIENCE="${POC_AUDIENCE:-poc}"
POC_RATE_MAX="${POC_RATE_MAX:-100}"
POC_KEEP="${POC_KEEP:-0}"
POC_EXPECT_REGISTER_ERR="${POC_EXPECT_REGISTER_ERR:-register_member: reply parse}"
VERIFY_BIN="$POC_DIR/verify/target/release/pow-claim-verify"
NODEQ="$POC_DIR/lib/nodeq.py"
URL1="http://127.0.0.1:18080"
URL2="http://127.0.0.1:18081"
GPORT=61871
GADDR="/ip4/127.0.0.1/tcp/$GPORT"
CFG="PoCConfig1111111111111111111111111111"
WAL="PoCWallet1111111111111111111111111111"

RUN="$POC_DIR/runs/$(date +%Y%m%d-%H%M%S)-gifter"
RUN_A="$RUN/a"; RUN_B="$RUN/b"
mkdir -p "$RUN_A" "$RUN_B"
REQ_TSV="$RUN/requests.tsv"; : > "$REQ_TSV"
FAILS="$RUN/fails.txt"; : > "$FAILS"

say() { poc_say "[$(date +%H:%M:%S)] $*"; }
nq() { local url="$1"; shift; python3 -I "$NODEQ" --node-url "$url" "$@"; }

STEP=""; STEP_T0=0; T_ALL=$(date +%s); TIMINGS=""
step() {
    local now; now=$(date +%s)
    [ -z "$STEP" ] || TIMINGS="$TIMINGS$STEP=$((now - STEP_T0)) "
    STEP="$1"; STEP_T0=$now
    say "==== step $STEP"
}
fail() { printf '%s: %s\n' "$STEP" "$*" >> "$FAILS"; poc_die "step $STEP: $*"; }
# soft assertion: record, keep going
check() { # check <ok 0/1> <message>
    if [ "$1" = 1 ]; then say "PASS $2"; else say "FAIL $2"; printf '%s: %s\n' "$STEP" "$2" >> "$FAILS"; fi
}

A_UP=0; B_UP=0
teardown() {
    local rc=$?
    if [ "$POC_KEEP" = 1 ]; then
        say "POC_KEEP=1: left up; stop with node2-up.sh --down $RUN_B; node-up.sh --down $RUN_A"
    else
        [ "$B_UP" = 0 ] || "$POC_DIR/node2-up.sh" --down "$RUN_B" || true
        [ "$A_UP" = 0 ] || "$POC_DIR/node-up.sh" --down "$RUN_A" || true
        rm -rf "$RUN_A/modules" "$RUN_B/modules"
        say "teardown done (module copies removed)"
    fi
    [ "$rc" = 0 ] || say "run-gifter.sh FAILED (rc=$rc) in step ${STEP:-?}; run dir $RUN"
}
trap teardown EXIT

# ---------------------------------------------------------------- 1. preflight
step preflight
busy() { lsof -nP -iUDP:"$1" >/dev/null 2>&1 || lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
for port in 18080 18081 "$GPORT" 13000 13001 3400 3401; do
    if busy "$port"; then fail "port $port busy (stale run? node-up.sh --down / node2-up.sh --down)"; fi
done
[ -x "$LOGOSCORE" ] || fail "no logoscore at $LOGOSCORE"
for f in "$BM_LGX" "$PCM_LGX" "$PCA_LGX" "$LIBP2P_LGX" "$GIFTER_LGX" "$STUB_LGX"; do
    [ -f "$f" ] || fail "missing artifact $f"
done
say "run dir $RUN"

# ---------------------------------------------------------------- 2. daemon A + node 1
step node1-up
POC_RUN_DIR="$RUN_A" EXTRA_LGX="$PCM_LGX $LIBP2P_LGX $GIFTER_LGX" "$POC_DIR/node-up.sh" >/dev/null \
    || { A_UP=1; fail "node-up.sh failed"; }
A_UP=1
eval "$(. "$RUN_A/env.sh"; printf 'POC_K=%q A_PID=%q\n' "$POC_K" "$POC_DAEMON_PID")"
say "node 1 up (daemon pid $A_PID), K=$POC_K"

# ---------------------------------------------------------------- 3. daemon B + node 2
step node2-up
POC_RUN_DIR="$RUN_B" EXTRA_LGX="$PCA_LGX $LIBP2P_LGX $GIFTER_LGX $STUB_LGX" \
    "$POC_DIR/node2-up.sh" --node1-run "$RUN_A" >/dev/null || { B_UP=1; fail "node2-up.sh failed"; }
B_UP=1
eval "$(. "$RUN_B/env.sh"; printf 'B_PID=%q NODE1_PEER=%q\n' "$POC_DAEMON_PID" "$POC_NODE1_PEER_ID")"
say "node 2 up (daemon pid $B_PID), node 1 peer $NODE1_PEER"

# ---------------------------------------------------------------- 4. mine + claim
step mine
cf_mine "$URL1" "$RUN_A" || fail "mining"
step claim
cf_claim "$URL1" "$RUN_A" "$POC_K" || fail "claim"
NUL=$(printf '%s' "$CLAIM_N" | tr 'A-F' 'a-f'); NUL="${NUL#0x}"

# ---------------------------------------------------------------- 5. finality on both nodes
step lib
l1=$(nq "$URL1" wait-lib --slot "$CLAIM_S" --timeout 600) || fail "node 1 LIB < $CLAIM_S after 600 s"
say "node 1 lib: $l1"
l2=$(nq "$URL2" wait-lib --slot "$CLAIM_S" --timeout 600) || fail "node 2 LIB < $CLAIM_S after 600 s"
say "node 2 lib: $l2"
NODE2_VIEW=""; t=0
while [ "$t" -le 120 ]; do
    NODE2_VIEW=$(nq "$URL2" capture --block "$CLAIM_B" --slot "$CLAIM_S" --out "$RUN/node2-view" 2>"$RUN/node2-view.err") && break
    NODE2_VIEW=""; sleep 5; t=$((t + 5))
done
[ -n "$NODE2_VIEW" ] || fail "node 2 does not hold claim block $CLAIM_B immutable: $(cat "$RUN/node2-view.err")"
say "node 2 view: $NODE2_VIEW"

# ---------------------------------------------------------------- 6. daemon B gifter
step gifter-b
for m in libp2p_module liblogos_lez_rln_module pow_claim_auth_module rln_gifter_module; do
    out=$(_with_timeout 60 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$RUN_B/config" "$LOGOSCORE" --json load-module "$m" 2>&1 || true)
    printf '%s\n' "$out" >> "$RUN_B/daemon.log"
    case "$out" in *'"status":"ok"'*) say "B loaded $m" ;; *) fail "B load-module $m: $out" ;; esac
done
GPEER=$(gf_libp2p_up "$RUN_B" "$GADDR")
say "gifter peer $GPEER"
serve_json() { # serve_json <node_url>
    python3 -I -c '
import json, sys
cfg, wal, rb, url, aud = sys.argv[1:6]
print(json.dumps({"config": cfg, "wallet": wal, "maxRateLimit": 100,
    "consumedNullifiersPath": rb + "/consumed_nullifiers.txt",
    "authVerifiers": {"pow-claim": {"module": "pow_claim_auth_module", "config": {
        "node_url": url, "audience": aud, "min_payout": 0, "allow_direct_ownership": True,
        "allow_spend_locator": False, "http_timeout_ms": 5000,
        "audit_log": rb + "/verifier-audit.jsonl"}}}}, separators=(",", ":")))' \
        "$CFG" "$WAL" "$RUN_B" "$1" "$POC_AUDIENCE"
}
SERVE=$(gf_serve "$RUN_B" "$(serve_json "$URL2")")
LP_B=$(gf_check_lp_logs "$RUN_B")
[ -z "$LP_B" ] || say "lp log B: $LP_B"

# ---------------------------------------------------------------- 7. daemon A client + payloads
step client-a
for m in pow_claim_capture_module libp2p_module rln_gifter_module; do
    out=$(_with_timeout 60 env -u TMPDIR LOGOSCORE_CONFIG_DIR="$RUN_A/config" "$LOGOSCORE" --json load-module "$m" 2>&1 || true)
    printf '%s\n' "$out" >> "$RUN_A/daemon.log"
    case "$out" in *'"status":"ok"'*) say "A loaded $m" ;; *) fail "A load-module $m: $out" ;; esac
done
APEER=$(gf_libp2p_up "$RUN_A" "/ip4/127.0.0.1/tcp/0")
say "client peer $APEER"
IDC=$(openssl rand -hex 32)
IDC2=$(openssl rand -hex 32)
pt0=$(date +%s)
P=$(cf_produce "$RUN_A" "$IDC" "$POC_AUDIENCE" "$POC_RATE_MAX" p) || fail "produce p: $(cat "$RUN_A/produce/p.json")"
PRODUCE_S=$(( $(date +%s) - pt0 ))
P_EVIL=$(cf_produce "$RUN_A" "$IDC" evil "$POC_RATE_MAX" p-evil) || fail "produce p-evil"
P50=$(cf_produce "$RUN_A" "$IDC" "$POC_AUDIENCE" 50 p50) || fail "produce p50"
say "payloads: P=${P:0:24}… (${#P} hex, ${PRODUCE_S}s) P_EVIL=${P_EVIL:0:24}… P50=${P50:0:24}…"
XCHECK="skipped"
if [ -x "$VERIFY_BIN" ]; then
    xrc=0
    "$VERIFY_BIN" --payload-hex "$P" --id-commitment-hex "$IDC" --audience "$POC_AUDIENCE" --expect-k "$POC_K" \
        > "$RUN_A/produce/verify.p.json" 2> "$RUN_A/produce/verify.p.err" || xrc=$?
    XCHECK=$(python3 -I -c '
import json, sys
v = json.load(open(sys.argv[1]))
ok = v.get("sig_valid") is True and v.get("expect_k_match") is True and str(v.get("pow_nullifier","")).lower().removeprefix("0x") == sys.argv[2]
print("ok" if ok and sys.argv[3] == "0" else "bad")' "$RUN_A/produce/verify.p.json" "$NUL" "$xrc" 2>/dev/null || echo bad)
    [ "$XCHECK" = ok ] && check 1 "pow-claim-verify cross-check of P" || check 0 "pow-claim-verify cross-check of P (rc=$xrc)"
fi
# neg-sig: flip one bit at byte 234-128+5 (inside the zkSign signature)
P_SIG=$(python3 -I -c '
import sys
b = bytearray.fromhex(sys.argv[1]); i = 234 - 128 + 5; b[i] ^= 0x01; print(b.hex())' "$P")
P_TRUNC="${P:0:$(( ${#P} - 2 ))}"

# ---------------------------------------------------------------- request machinery
AUDIT="$RUN_B/verifier-audit.jsonl"
audit_n() { if [ -f "$AUDIT" ]; then wc -l < "$AUDIT" | tr -d ' '; else echo 0; fi; }
stub_n() { grep -ac '\[liblogos_lez_rln_module\] Warning: QMetaObject::invokeMethod' "$RUN_B/daemon.log" || true; }
mkbody() { # mkbody <idc> <rate> <authType> <mode> [payload]
    python3 -I -c '
import json, sys
gp, ga, aud, rm, idc, rate, at, mode = sys.argv[1:9]
payload = sys.argv[9] if len(sys.argv) > 9 else ""
d = {"gifterPeerId": gp, "gifterMultiaddr": ga, "identityCommitment": idc, "rate": int(rate), "authType": at}
if mode == "provider":
    d["authProvider"] = "pow_claim_capture_module"
    d["authArgs"] = {"node_url": "http://127.0.0.1:18080", "audience": aud, "rate_max": int(rm)}
else:
    d["authPayload"] = payload
print(json.dumps(d, separators=(",", ":")))' "$GPEER" "$GADDR" "$POC_AUDIENCE" "$POC_RATE_MAX" "$@"
}
REG_ERR=""
# run_req <tag> <body> <error-regex> <audit: accept|reject|error|none> <stub delta> [node-url-for-accept]
run_req() {
    local tag="$1" body="$2" want="$3" aud="$4" sdelta="$5" anode="${6:-$URL2}"
    local a0 s0 a1 s1 err lat ok=1 why="" last
    a0=$(audit_n); s0=$(stub_n)
    gf_request "$RUN_A" "$body" "$tag" >/dev/null || true
    a1=$(audit_n); s1=$(stub_n)
    lat=$(gf_latency "$RUN_A" "$tag")
    err=$(gf_field "$(cat "$RUN_A/requests/$tag.res.json" 2>/dev/null)" error)
    [ -s "$RUN_A/requests/$tag.res.json" ] && [ "$(tr -d '[:space:]' < "$RUN_A/requests/$tag.res.json")" != "" ] \
        || { ok=0; why="$why no-reply;"; }
    [ "${lat:-99}" -lt 20 ] || { ok=0; why="$why latency=${lat}s;"; }
    printf '%s' "$err" | grep -Eiq -- "$want" || { ok=0; why="$why error!~/$want/;"; }
    if [ "$want" != "$POC_EXPECT_REGISTER_ERR" ] && printf '%s' "$err" | grep -Eq -- "$POC_EXPECT_REGISTER_ERR"; then
        ok=0; why="$why neg-matches-register-error;"
    fi
    if [ "$aud" = none ]; then
        [ "$a1" = "$a0" ] || { ok=0; why="$why audit+$((a1 - a0)) want 0;"; }
    else
        [ "$a1" = $((a0 + 1)) ] || { ok=0; why="$why audit+$((a1 - a0)) want 1;"; }
        last=$(tail -n 1 "$AUDIT" 2>/dev/null || true)
        python3 -I -c '
import json, sys
d = json.loads(sys.argv[1]); want, nul, node = sys.argv[2:5]
ok = d.get("verdict") == want
if want == "accept":
    ok = ok and str(d.get("nullifier") or "").lower().removeprefix("0x") == nul \
         and d.get("node") == node and d.get("path") == "spent_to"
sys.exit(0 if ok else 1)' "$last" "$aud" "$NUL" "$anode" 2>/dev/null || { ok=0; why="$why audit-last!=$aud($last);"; }
    fi
    [ "$((s1 - s0))" = "$sdelta" ] || { ok=0; why="$why stub+$((s1 - s0)) want $sdelta;"; }
    if [ "$aud" = accept ]; then
        if [ -f "$RUN_B/consumed_nullifiers.txt" ] && grep -q "pow-claim:$NUL" "$RUN_B/consumed_nullifiers.txt"; then
            ok=0; why="$why nullifier-persisted;"
        fi
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$tag" "$lat" "$ok" "$err" "$why" >> "$REQ_TSV"
    check "$ok" "request $tag (${lat}s): ${err:-<no error>}${why:+ —$why}"
}

# ---------------------------------------------------------------- 8. provider path
step pos-provider
run_req pos-provider "$(mkbody "$IDC" 100 pow-claim provider)" "$POC_EXPECT_REGISTER_ERR" accept 1

# ---------------------------------------------------------------- 9. replays / negatives
step replays
run_req pos-replay   "$(mkbody "$IDC"  100 pow-claim    payload "$P")"       "$POC_EXPECT_REGISTER_ERR" accept 1
run_req neg-sig      "$(mkbody "$IDC"  100 pow-claim    payload "$P_SIG")"   "signature"                reject 0
run_req neg-audience "$(mkbody "$IDC"  100 pow-claim    payload "$P_EVIL")"  "signature"                reject 0
run_req neg-idc      "$(mkbody "$IDC2" 100 pow-claim    payload "$P")"       "signature"                reject 0
run_req neg-trunc    "$(mkbody "$IDC"  100 pow-claim    payload "$P_TRUNC")" "payload|length"           reject 0
run_req neg-authtype "$(mkbody "$IDC"  100 pow-claim-v0 payload "$P")"       "unsupported authentication_type" none 0
run_req neg-rate     "$(mkbody "$IDC"  100 pow-claim    payload "$P50")"     "rate_max"                 reject 0

# ---------------------------------------------------------------- 10. node 1 down
step node1-down
r=$(POC_RUN_DIR="$RUN_A" CALL_TIMEOUT=60 lc_call blockchain_module stop || true)
say "node 1 stop -> ${r:-<no output>}"
sleep 2
if curl -s --max-time 3 "$URL1/cryptarchia/info" >/dev/null 2>&1; then
    check 0 "node 1 HTTP still answers after stop"
else
    check 1 "node 1 HTTP down"
fi
run_req pos-node1-down "$(mkbody "$IDC" 100 pow-claim payload "$P")" "$POC_EXPECT_REGISTER_ERR" accept 1
# contrast: verifier pointed at the dead node 1
gf_serve "$RUN_B" "$(serve_json "$URL1")" >/dev/null
run_req pos-dead-node "$(mkbody "$IDC" 100 pow-claim payload "$P")" "auth verifier pow_claim_auth_module.*unreachable" error 0
gf_serve "$RUN_B" "$(serve_json "$URL2")" >/dev/null
say "re-served with node_url $URL2"

# ---------------------------------------------------------------- 11. summary
step summary
TIMINGS="${TIMINGS}total=$(( $(date +%s) - T_ALL ))"
STUB_TOTAL=$(stub_n)
S_RUN="$RUN" S_TIMINGS="$TIMINGS" S_GPEER="$GPEER" S_APEER="$APEER" S_N1PEER="$NODE1_PEER" \
S_B="$CLAIM_B" S_S="$CLAIM_S" S_N="$CLAIM_N" S_TX="$CLAIM_TX" S_UPK="$CLAIM_UPK" S_AUTO="$CLAIM_AUTO" \
S_K="$POC_K" S_VIEW="$NODE2_VIEW" S_IDC="$IDC" S_IDC2="$IDC2" S_P="$P" S_PROD="$PRODUCE_S" S_XCHECK="$XCHECK" \
S_STUB="$STUB_TOTAL" S_PCM="$PCM_LGX" S_PCA="$PCA_LGX" S_LIBP2P="$LIBP2P_LGX" S_GIFTER="$GIFTER_LGX" \
S_STUBLGX="$STUB_LGX" S_BM="$BM_LGX" S_LREV="${LIBP2P_REV:-}" S_GREV="${GIFTER_REV:-}" S_REGRX="$POC_EXPECT_REGISTER_ERR" \
python3 -I - "$RUN/summary.json" "$REQ_TSV" "$RUN_B/verifier-audit.jsonl" "$FAILS" <<'PY'
import json, os, sys
e = os.environ
out, tsv, audit, fails = sys.argv[1:5]
reqs = []
for line in open(tsv):
    if not line.strip():
        continue
    tag, lat, ok, err, why = (line.rstrip("\n").split("\t") + [""] * 5)[:5]
    reqs.append({"tag": tag, "latency_s": int(lat) if lat.isdigit() else None, "error": err or None,
                 "pass": ok == "1", "why": why.strip() or None})
counts = {}
if os.path.exists(audit):
    for l in open(audit):
        if l.strip():
            v = json.loads(l).get("verdict")
            counts[v] = counts.get(v, 0) + 1
fl = [l.strip() for l in open(fails) if l.strip()]
try:
    view = json.loads(e["S_VIEW"])
except Exception:
    view = e["S_VIEW"]
s = {
    "run": e["S_RUN"],
    "artifacts": {"blockchain_module": e["S_BM"], "pow_claim_capture_module": e["S_PCM"],
                  "pow_claim_auth_module": e["S_PCA"], "libp2p_module": e["S_LIBP2P"],
                  "libp2p_rev": e["S_LREV"] or None, "rln_gifter_module": e["S_GIFTER"],
                  "gifter_rev": e["S_GREV"] or None, "liblogos_lez_rln_module_stub": e["S_STUBLGX"]},
    "peers": {"gifter_b": e["S_GPEER"], "client_a": e["S_APEER"], "node1": e["S_N1PEER"]},
    "claim": {"k": e["S_K"], "block_id": e["S_B"], "slot": int(e["S_S"]), "pow_nullifier": e["S_N"],
              "tx_hash": e["S_TX"], "utxo_pk": e["S_UPK"], "auto_claim": e["S_AUTO"] == "true"},
    "node2_view": view,
    "identity_commitment": e["S_IDC"], "identity_commitment_2": e["S_IDC2"],
    "payload_hex": e["S_P"], "produce_latency_s": int(e["S_PROD"]), "verify_cli_crosscheck": e["S_XCHECK"],
    "expect_register_error_regex": e["S_REGRX"],
    "requests": reqs,
    "audit_counts": {"accept": counts.get("accept", 0), "reject": counts.get("reject", 0),
                     "error": counts.get("error", 0)},
    "stub_inbound_calls": int(e["S_STUB"] or 0),
    "timings_s": {kv.split("=")[0]: int(kv.split("=")[1]) for kv in e["S_TIMINGS"].split()},
    "failures": fl,
    "all_pass": not fl and all(r["pass"] for r in reqs),
}
json.dump(s, open(out, "w"), indent=1)
open(out, "a").write("\n")
short = dict(s); short["payload_hex"] = s["payload_hex"][:32] + "…"
print("==== PoW-claim gifter run summary ====")
print(json.dumps(short, indent=1))
print()
print("%-15s %7s  %-4s  %s" % ("tag", "latency", "pass", "error"))
for r in reqs:
    print("%-15s %6ss  %-4s  %s" % (r["tag"], r["latency_s"], "ok" if r["pass"] else "FAIL", r["error"]))
print("audit:", s["audit_counts"], " stub_inbound_calls:", s["stub_inbound_calls"], " all_pass:", s["all_pass"])
PY
STEP=done
if [ -s "$FAILS" ]; then
    say "FAILED assertions:"; cat "$FAILS" >&2
    exit 1
fi
say "OK — all green; summary at $RUN/summary.json"
