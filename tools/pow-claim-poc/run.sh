#!/usr/bin/env bash
# run.sh — PoW-claim PoC end to end on one fresh node:
#   node (logoscore + blockchain_module) -> mine -> claim -> settle (LIB) -> capture fixtures
#   -> pow_claim_capture_module.produce_auth -> pow-claim-verify (+ negative check).
#
# Env: POC_RUN_DIR, POC_HTTP_PORT (18080), POC_K, POC_AUDIENCE (poc), POC_RATE_MAX (100),
#      POC_ALLOW_UNFINAL (0), LOGOSCORE, BM_LGX, PCM_LGX (skip module build if set),
#      POC_KEEP (0; 1 leaves the node up), POC_SKIP_BUILD_VERIFY (0).
# Writes: <run>/{claim.json,produce/,summary.json}, verify/tests/fixtures/golden.json,
#         rust-lib/pow-claim-core/tests/fixtures/real/.
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$POC_DIR/../.." && pwd)"
. "$POC_DIR/lib/logoscore.sh"
export PATH="$PATH:/nix/var/nix/profiles/default/bin"

POC_HTTP_PORT="${POC_HTTP_PORT:-18080}"
POC_K="${POC_K:-e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07}"
POC_AUDIENCE="${POC_AUDIENCE:-poc}"
POC_RATE_MAX="${POC_RATE_MAX:-100}"
POC_ALLOW_UNFINAL="${POC_ALLOW_UNFINAL:-0}"
POC_KEEP="${POC_KEEP:-0}"
POC_SKIP_BUILD_VERIFY="${POC_SKIP_BUILD_VERIFY:-0}"
LOGOSCORE="${LOGOSCORE:-$POC_DIR/runs/logos/bin/logoscore}"
export POC_HTTP_PORT POC_K LOGOSCORE
URL="http://127.0.0.1:$POC_HTTP_PORT"
NODEQ="$POC_DIR/lib/nodeq.py"
VERIFY_MANIFEST="$POC_DIR/verify/Cargo.toml"
VERIFY_BIN="$POC_DIR/verify/target/release/pow-claim-verify"
REAL_FIX="$REPO/rust/pow-claim-capture-module/rust-lib/pow-claim-core/tests/fixtures/real"
GOLDEN="$POC_DIR/verify/tests/fixtures/golden.json"
NODE_REV=2c652646d74354b2877620bf0bc53b4c4d3f18e4

nq() { python3 -I "$NODEQ" --node-url "$URL" "$@"; }
pyget() { python3 -I -c "import json,sys; d=json.load(sys.stdin); v=$1; print(v if isinstance(v,str) else json.dumps(v))"; }

STEP=""; STEP_T0=0; T_ALL=$(date +%s); TIMINGS=""
step() {
    local now; now=$(date +%s)
    [ -z "$STEP" ] || TIMINGS="$TIMINGS$STEP=$((now - STEP_T0)) "
    STEP="$1"; STEP_T0=$now
    poc_say "[$(date +%H:%M:%S)] step $STEP"
}
fail() { poc_die "step $STEP: $*"; }

RUN=""
teardown() {
    local rc=$?
    if [ -n "$RUN" ] && [ "$POC_KEEP" != 1 ]; then
        "$POC_DIR/node-up.sh" --down "$RUN" || true
    elif [ -n "$RUN" ]; then
        poc_say "POC_KEEP=1: node left up ($RUN); stop with node-up.sh --down $RUN"
    fi
    [ "$rc" = 0 ] || poc_say "run.sh FAILED (rc=$rc) in step ${STEP:-?}${RUN:+; run dir $RUN}"
}
trap teardown EXIT

# ---------------------------------------------------------------- 1. artifacts
step artifacts
[ -x "$LOGOSCORE" ] || fail "no logoscore at $LOGOSCORE"
if [ -z "${BM_LGX:-}" ]; then
    BM_LGX=$(find -L "$POC_DIR/runs/bm-lgx/" -maxdepth 1 -name '*.lgx' 2>/dev/null | head -1)
fi
[ -f "${BM_LGX:-}" ] || fail "no blockchain_module .lgx (BM_LGX or runs/bm-lgx/*.lgx)"
export BM_LGX
if [ -z "${PCM_LGX:-}" ]; then
    poc_say "building pow_claim_capture_module (build-module.sh)"
    PCM_LGX=$("$POC_DIR/build-module.sh" | tail -1) || {
        poc_say "build-module.sh failed; retrying once"
        PCM_LGX=$("$POC_DIR/build-module.sh" | tail -1)
    } || fail "build-module.sh failed"
fi
[ -f "$PCM_LGX" ] || fail "no producer .lgx at $PCM_LGX"
poc_say "PCM_LGX=$PCM_LGX"
if [ "$POC_SKIP_BUILD_VERIFY" != 1 ]; then
    cargo build --release --quiet --manifest-path "$VERIFY_MANIFEST" || fail "cargo build verify"
fi
[ -x "$VERIFY_BIN" ] || fail "no verifier at $VERIFY_BIN"

# ---------------------------------------------------------------- 2. node
step node-up
oldpid=$(cat "$POC_DIR/runs/latest/daemon.pid" 2>/dev/null || true)
if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
    poc_say "stopping previous node (pid $oldpid)"
    "$POC_DIR/node-up.sh" --down
fi
RUN=$(EXTRA_LGX="$PCM_LGX" "$POC_DIR/node-up.sh" | tail -1) || { RUN=""; fail "node-up.sh failed"; }
[ -f "$RUN/env.sh" ] || fail "node-up.sh printed '$RUN' without env.sh"
. "$RUN/env.sh"
poc_say "run dir $RUN"
mkdir -p "$RUN/produce"

# ---------------------------------------------------------------- 3. mine
step mine
r=$(lc_call blockchain_module pow_start_mining || true)
poc_say "pow_start_mining -> $r"
claimable=$(nq wait-claimable --min 1 --timeout 120) || {
    lc_call blockchain_module pow_stop_mining >/dev/null || true
    fail "no claimable ticket within 120 s"
}
r=$(lc_call blockchain_module pow_stop_mining || true)
poc_say "claimable=$claimable; pow_stop_mining -> $r"

# ---------------------------------------------------------------- 4. claim
step claim
out=$(CALL_TIMEOUT=120 lc_call blockchain_module pow_claim "$(argfile k "$POC_K")" || true)
printf '%s\n' "$out" > "$RUN/pow_claim.out.json"
TX=$(printf '%s' "$out" | jres | jval 2>/dev/null || true)
case "$TX" in
    [0-9a-f]*) [ "${#TX}" = 64 ] || TX="" ;;
    *) TX="" ;;
esac
if [ -z "$TX" ]; then
    poc_say "pow_claim via module gave '$out'; falling back to POST /pow/claim"
    out=$(curl -s -X POST -H 'content-type: application/json' -d "{\"claim_address\":\"$POC_K\"}" "$URL/pow/claim" || true)
    printf '%s\n' "$out" > "$RUN/pow_claim.http.json"
    TX=$(printf '%s' "$out" | python3 -I -c '
import json, sys, re
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    d = raw
s = d if isinstance(d, str) else json.dumps(d)
m = re.search(r"[0-9a-f]{64}", s)
print(m.group(0) if m else "")')
    poc_say "POST /pow/claim -> $out"
fi
poc_say "claim tx ${TX:-<unknown>}"
if [ -n "$TX" ]; then
    CLAIM=$(nq find-claim --tx-hash "$TX" --timeout 180) || fail "claim tx $TX not found within 180 s"
else
    CLAIM=$(nq find-claim --timeout 180) || fail "no claim event within 180 s"
fi
printf '%s\n' "$CLAIM" > "$RUN/claim.json"
B=$(printf '%s' "$CLAIM" | pyget 'd["block_id"]')
S=$(printf '%s' "$CLAIM" | pyget 'd["slot"]')
N=$(printf '%s' "$CLAIM" | pyget 'd["pow_nullifier"]')
CTX=$(printf '%s' "$CLAIM" | pyget 'd["tx_hash"]')
UPK=$(printf '%s' "$CLAIM" | pyget 'd["utxo_pk"]')
AUTO=$(printf '%s' "$CLAIM" | pyget 'd.get("auto_claim", False)')
poc_say "claim: block=$B slot=$S nullifier=$N tx=$CTX utxo_pk=$UPK auto_claim=$AUTO"

# ---------------------------------------------------------------- 5. finality
step lib
if [ "$POC_ALLOW_UNFINAL" = 1 ]; then
    poc_say "POC_ALLOW_UNFINAL=1: not waiting for LIB"
else
    lib=$(nq wait-lib --slot "$S" --timeout 600) || fail "LIB did not reach slot $S within 600 s"
    poc_say "lib: $lib"
fi

# ---------------------------------------------------------------- 6. capture
step capture
mkdir -p "$REAL_FIX"
if [ "$POC_ALLOW_UNFINAL" = 1 ]; then
    poc_say "POC_ALLOW_UNFINAL=1: skipping fixture capture (needs an immutable claim block)"
else
    cap=$(nq capture --block "$B" --slot "$S" --out "$REAL_FIX") || fail "capture"
    poc_say "capture: $cap"
fi

# ---------------------------------------------------------------- 7. produce
step produce
lc_load pow_claim_capture_module
IDC=$(openssl rand -hex 32)
UNF=false; [ "$POC_ALLOW_UNFINAL" = 1 ] && UNF=true
ARGS_OBJ="{\"node_url\":\"$URL\",\"audience\":\"$POC_AUDIENCE\",\"rate_max\":$POC_RATE_MAX,\"allow_unfinal\":$UNF}"
REQ1="{\"auth_type\":\"pow-claim\",\"id_commitment_hex\":\"$IDC\",\"args\":$ARGS_OBJ}"
REQ2=$(printf '%s' "$REQ1" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d["args"]=json.dumps(d["args"],separators=(",",":")); print(json.dumps(d,separators=(",",":")))')
# produce <tag> <request-json>  -> payload_hex on stdout
produce() {
    local tag="$1" req="$2" env res
    printf '%s\n' "$req" > "$RUN/produce/$tag.request.json"
    env=$(CALL_TIMEOUT=180 lc_call pow_claim_capture_module produce_auth "$req" || true)
    printf '%s\n' "$env" > "$RUN/produce/$tag.envelope.json"
    res=$(printf '%s' "$env" | jres)
    printf '%s\n' "$res" > "$RUN/produce/$tag.response.json"
    printf '%s' "$res" | python3 -I -c '
import json, re, sys
raw = sys.stdin.read().strip()
try:
    d = json.loads(raw)
except Exception:
    sys.exit("unparsable reply: %r" % raw[:300])
if isinstance(d, str):
    d = json.loads(d)
p = d.get("payload_hex") if isinstance(d, dict) else None
if not isinstance(p, str):
    sys.exit("no payload_hex: %r" % d)
if not re.fullmatch(r"[0-9a-f]{468}", p):
    sys.exit("payload_hex is not 468 lowercase hex chars (len %d)" % len(p))
print(p)'
}
P1=$(produce obj "$REQ1") || fail "produce_auth (args object) failed: $(cat "$RUN/produce/obj.response.json" 2>/dev/null)"
poc_say "payload (args object): ${#P1} hex"
P2=$(produce str "$REQ2") || fail "produce_auth (args string) failed: $(cat "$RUN/produce/str.response.json" 2>/dev/null)"
poc_say "payload (args string): ${#P2} hex"
[ "${P1:0:212}" = "${P2:0:212}" ] || fail "args object vs string: payload prefix (106 B) differs"
[ "$P1" = "$P2" ] && SIG_SAME=true || SIG_SAME=false
poc_say "args object/string: first 106 B identical; signature identical=$SIG_SAME"

# ---------------------------------------------------------------- 8. verify
step verify
# vrun <tag> <payload> <idc> -> sets VRC; JSON in $RUN/produce/verify.<tag>.json
vrun() {
    VRC=0
    "$VERIFY_BIN" --payload-hex "$2" --id-commitment-hex "$3" --audience "$POC_AUDIENCE" --expect-k "$POC_K" \
        > "$RUN/produce/verify.$1.json" 2> "$RUN/produce/verify.$1.err" || VRC=$?
}
vrun pos1 "$P1" "$IDC"; [ "$VRC" = 0 ] || fail "verify P1 exit $VRC: $(cat "$RUN/produce/verify.pos1.json" "$RUN/produce/verify.pos1.err")"
vrun pos2 "$P2" "$IDC"; [ "$VRC" = 0 ] || fail "verify P2 exit $VRC: $(cat "$RUN/produce/verify.pos2.json" "$RUN/produce/verify.pos2.err")"
IDC_BAD=$(openssl rand -hex 32)
vrun neg "$P1" "$IDC_BAD"; NEG_RC=$VRC
python3 -I - "$RUN/produce" "$B" "$N" "$POC_RATE_MAX" "$POC_K" "$NEG_RC" <<'EOF' || fail "verify assertions"
import json, sys
d, b, n, rm, k, neg_rc = sys.argv[1:]
errs = []
for tag in ("pos1", "pos2"):
    v = json.load(open("%s/verify.%s.json" % (d, tag)))
    for key, want in (("sig_valid", True), ("claim_block_id", b), ("pow_nullifier", n),
                      ("rate_max", int(rm)), ("k", k), ("expect_k_match", True)):
        got = v.get(key)
        if isinstance(got, str) and isinstance(want, str):
            got = got.lower()
        if got != want:
            errs.append("%s: %s=%r want %r" % (tag, key, got, want))
neg = json.load(open("%s/verify.neg.json" % d))
if int(neg_rc) != 1:
    errs.append("negative: exit %s want 1" % neg_rc)
if neg.get("sig_valid") is not False:
    errs.append("negative: sig_valid=%r want false" % neg.get("sig_valid"))
if errs:
    sys.exit("\n".join(errs))
EOF
poc_say "verify: positive ok (x2), negative rc=$NEG_RC sig_valid=false"

mkdir -p "$(dirname "$GOLDEN")"
CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 -I - "$GOLDEN" "$REAL_FIX" "$P1" "$IDC" "$POC_AUDIENCE" "$POC_K" "$B" "$S" "$N" "$CTX" "$POC_RATE_MAX" \
    "$NODE_REV" "$CAPTURED_AT" "$POC_ALLOW_UNFINAL" <<'EOF' || fail "writing fixtures"
import json, sys
golden, real, p, idc, aud, k, b, s, n, tx, rm, rev, at, unf = sys.argv[1:]
def dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")
dump(golden, {"payload_hex": p, "id_commitment_hex": idc, "audience": aud})
if unf != "1":
    sig = p[-256:]
    dump(real + "/sign_zk.json", {"sig": {"pi_a": sig[:64], "pi_b": sig[64:192], "pi_c": sig[192:]}})
    dump(real + "/meta.json", {"k": k, "claim_block_id": b, "slot": int(s), "pow_nullifier": n, "tx_hash": tx,
                               "id_commitment_hex": idc, "audience": aud, "rate_max": int(rm), "payload_hex": p,
                               "node_rev": rev, "captured_at": at})
EOF
poc_say "wrote $GOLDEN"
[ "$POC_ALLOW_UNFINAL" = 1 ] || poc_say "wrote $REAL_FIX/{sign_zk,meta}.json"

# ---------------------------------------------------------------- 9. summary
step summary
TIMINGS="${TIMINGS}total=$(( $(date +%s) - T_ALL ))"
python3 -I - "$RUN/summary.json" "$POC_K" "$B" "$S" "$N" "$CTX" "$TX" "$UPK" "$AUTO" "$P1" "$IDC" "$POC_AUDIENCE" \
    "$POC_RATE_MAX" "$RUN/produce" "$NEG_RC" "$SIG_SAME" "$TIMINGS" "$GOLDEN" "$REAL_FIX" <<'EOF'
import json, sys
(out, k, b, s, n, ctx, tx, upk, auto, p, idc, aud, rm, pd, neg_rc, sig_same, timings, golden, real) = sys.argv[1:]
pos = json.load(open(pd + "/verify.pos1.json"))
neg = json.load(open(pd + "/verify.neg.json"))
summary = {
    "k": k, "claim_block_id": b, "slot": int(s), "pow_nullifier": n,
    "claim_tx_hash": ctx, "pow_claim_returned_tx": tx or None, "auto_claim_race": auto == "true",
    "utxo_pk": upk, "id_commitment_hex": idc, "audience": aud, "rate_max": int(rm),
    "payload_len_bytes": len(p) // 2, "payload_hex": p,
    "sig_valid": pos.get("sig_valid"), "expect_k_match": pos.get("expect_k_match"),
    "args_string_same_signature": sig_same == "true",
    "negative_check": {"exit": int(neg_rc), "sig_valid": neg.get("sig_valid")},
    "timings_s": {kv.split("=")[0]: int(kv.split("=")[1]) for kv in timings.split()},
    "golden": golden, "real_fixtures": real,
}
with open(out, "w") as f:
    json.dump(summary, f, indent=1)
    f.write("\n")
print("==== PoW-claim PoC summary ====")
print(json.dumps(summary, indent=1))
EOF
STEP=done
poc_say "OK — summary at $RUN/summary.json"
