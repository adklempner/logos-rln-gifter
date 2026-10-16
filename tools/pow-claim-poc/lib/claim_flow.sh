# shellcheck shell=bash
# tools/pow-claim-poc/lib/claim_flow.sh — mine / claim / produce on node 1, as
# functions over an explicit run dir (copies of run.sh steps 3-5 and its produce call).
# Source AFTER lib/logoscore.sh. Never writes fixture dirs.
#
# Needs: NODEQ (path to lib/nodeq.py; defaults next to this file).

CF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODEQ="${NODEQ:-$CF_DIR/nodeq.py}"

_cf_nq() { local url="$1"; shift; python3 -I "$NODEQ" --node-url "$url" "$@"; }
_cf_get() { python3 -I -c "import json,sys; d=json.load(sys.stdin); v=$1; print(v if isinstance(v,str) else json.dumps(v))"; }

# Usage: cf_mine <url> <run_a>   (start mining until >= 1 claimable ticket, then stop)
cf_mine() {
    local url="$1" run="$2" r claimable
    r=$(POC_RUN_DIR="$run" lc_call blockchain_module pow_start_mining || true)
    poc_say "pow_start_mining -> $r"
    claimable=$(_cf_nq "$url" wait-claimable --min 1 --timeout 120) || {
        POC_RUN_DIR="$run" lc_call blockchain_module pow_stop_mining >/dev/null || true
        poc_say "no claimable ticket within 120 s"
        return 1
    }
    r=$(POC_RUN_DIR="$run" lc_call blockchain_module pow_stop_mining || true)
    poc_say "claimable=$claimable; pow_stop_mining -> $r"
}

# Usage: cf_claim <url> <run_a> <K>
# Exports CLAIM_B CLAIM_S CLAIM_N CLAIM_TX CLAIM_UPK CLAIM_AUTO; writes <run_a>/claim.json.
cf_claim() {
    local url="$1" run="$2" k="$3" out tx claim
    out=$(POC_RUN_DIR="$run" CALL_TIMEOUT=120 lc_call blockchain_module pow_claim "$(POC_RUN_DIR="$run" argfile k "$k")" || true)
    printf '%s\n' "$out" > "$run/pow_claim.out.json"
    tx=$(printf '%s' "$out" | jres | jval 2>/dev/null || true)
    case "$tx" in
        [0-9a-f]*) [ "${#tx}" = 64 ] || tx="" ;;
        *) tx="" ;;
    esac
    if [ -z "$tx" ]; then
        poc_say "pow_claim via module gave '$out'; falling back to POST /pow/claim"
        out=$(curl -s -X POST -H 'content-type: application/json' -d "{\"claim_address\":\"$k\"}" "$url/pow/claim" || true)
        printf '%s\n' "$out" > "$run/pow_claim.http.json"
        tx=$(printf '%s' "$out" | python3 -I -c '
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
    poc_say "claim tx ${tx:-<unknown>}"
    if [ -n "$tx" ]; then
        claim=$(_cf_nq "$url" find-claim --tx-hash "$tx" --timeout 180) || { poc_say "claim tx $tx not found within 180 s"; return 1; }
    else
        claim=$(_cf_nq "$url" find-claim --timeout 180) || { poc_say "no claim event within 180 s"; return 1; }
    fi
    printf '%s\n' "$claim" > "$run/claim.json"
    CLAIM_B=$(printf '%s' "$claim" | _cf_get 'd["block_id"]')
    CLAIM_S=$(printf '%s' "$claim" | _cf_get 'd["slot"]')
    CLAIM_N=$(printf '%s' "$claim" | _cf_get 'd["pow_nullifier"]')
    CLAIM_TX=$(printf '%s' "$claim" | _cf_get 'd["tx_hash"]')
    CLAIM_UPK=$(printf '%s' "$claim" | _cf_get 'd["utxo_pk"]')
    CLAIM_AUTO=$(printf '%s' "$claim" | _cf_get 'd.get("auto_claim", False)')
    export CLAIM_B CLAIM_S CLAIM_N CLAIM_TX CLAIM_UPK CLAIM_AUTO
    poc_say "claim: block=$CLAIM_B slot=$CLAIM_S nullifier=$CLAIM_N tx=$CLAIM_TX utxo_pk=$CLAIM_UPK auto_claim=$CLAIM_AUTO"
}

# Usage: cf_produce <run_a> <idc> <audience> <rate_max> <tag> [extra_args_json]
# produce_auth on pow_claim_capture_module (node_url :18080, allow_unfinal false);
# saves <run_a>/produce/<tag>.json (+ .request/.envelope); echoes payload_hex (468 hex).
cf_produce() {
    local run="$1" idc="$2" aud="$3" rm="$4" tag="$5" extra="${6:-}" req env res
    mkdir -p "$run/produce"
    req=$(python3 -I -c '
import json, sys
idc, aud, rm, extra = sys.argv[1:5]
args = {"node_url": "http://127.0.0.1:18080", "audience": aud, "rate_max": int(rm), "allow_unfinal": False}
if extra:
    args.update(json.loads(extra))
print(json.dumps({"auth_type": "pow-claim", "id_commitment_hex": idc, "args": args}, separators=(",", ":")))' \
        "$idc" "$aud" "$rm" "$extra")
    printf '%s\n' "$req" > "$run/produce/$tag.request.json"
    env=$(POC_RUN_DIR="$run" CALL_TIMEOUT=180 lc_call pow_claim_capture_module produce_auth "$req" || true)
    printf '%s\n' "$env" > "$run/produce/$tag.envelope.json"
    res=$(printf '%s' "$env" | jres)
    printf '%s\n' "$res" > "$run/produce/$tag.json"
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
