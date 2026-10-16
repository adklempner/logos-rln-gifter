#!/usr/bin/env python3
"""nodeq.py — tiny stdlib client for the logos-blockchain node HTTP API (PoC driver).

Subcommands (all take --node-url, default http://127.0.0.1:18080):
  info                                   print /cryptarchia/info
  wait-claimable --min N --timeout S     poll /pow/rewards/claimable until claimable_tickets >= N
  find-claim [--tx-hash H] --timeout S [--depth 60]
                                         walk tip -> parents, find a PoWRewardClaimed tx event
  wait-lib --slot S --timeout T          poll until cryptarchia_info.lib_slot >= S
  capture --block B --slot S --out DIR   write a FakeNode::from_dir fixture set
Run with `python3 -I`.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


class NodeError(Exception):
    pass


def get(url, path, timeout=10):
    try:
        with urllib.request.urlopen(url + path, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        msg = body
        try:
            d = json.loads(body)
            if isinstance(d, dict) and ("code" in d or "message" in d):
                msg = "code=%s message=%s" % (d.get("code"), d.get("message"))
        except Exception:
            pass
        raise NodeError("GET %s -> HTTP %d: %s" % (path, e.code, msg))
    except (urllib.error.URLError, OSError) as e:
        raise NodeError("GET %s -> %s" % (path, e))
    try:
        return json.loads(raw)
    except Exception:
        raise NodeError("GET %s -> non-JSON body: %r" % (path, raw[:200]))


def warn(msg):
    sys.stderr.write("nodeq: %s\n" % msg)


def cinfo(url):
    d = get(url, "/cryptarchia/info")
    ci = d.get("cryptarchia_info") if isinstance(d, dict) else None
    if not isinstance(ci, dict):
        raise NodeError("/cryptarchia/info without cryptarchia_info: %r" % d)
    return d, ci


def cmd_info(a):
    d, _ = cinfo(a.node_url)
    print(json.dumps(d))
    return 0


def cmd_wait_claimable(a):
    t0 = time.time()
    c = 0
    while time.time() - t0 < a.timeout:
        try:
            d = get(a.node_url, "/pow/rewards/claimable")
            c = int(d.get("claimable_tickets") or 0)
            if c >= a.min:
                print(c)
                return 0
        except NodeError as e:
            warn(str(e))
        time.sleep(1)
    warn("timeout: claimable_tickets=%d < %d after %ds" % (c, a.min, a.timeout))
    print(c)
    return 1


def claim_events(events):
    for e in events if isinstance(events, list) else []:
        tx = e.get("Tx") if isinstance(e, dict) else None
        if not isinstance(tx, dict):
            continue
        pl = tx.get("payload") or {}
        if isinstance(pl, dict) and "PoWRewardClaimed" in pl:
            yield tx, pl["PoWRewardClaimed"]


def cmd_find_claim(a):
    want = a.tx_hash.lower() if a.tx_hash else None
    t0 = time.time()
    seen = {}  # block id -> (block, [(tx, claim)])
    other = None
    while time.time() - t0 < a.timeout:
        try:
            _, ci = cinfo(a.node_url)
            bid = ci.get("tip")
            for _ in range(a.depth):
                if not bid:
                    break
                bid = bid.lower()
                if bid not in seen:
                    try:
                        blk = get(a.node_url, "/cryptarchia/blocks/%s" % bid)
                    except NodeError as e:
                        if "HTTP 404" in str(e):  # genesis (and pruned blocks) are not served
                            break
                        raise
                    if blk is None:
                        break
                    ev = get(a.node_url, "/cryptarchia/blocks/%s/events" % bid)
                    seen[bid] = (blk, list(claim_events(ev)))
                blk, claims = seen[bid]
                for tx, cl in claims:
                    hit = {
                        "block_id": bid,
                        "slot": blk.get("header", {}).get("slot"),
                        "tx_hash": (tx.get("tx_hash") or "").lower(),
                        "pow_nullifier": (cl.get("pow_nullifier") or "").lower(),
                        "utxo_pk": ((cl.get("utxo") or {}).get("note") or {}).get("pk"),
                        "elapsed_s": round(time.time() - t0, 1),
                    }
                    if want is None or hit["tx_hash"] == want:
                        hit["auto_claim"] = False
                        print(json.dumps(hit))
                        return 0
                    if other is None:
                        other = hit
                bid = blk.get("header", {}).get("parent_block")
        except NodeError as e:
            warn(str(e))
        if other is not None and time.time() - t0 >= a.timeout / 2.0:
            warn("auto-claim spent the ticket: found claim tx %s, not %s" % (other["tx_hash"], want))
            other["auto_claim"] = True
            print(json.dumps(other))
            return 0
        time.sleep(2)
    if other is not None:
        warn("auto-claim spent the ticket: found claim tx %s, not %s" % (other["tx_hash"], want))
        other["auto_claim"] = True
        print(json.dumps(other))
        return 0
    warn("no PoWRewardClaimed%s within %ds (walked %d blocks)"
         % (" for tx " + want if want else "", a.timeout, len(seen)))
    return 1


def cmd_wait_lib(a):
    t0 = time.time()
    ls = None
    while time.time() - t0 < a.timeout:
        try:
            _, ci = cinfo(a.node_url)
            ls = ci.get("lib_slot")
            if isinstance(ls, int) and ls >= a.slot:
                print(json.dumps({"lib_slot": ls, "height": ci.get("height"),
                                  "elapsed_s": round(time.time() - t0, 1)}))
                return 0
        except NodeError as e:
            warn(str(e))
        time.sleep(2)
    warn("timeout: lib_slot=%s < %d after %ds" % (ls, a.slot, a.timeout))
    return 1


def dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=False)
        f.write("\n")


def cmd_capture(a):
    b = a.block.lower()
    os.makedirs(a.out, exist_ok=True)
    pow_status = get(a.node_url, "/pow/status")
    info, ci = cinfo(a.node_url)
    blk = get(a.node_url, "/cryptarchia/blocks/%s" % b)
    if blk is None:
        raise NodeError("block %s not found" % b)
    slot = blk.get("header", {}).get("slot")
    if slot != a.slot:
        raise NodeError("block %s has slot %r, expected %d" % (b, slot, a.slot))
    ev = get(a.node_url, "/cryptarchia/blocks/%s/events" % b)
    imm = get(a.node_url, "/cryptarchia/blocks?slot_from=%d&slot_to=%d" % (a.slot, a.slot))
    if not isinstance(imm, list):
        raise NodeError("immutable range is not an array: %r" % imm)
    ids = [str(x.get("header", {}).get("id", "")).lower() for x in imm if isinstance(x, dict)]
    if b not in ids:
        raise NodeError("immutable range %d..%d does not contain %s (got %s; lib_slot=%s)"
                        % (a.slot, a.slot, b, ids, ci.get("lib_slot")))
    dump(os.path.join(a.out, "pow_status.json"), pow_status)
    dump(os.path.join(a.out, "info.json"), info)
    dump(os.path.join(a.out, "block_%s.json" % b), blk)
    dump(os.path.join(a.out, "events_%s.json" % b), ev)
    dump(os.path.join(a.out, "immutable.json"), imm)
    dump(os.path.join(a.out, "immutable_%d_%d.json" % (a.slot, a.slot)), imm)
    print(json.dumps({"out": a.out, "block_id": b, "slot": a.slot, "lib_slot": ci.get("lib_slot"),
                      "events": len(ev) if isinstance(ev, list) else None}))
    return 0


def _peer_ids(lst):
    out = []
    for x in lst if isinstance(lst, list) else []:
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            v = x.get("peer_id") or x.get("id") or x.get("peerId")
            if v:
                out.append(str(v))
    return out


def cmd_netinfo(a):
    d = get(a.node_url, "/network/info")
    cp = _peer_ids(d.get("connected_peers"))
    print(json.dumps({"peer_id": d.get("peer_id"), "listen_addresses": d.get("listen_addresses"),
                      "n_peers": d.get("n_peers"), "connected_peers": cp,
                      "n_connections": d.get("n_connections")}))
    return 0


def cmd_wait_online(a):
    t0 = time.time()
    ci = {}
    while time.time() - t0 < a.timeout:
        try:
            _, ci = cinfo(a.node_url)
            ls = ci.get("lib_slot")
            if ci.get("state") == "Online" and isinstance(ls, int) and ls > a.min_lib_slot:
                print(json.dumps({"elapsed_s": round(time.time() - t0, 1), "height": ci.get("height"),
                                  "lib_slot": ls, "state": ci.get("state")}))
                return 0
        except NodeError as e:
            warn(str(e))
        time.sleep(2)
    warn("timeout: state=%s lib_slot=%s height=%s after %ds"
         % (ci.get("state"), ci.get("lib_slot"), ci.get("height"), a.timeout))
    return 1


def _imm_ids(url, a, b):
    d = get(url, "/cryptarchia/blocks?slot_from=%d&slot_to=%d" % (a, b), timeout=60)
    if not isinstance(d, list):
        raise NodeError("immutable range is not an array: %r" % (d,))
    return [str(x.get("header", {}).get("id", "")).lower() for x in d if isinstance(x, dict)]


def cmd_same_immutable(a):
    mine = _imm_ids(a.node_url, a.slot_from, a.slot_to)
    other = _imm_ids(a.other_url.rstrip("/"), a.slot_from, a.slot_to)
    missing = [x for x in mine if x not in set(other)]
    extra = [x for x in other if x not in set(mine)]
    print(json.dumps({"equal": mine == other, "n_self": len(mine), "n_other": len(other),
                      "missing": missing, "extra": extra}))
    return 0 if mine == other else 1


def main():
    p = argparse.ArgumentParser(description="logos-blockchain node HTTP queries for the PoW-claim PoC")
    p.add_argument("--node-url", default="http://127.0.0.1:18080")
    sp = p.add_subparsers(dest="cmd")
    sp.add_parser("info")
    s = sp.add_parser("wait-claimable")
    s.add_argument("--min", type=int, default=1)
    s.add_argument("--timeout", type=int, default=120)
    s = sp.add_parser("find-claim")
    s.add_argument("--tx-hash")
    s.add_argument("--timeout", type=int, default=180)
    s.add_argument("--depth", type=int, default=60)
    s = sp.add_parser("wait-lib")
    s.add_argument("--slot", type=int, required=True)
    s.add_argument("--timeout", type=int, default=600)
    s = sp.add_parser("capture")
    s.add_argument("--block", required=True)
    s.add_argument("--slot", type=int, required=True)
    s.add_argument("--out", required=True)
    sp.add_parser("netinfo")
    s = sp.add_parser("wait-online")
    s.add_argument("--timeout", type=int, default=300)
    s.add_argument("--min-lib-slot", type=int, default=-1)
    s = sp.add_parser("same-immutable")
    s.add_argument("--other-url", required=True)
    s.add_argument("--slot-from", type=int, required=True)
    s.add_argument("--slot-to", type=int, required=True)
    a = p.parse_args()
    a.node_url = a.node_url.rstrip("/")
    fn = {"info": cmd_info, "wait-claimable": cmd_wait_claimable, "find-claim": cmd_find_claim,
          "wait-lib": cmd_wait_lib, "capture": cmd_capture,
          "netinfo": cmd_netinfo, "wait-online": cmd_wait_online, "same-immutable": cmd_same_immutable}.get(a.cmd)
    if fn is None:
        p.print_help(sys.stderr)
        return 2
    try:
        return fn(a)
    except NodeError as e:
        warn("error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
