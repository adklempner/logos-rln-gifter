#!/usr/bin/env python3
"""List PoW reward claims on a logos-blockchain node, for pinned-mode pow-claim.

Walks the chain from the tip back to --until-slot (default: 3000 slots before
the tip) and prints one JSON line per PoWRewardClaimed event: slot,
claim_block_id, tx_hash, pow_nullifier, paid_pk, final (slot <= lib_slot).
The two values a tester pins in `auth_args` are claim_block_id and
pow_nullifier. Pick your claim by its tx hash (what the claim submission /
`Claim submitted` log line reported) with --tx, or by slot: the chain's slot
is 1 s, so the slot of a block is seconds since genesis (compare with
/cryptarchia/info `slot` and the wall clock). --pk matches the paid note's
key; that is the claim address, which may not be the auto-claim target key.

    python3 -I find-claims.py --node http://127.0.0.1:18080 --until-slot 561700
    python3 -I find-claims.py --node http://127.0.0.1:18080 --tx <hex64>
"""
import argparse
import json
import sys
import urllib.error
import urllib.request


def get(node, path):
    """JSON at node+path; None on 404 (block or events not known)."""
    try:
        with urllib.request.urlopen(node + path, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", default="http://127.0.0.1:18080")
    ap.add_argument("--tx", default="", help="only the claim with this tx hash (hex)")
    ap.add_argument("--pk", default="", help="only claims whose paid note key is this (hex)")
    ap.add_argument("--until-slot", type=int, default=None, help="stop below this slot (default tip-3000)")
    a = ap.parse_args()
    info = get(a.node, "/cryptarchia/info")["cryptarchia_info"]
    until = a.until_slot if a.until_slot is not None else info["slot"] - 3000
    want_tx, want_pk = a.tx.lower(), a.pk.lower()
    bid, walked, hits = info["tip"], 0, 0
    while bid:
        blk = get(a.node, "/cryptarchia/blocks/%s" % bid)
        if blk is None:
            break
        slot = blk["header"]["slot"]
        if slot < until:
            break
        walked += 1
        for ev in get(a.node, "/cryptarchia/blocks/%s/events" % bid) or []:
            tx = ev.get("Tx") if isinstance(ev, dict) else None
            if not tx:
                continue
            c = (tx.get("payload") or {}).get("PoWRewardClaimed")
            if not c:
                continue
            txh = (tx.get("tx_hash") or "").lower()
            pk = (((c.get("utxo") or {}).get("note") or {}).get("pk") or "").lower()
            if (want_tx and txh != want_tx) or (want_pk and pk != want_pk):
                continue
            hits += 1
            print(json.dumps({"slot": slot, "claim_block_id": bid.lower(), "tx_hash": txh,
                              "pow_nullifier": (c.get("pow_nullifier") or "").lower(), "paid_pk": pk,
                              "value": ((c.get("utxo") or {}).get("note") or {}).get("value"),
                              "final": slot <= info["lib_slot"]}))
            if want_tx:
                break
        if want_tx and hits:
            break
        bid = blk["header"].get("parent_block")
    print(json.dumps({"walked_blocks": walked, "claims": hits, "tip_slot": info["slot"],
                      "lib_slot": info["lib_slot"], "until_slot": until}), file=sys.stderr)


if __name__ == "__main__":
    main()
