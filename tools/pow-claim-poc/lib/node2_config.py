#!/usr/bin/env python3
"""Patch a blockchain_module-generated user_config.yaml (node 2, follower) for the PoC.

Exact-substring patch (no YAML library, same rationale as node_config.py), asserted
to match exactly once (exit 2 otherwise):
  prolonged_bootstrap_period '3600.000000000' -> '5.000000000'
Asserts (exit 2 on failure):
  - initial_peers lists MADDR, and the IBD peers list contains MADDR's /p2p/ PeerId
  - api listen_address == --http
Prints a JSON summary (stdout) of the patch and of defaults left untouched
(grace_period, mining, auto-claim targets, blend listening address).

Usage: python3 -I node2_config.py --in F --out G --initial-peer MADDR [--http 127.0.0.1:18081]
"""
import argparse
import json
import re
import sys

BOOT_OLD = "      prolonged_bootstrap_period: '3600.000000000'\n"
BOOT_NEW = "      prolonged_bootstrap_period: '5.000000000'\n"


def die(msg):
    sys.stderr.write("node2_config: %s\n" % msg)
    sys.exit(2)


def once(text, pat, what):
    n = text.count(pat)
    if n != 1:
        die("%s: pattern matched %d times (want 1): %r" % (what, n, pat))


def first(text, rx, what):
    m = re.search(rx, text, re.M)
    if not m:
        die("%s: not found (%s)" % (what, rx))
    return m.group(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--initial-peer", required=True)
    ap.add_argument("--http", default="127.0.0.1:18081")
    a = ap.parse_args()

    m = re.search(r"/p2p/([A-Za-z0-9]+)$", a.initial_peer)
    if not m:
        die("--initial-peer must end in /p2p/<PeerId>: %r" % a.initial_peer)
    peer_id = m.group(1)

    with open(a.inp) as f:
        text = f.read()

    once(text, "    initial_peers:\n    - %s\n" % a.initial_peer, "initial_peers")
    once(text, "        peers:\n        - %s\n" % peer_id, "ibd peers")
    once(text, "    listen_address: %s\n" % a.http, "api listen_address")
    once(text, BOOT_OLD, "bootstrap period")
    text = text.replace(BOOT_OLD, BOOT_NEW)

    summary = {
        "patched": [{"old": BOOT_OLD.strip(), "new": BOOT_NEW.strip()}],
        "asserted": {"initial_peers": a.initial_peer, "ibd_peers": [peer_id], "http": a.http},
        "defaults": {
            "grace_period": first(text, r"^\s+grace_period: (.+)$", "grace_period"),
            "state_recording_interval": first(text, r"^\s+state_recording_interval: (.+)$", "interval"),
            "mining_max_threads": first(text, r"^\s+max_threads: (.+)$", "max_threads"),
            "mining_max_tickets_per_block": first(text, r"^\s+max_tickets_per_block: (.+)$", "max_tickets"),
            "auto_claim_public_key": first(text, r"^\s+- public_key: (.+)$", "auto_claim key"),
            "auto_claim_threshold": first(text, r"^\s+threshold: (\d+)$", "auto_claim threshold"),
            "blend_listening_address": first(text, r"^\s+listening_address: (.+)$", "blend addr"),
        },
    }
    with open(a.out, "w") as f:
        f.write(text)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
