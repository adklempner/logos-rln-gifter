#!/usr/bin/env python3
"""Patch the logos-blockchain standalone node config + deployment (rc.5) for the PoC.

Exact-substring replacements, each asserted to match exactly once (exit 2
otherwise). No YAML library on purpose: the files carry !Zk/!Ed25519 tags and
the node loads them with OnUnknownKeys::Fail, so a re-serialisation could only
hurt.

Deployment: cucumber fast-mining overrides (tests/cucumber_tests/features/
pow_mining.feature @ logos-blockchain 2c652646). Note `target_claims_per_block`
and `target_claim_per_block` are different keys; only the former is patched.

Deviation from cucumber: `rate_num` 1 -> 3000. The standalone genesis time is
far in the past, so the node starts thousands of epochs in and the boundary
recomputes the per-claim reward as pool*rate_num/(rate_den*target_claim_per_block
*expected_blocks_per_epoch) = pool*rate_num/(10*1*300) (ledger/src/mantle/pow/mod.rs
compute_epoch_pow_reward). With rate_num 1 that is 333 for a 1e6 pool: the claim
batch takes ~134 tickets, some transfer change output comes out 0 after the fee,
and Blend drops the tx ("Transfer verification error: Outputs error: Zero value
note"). rate_num 3000 makes epoch_reward == pool, i.e. exactly one claim per
fresh state, like cucumber's pool == epoch_reward_genesis.

Node config: HTTP port, p2p swarm port (3000 is not genesis-bound; 3400 blend is), absolute db/state/log dirs under the run dir, and one
auto-claim target (must be in wallet.known_keys or the node refuses to start).

Usage:
  python3 -I node_config.py --node-in A --dep-in B --node-out C --dep-out D \
      --run-dir R --http-port P --claim-key K [--reward-pool N] [--rate-num R]
"""
import argparse
import os
import re
import sys

DEFAULT_K = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07"


def patch(text, pairs, what):
    for old, new in pairs:
        n = text.count(old)
        if n != 1:
            sys.stderr.write("node_config: %s: pattern matched %d times (want 1): %r\n" % (what, n, old))
            sys.exit(2)
        text = text.replace(old, new)
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-in", required=True)
    ap.add_argument("--dep-in", required=True)
    ap.add_argument("--node-out", required=True)
    ap.add_argument("--dep-out", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--http-port", type=int, required=True)
    ap.add_argument("--p2p-port", type=int, default=3000)
    ap.add_argument("--claim-key", default=DEFAULT_K)
    ap.add_argument("--reward-pool", type=int, default=1000000)
    ap.add_argument("--rate-num", type=int, default=3000)
    a = ap.parse_args()

    k = a.claim_key.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", k):
        sys.stderr.write("node_config: --claim-key must be 64 lowercase hex chars\n")
        sys.exit(2)
    run = os.path.abspath(a.run_dir)
    node_dir = os.path.join(run, "node")
    db, state, logs = (os.path.join(node_dir, d) for d in ("db", "state", "logs"))

    with open(a.dep_in) as f:
        dep = f.read()
    dep = patch(dep, [
        ("      minimum_difficulty: 19\n", "      minimum_difficulty: 1\n"),
        ("      ema_smoothing_factor: 9\n", "      ema_smoothing_factor: 1\n"),
        ("      ema_smoothing_precision: 10\n", "      ema_smoothing_precision: 1000000000000000000\n"),
        ("      target_claims_per_block: 1\n", "      target_claims_per_block: 1000000000000000000\n"),
        ("      reward_pool_genesis: 300000000000\n", "      reward_pool_genesis: %d\n" % a.reward_pool),
        ("      epoch_reward_genesis: 100000000\n", "      epoch_reward_genesis: %d\n" % a.reward_pool),
        ("      rate_num: 1\n", "      rate_num: %d\n" % a.rate_num),
        ("  slot_activation_coeff:\n    numerator: 1\n    denominator: 20\n",
         "  slot_activation_coeff:\n    numerator: 1\n    denominator: 2\n"),
    ], "deployment")

    with open(a.node_in) as f:
        node = f.read()
    if k not in node.split("known_keys:", 1)[-1].split("voucher_master_key_id", 1)[0]:
        sys.stderr.write("node_config: claim key %s is not in wallet.known_keys\n" % k)
        sys.exit(2)
    node = patch(node, [
        ("    swarm:\n      host: 0.0.0.0\n      port: 3000\n",
         "    swarm:\n      host: 0.0.0.0\n      port: %d\n" % a.p2p_port),
        ("    listen_address: 127.0.0.1:8080\n", "    listen_address: 127.0.0.1:%d\n" % a.http_port),
        ("    folder_name: ./db\n", "    folder_name: %s\n" % db),
        ("  base_folder: ./state\n", "  base_folder: %s\n" % state),
        ("    file:\n      directory: .\n", "    file:\n      directory: %s\n" % logs),
        ("    targets: []\n",
         "    targets:\n    - public_key: %s\n      threshold: 1000000000000\n" % k),
    ], "node-config")

    for d in (db, state, logs):
        os.makedirs(d, exist_ok=True)
    for path, text in ((a.dep_out, dep), (a.node_out, node)):
        with open(path, "w") as f:
            f.write(text)
    print("node_config: wrote %s and %s" % (a.node_out, a.dep_out))


if __name__ == "__main__":
    main()
