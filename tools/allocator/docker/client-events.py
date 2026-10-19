#!/usr/bin/env python3
"""tools/allocator/docker/client-events.py — readers over the event streams
`logosctl --json watch <module>` appends to (client-delivery.sh).

Each line the watcher writes is
  {"data":{"arg0":…,"arg1":…},"event":"…","module":"…","timestamp":"…"}
mixed with whatever the CLI prints on stderr (skipped: not JSON). A line
without its trailing newline is one the watcher is still writing: it is left
for the next read.

  wait <events> <cursor> <start> <regex> <timeout_s> [substring]
      Poll every 2 s from the cursor's byte offset (the start offset when the
      cursor file is missing) for the first event whose name FULLY matches
      <regex> and whose raw line contains [substring]. Prints that event as
      compact JSON and advances the cursor past it (a match is consumed, as in
      the e2e harness's node_wait_event). Exit 1 on timeout.

  new <events> <cursor> <start>
      Print every complete event since the cursor, one summary line each, and
      advance the cursor:
        RECEIVED hash=… topic=… source=… payload=…   messageReceived
        VALIDATE req=…                               rln validate-proof request
        EVENT <name> <data>                          anything else
"""
import base64
import json
import os
import re
import sys
import time


def read_pos(cursor, start):
    for path in (cursor, start):
        try:
            with open(path) as f:
                return int(f.read().strip() or 0)
        except (OSError, ValueError):
            continue
    return 0


def write_pos(cursor, pos):
    tmp = cursor + ".tmp"
    with open(tmp, "w") as f:
        f.write("%d\n" % pos)
    os.replace(tmp, cursor)


def events(path, pos):
    """Yield (offset after line, event dict) for complete JSON lines."""
    try:
        f = open(path, "rb")
    except OSError:
        return
    with f:
        try:
            size = os.fstat(f.fileno()).st_size
        except OSError:
            size = 0
        # A truncated stream (volume reset) restarts from the top.
        f.seek(pos if pos <= size else 0)
        while True:
            raw = f.readline()
            if not raw or not raw.endswith(b"\n"):
                return
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("{"):
                yield f.tell(), None, line
                continue
            try:
                d = json.loads(line)
            except Exception:
                yield f.tell(), None, line
                continue
            yield f.tell(), d if isinstance(d, dict) else None, line


def cmd_wait(path, cursor, start, regex, timeout, substring):
    pat = re.compile(regex)
    end = time.time() + timeout
    while True:
        pos = read_pos(cursor, start)
        for off, d, line in events(path, pos):
            if d is None:
                continue
            if not pat.fullmatch(d.get("event") or ""):
                continue
            if substring and substring not in line:
                continue
            write_pos(cursor, off)
            print(json.dumps(d, separators=(",", ":")))
            return 0
        if time.time() >= end:
            return 1
        time.sleep(2)


def payload_text(v):
    """messageReceived's payload: {"_bytes": base64url}, base64, or a byte list."""
    b = None
    if isinstance(v, dict) and "_bytes" in v:
        s = str(v["_bytes"])
        try:
            b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        except Exception:
            return s
    elif isinstance(v, list):
        try:
            b = bytes(v)
        except Exception:
            return json.dumps(v)
    elif isinstance(v, str):
        try:
            b = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
        except Exception:
            return v
    else:
        return json.dumps(v)
    try:
        t = b.decode("utf-8")
        if t.isprintable():
            return t[:200]
    except UnicodeDecodeError:
        pass
    return "0x" + b.hex()[:400]


def summary(d):
    name = d.get("event") or ""
    data = d.get("data") or {}
    if not isinstance(data, dict):
        data = {"arg0": data}
    if name == "messageReceived":
        return "RECEIVED hash=%s topic=%s source=%s payload=%s" % (
            data.get("arg0", ""), data.get("arg1", ""), data.get("arg3", ""),
            payload_text(data.get("arg2", "")))
    if re.fullmatch(r"(rlnValidateProofRequest|dispatchRlnValidateProofRequestEvent)", name):
        return "VALIDATE req=%s" % data.get("arg0", "")
    s = json.dumps(data, separators=(",", ":"))
    return "EVENT %s %s" % (name, s if len(s) <= 300 else s[:300] + "…")


def cmd_new(path, cursor, start):
    pos = read_pos(cursor, start)
    last = pos
    for off, d, _line in events(path, pos):
        last = off
        if d is not None:
            print(summary(d))
    if last != pos:
        write_pos(cursor, last)
    return 0


def main(argv):
    if len(argv) >= 7 and argv[1] == "wait":
        return cmd_wait(argv[2], argv[3], argv[4], argv[5], float(argv[6]),
                        argv[7] if len(argv) > 7 else "")
    if len(argv) == 5 and argv[1] == "new":
        return cmd_new(argv[2], argv[3], argv[4])
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
