#!/usr/bin/env python3
"""Run conformance/qr/vectors.json against the Python implementation.

    python3 conformance/run_vectors_qr.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "implementations", "python"))

import qr  # noqa: E402


def check(v, r):
    """Compare a verdict with a vector's expectation. Returns a list of mismatches."""
    e, bad = v["expect"], []
    if r["ok"] != e["ok"]:
        bad.append(f"ok is {r['ok']}, want {e['ok']}")
    if r["trusted"] != e["trusted"]:
        bad.append(f"trusted is {r['trusted']}, want {e['trusted']}")
    if "error" in e and not any(e["error"] in x for x in r["errors"]):
        bad.append(f"no error contains {e['error']!r}: {r['errors']}")
    if "untrusted" in e and not any(e["untrusted"] in x for x in r["untrusted"]):
        bad.append(f"no untrusted reason contains {e['untrusted']!r}: {r['untrusted']}")
    for n in e.get("notes", []):
        if not any(n in x for x in r.get("notes", [])):
            bad.append(f"no note contains {n!r}: {r.get('notes')}")
    for k in ("endpoints", "needs_confirmation", "key_changes"):
        if k in e and r.get(k) != e[k]:
            bad.append(f"{k} is {r.get(k)}, want {e[k]}")
    return bad


def run(v):
    kind = v["kind"]
    if kind == "reference":
        return qr.verify_reference(v["subject"], trust=v["trust"], now=v["now"])
    if kind == "resolution-envelope":
        return qr.check_resolution_envelope(v["res"], v["ref"], trust=v["trust"], now=v["now"], fetched_from=v["fetched_from"])
    return qr.verify_resolution(v["res"], v["ref"], trust=v["trust"], now=v["now"], fetched_from=v["fetched_from"], pin=v.get("pin"))


def main():
    vectors = json.load(open(os.path.join(HERE, "qr", "vectors.json")))["vectors"]
    failures = 0
    for v in vectors:
        bad = check(v, run(v))
        failures += bool(bad)
        print(f"{'ok ' if not bad else 'BAD'} {v['name']:52} {'; '.join(bad)[:150]}")
    print()
    if failures:
        print(f"FAILED: {failures} vector(s) disagree with the expected verdict")
        return 1
    kinds = {}
    for v in vectors:
        kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
    print(f"PASS: {len(vectors)}/{len(vectors)} vectors {kinds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
