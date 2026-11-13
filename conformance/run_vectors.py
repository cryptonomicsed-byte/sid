#!/usr/bin/env python3
"""Run conformance/vectors.json against the Python implementation.

The TypeScript test suite runs the same file against `verifySid`. If the two
disagree on any vector, one of them is wrong — that is the whole point.

    python3 conformance/run_vectors.py
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "implementations", "python"))

import sid  # noqa: E402

BASES = {
    "minimal": json.load(open(os.path.join(HERE, "fixtures", "minimal-sid.json"))),
    "full": json.load(open(os.path.join(HERE, "fixtures", "full-sid.json"))),
}


def apply_set(cert, path, value):
    node = cert
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def main():
    vectors = json.load(open(os.path.join(HERE, "vectors.json")))["vectors"]
    failures = 0
    print(f"{'vector':30} {'ok':>6}  {'errors'}")
    for v in vectors:
        cert = copy.deepcopy(BASES[v["base"]])
        for path, value in [(s[0:-1], s[-1]) for s in v["set"]]:
            apply_set(cert, path, value)
        if v["restamp"]:
            cert = sid._finalize(cert)
        r = sid.verify_sid(cert)
        ok_expected = v["ok"]
        good = r["ok"] == ok_expected
        if ok_expected is False and "error" in v:
            good = good and any(v["error"] in e for e in r["errors"])
        if not good:
            failures += 1
        first = r["errors"][0] if r["errors"] else "—"
        print(f"{v['name']:30} {str(r['ok']):>6}  {first[:80]}")
    print()
    if failures:
        print(f"FAILED: {failures} vector(s) disagree with the expected verdict")
        return 1
    print(f"PASS: {len(vectors)}/{len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
