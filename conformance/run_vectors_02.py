#!/usr/bin/env python3
"""Run conformance/v0.2/vectors.json against the Python implementation.

    python3 conformance/run_vectors_02.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "implementations", "python"))

import sid02  # noqa: E402

V = os.path.join(HERE, "v0.2")


def main():
    trust = json.load(open(os.path.join(V, "trust.json")))
    vectors = json.load(open(os.path.join(V, "vectors.json")))["vectors"]
    failures = 0
    for v in vectors:
        anchors = trust if v["trust"] is True else (None if v["trust"] is False else v["trust"])
        if v["kind"] == "sid":
            r = sid02.verify_sid(v["cert"], trust=anchors, previous=v.get("previous"),
                                 head=v.get("head"), legacy=v.get("legacy"))
        else:
            r = sid02.verify_runtime(v["stmt"], v["cert"], trust=anchors, now=v.get("now"), head=v.get("head"))
        e = v["expect"]
        good = r["ok"] == e["ok"] and r["trusted"] == e["trusted"]
        if "error" in e:
            good = good and any(e["error"] in x for x in r["errors"])
        if "untrusted" in e:
            good = good and any(e["untrusted"] in x for x in r["untrusted"])
        if "migration" in e:
            good = good and r.get("migration") == e["migration"]
        if not good:
            failures += 1
        note = (r["errors"] or r["untrusted"] or ["—"])[0]
        print(f"{'ok ' if good else 'BAD'} {v['name']:44} ok={str(r['ok']):5} trusted={str(r['trusted']):5} {note[:70]}")
    print()
    if failures:
        print(f"FAILED: {failures} vector(s) disagree with the expected verdict")
        return 1
    print(f"PASS: {len(vectors)}/{len(vectors)} vectors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
