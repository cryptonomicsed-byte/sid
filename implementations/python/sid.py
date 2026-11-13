#!/usr/bin/env python3
"""sid/0.1 verifier — the Python reference implementation.

Mirrors `implementations/typescript/src/sid.ts` rule for rule. Both must return
the same verdict for the same certificate; `conformance/vectors.json` is the
shared proof of that.

Rules are data-only on purpose: no Odù corpus, no network, no clock. A verifier
that needs the corpus cannot check a certificate it received from someone else.

    from sid import verify_sid
    r = verify_sid(cert)            # -> {"ok": bool, "errors": [str]}
    r = verify_sid(cert, previous)  # also checks the chain link
"""
import re

from canonical import acting_hash, canonical_hash

FORMAT = "sid/0.1"
BIRTH_EVENT_KIND = 30401
ACTING_KEYS = ["identity", "capabilities", "memory", "lifecycle", "status"]
STATUSES = ["cast", "live", "suspended", "retired"]

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^sid_[a-z0-9][a-z0-9-]*$")
SECRETS = ["seed", "mnemonic", "private_key", "nsec", "secret"]


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _finalize(cert):
    """Fill only absent v1 defaults, then acting_hash, then hash."""
    c = {k: v for k, v in cert.items()}
    if c.get("version") == 1:
        c.setdefault("previous_version", None)
        if c.get("previous_hash") is None:
            c["previous_hash"] = "none"
    c["acting_hash"] = acting_hash(c)
    c["hash"] = canonical_hash(c)
    return c


def verify_sid(cert, previous=None):
    errors = []
    add = errors.append

    if not isinstance(cert, dict):
        return {"ok": False, "errors": ["not an object"]}

    if cert.get("format") != FORMAT:
        add(f"format must be {FORMAT}")
    if not isinstance(cert.get("id"), str) or not ID_RE.match(cert["id"]):
        add("id must match sid_<slug>")
    if not _is_int(cert.get("version")) or cert["version"] < 1:
        add("version must be an integer >= 1")
    if cert.get("status") not in STATUSES:
        add("status must be cast|live|suspended|retired")
    if not isinstance(cert.get("born_at"), str) or not cert["born_at"]:
        add("born_at is required")

    ident = cert.get("identity")
    if not isinstance(ident, dict):
        add("identity is required")
    else:
        if ident.get("type") != "agent":
            add('identity.type must be "agent"')
        p, s = ident.get("odu_primary"), ident.get("odu_secondary")
        if not _is_int(p) or not 0 <= p <= 255:
            add("identity.odu_primary must be 0-255")
        if not _is_int(s) or not 0 <= s <= 255:
            add("identity.odu_secondary must be 0-255")
        if _is_int(p) and _is_int(s):
            expected = (p << 8) | s
            if ident.get("odu_link") != expected:
                add(f"identity.odu_link {ident.get('odu_link')} != (odu_primary<<8|odu_secondary) {expected}")
        cal = ident.get("calabash")
        if cal is not None:
            if not isinstance(cal, dict):
                add("identity.calabash must be an object")
            else:
                if not all(_is_int(cal.get(k)) for k in ("id", "top", "bottom")):
                    add("identity.calabash id/top/bottom must be integers")
                elif (cal["id"], cal["top"], cal["bottom"]) != (
                    ident.get("odu_link"),
                    ident.get("odu_primary"),
                    ident.get("odu_secondary"),
                ):
                    add(
                        "identity.calabash {}/{}/{} disagrees with the Odu fields {}/{}/{}".format(
                            cal["id"], cal["top"], cal["bottom"],
                            ident.get("odu_link"), ident.get("odu_primary"), ident.get("odu_secondary"),
                        )
                    )
                if not isinstance(cal.get("vessel"), str) or not cal["vessel"]:
                    add("identity.calabash.vessel must name one of the 16 Action Vessels")

    h = cert.get("hash")
    if not isinstance(h, str) or not HEX64.match(h):
        add("hash must be 64-hex")
    elif canonical_hash(cert) != h:
        add("hash does not match the canonical body")
    a = cert.get("acting_hash")
    if not isinstance(a, str) or not HEX64.match(a):
        add("acting_hash must be 64-hex")
    elif acting_hash(cert) != a:
        add("acting_hash does not match the acting keys")

    if cert.get("version") == 1:
        if "previous_version" in cert and cert["previous_version"] is not None:
            add("v1 must have previous_version = null")
        if cert.get("previous_hash") not in ("none", None):
            add('v1 must have previous_hash = "none"')
    elif _is_int(cert.get("version")):
        if cert.get("previous_version") != cert["version"] - 1:
            add("previous_version must be version - 1")
        if not isinstance(cert.get("previous_hash"), str) or not HEX64.match(cert["previous_hash"]):
            add("previous_hash must be 64-hex for v>1")

    if previous is not None:
        if cert.get("previous_hash") != previous.get("hash"):
            add("previous_hash does not match the hash of the supplied previous version")
        if cert.get("version") != (previous.get("version") or 0) + 1:
            add("version is not previous.version + 1")

    life = cert.get("lifecycle") or {}
    if isinstance(life, dict) and life.get("state") is not None and life.get("state") != cert.get("status"):
        add("lifecycle.state must equal status")

    t = cert.get("time")
    if isinstance(t, dict):
        if t.get("anchored") is True and not t.get("ots_proof"):
            add("time.anchored = true requires time.ots_proof")
        if t.get("anchored") is True and t.get("ots_status") != "complete":
            add('time.anchored = true requires time.ots_status = "complete"')
        if t.get("anchored") is True and t.get("clock_source") != "okf":
            add('time.anchored = true requires time.clock_source = "okf"')
        cal = t.get("calendar")
        if cal is not None:
            if not isinstance(cal, dict):
                add("time.calendar must be an object")
            else:
                for k in ("epoch", "cycle", "phase"):
                    v = cal.get(k)
                    if not _is_int(v) or v < 0:
                        add(f"time.calendar.{k} must be a non-negative integer")

    for forbidden in SECRETS:
        for section in ("genesis", "identity"):
            sec = cert.get(section)
            if isinstance(sec, dict) and forbidden in sec:
                add(f"{section} must not carry {forbidden}")

    return {"ok": not errors, "errors": errors}
