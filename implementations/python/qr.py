"""helix-qr/1: signed QR contact references and their resolutions.

Reference implementation (see spec/helix-qr-1.md). Builds on sid/0.2: the
document hash, the issuer proof and the trust anchors are exactly those of
sid02, and a resolution carries a sid/0.2 certificate and a sid-runtime/0.2
statement that sid02 verifies. A QR code is a pointer. It never carries a key,
an address or a secret; everything a caller will rely on is fetched, signed,
and verified here.

Verdicts have the sid shape: `ok` (well-formed and not tampered), `trusted`
(ok, AND anchored AND current), `errors`, `untrusted`, plus `notes`.
"""
import base64
import json
import re
from datetime import datetime, timedelta, timezone

import sid02
from sid02 import sid_hash, issue_message, sign_document  # noqa: F401  (re-exported)

FORMAT = "helix-qr/1"
RESOLUTION_FORMAT = "helix-qr-resolution/1"
MAX_LIFETIME = timedelta(days=400)
MAX_FRESH = timedelta(hours=24)
SKEW = timedelta(minutes=5)
STATUSES = ("active", "suspended", "revoked", "superseded")
KINDS = ("agent", "business")

REF_KEYS = {"format", "kind", "sid", "card", "resolver", "domain", "issued_at", "expires_at", "nonce",
            "issuer", "hash", "proof"}
RES_KEYS = {"format", "reference_hash", "resolver", "status", "superseded_by", "issued_at", "fresh_until",
            "certificate", "runtime", "card", "issuer", "hash", "proof"}

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# All patterns are ASCII-only and anchored with \Z, so they mean the same in Python, JavaScript and Go
# (Python's `$` accepts a trailing newline and its \d and \s are Unicode-wide).
HOST_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z][a-z0-9-]{{0,61}}[a-z0-9]|[a-z])\Z")
ORIGIN_RE = re.compile(r"^https://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?\Z")
HTTPS_URL_RE = re.compile(r"^https://([A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:/[!-~]*)?\Z")
WSS_RE = re.compile(r"^wss://([A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:/[!-~]*)?\Z")
WIRE_RE = re.compile(r"^(https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?)/q/([A-Za-z0-9_-]{1,4096})\Z")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22}\Z")
HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
SLUG = re.compile(r"^[a-z0-9][a-z0-9_.-]*\Z")
SIP_RE = re.compile(r"^sips?:[!-~]+@[!-~]+\Z")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet",
                    ".private", ".localdomain")


# ── small helpers ────────────────────────────────────────────────────────────
def _ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _fmt(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_host(host: str) -> bool:
    """A name that could be reached on the public internet: lowercase DNS, at
    least two labels, an alphabetic TLD, and not one of the private-use suffixes."""
    if not HOST_RE.match(host) or host.endswith(PRIVATE_SUFFIXES) or host in ("localhost",):
        return False
    return not host.split(".")[-1].isdigit()


def origin_problem(origin) -> "str | None":
    """Why `origin` is not an acceptable resolver origin, or None."""
    if not isinstance(origin, str):
        return "resolver must be a string"
    m = ORIGIN_RE.match(origin)
    if not m:
        return "resolver must be an https origin: scheme and host, nothing else"
    host, port = m.group(1), m.group(2)
    if not public_host(host):
        return "resolver must be a lowercase public DNS name, not an IP address, localhost or a private-use name"
    if port is not None and (not 1 <= int(port) <= 65535 or int(port) == 443 or port.startswith("0")):
        return "resolver has a bad or default port"
    return None


def _time_ok(v):
    """RFC 3339 UTC, to the second, and a real date."""
    if not (isinstance(v, str) and TIME_RE.match(v)):
        return False
    try:
        _ts(v)
        return True
    except ValueError:
        return False


def _verdict():
    return {"ok": False, "trusted": False, "errors": [], "untrusted": [], "notes": []}


def _finish(v):
    v["ok"] = not v["errors"]
    v["trusted"] = v["ok"] and not v["untrusted"]
    return v


# ── making documents (issuer side) ───────────────────────────────────────────
def make_reference(kind, sid, resolver, issued_at, expires_at, nonce, issuer, alg, secret_hex, card=None, domain=None):
    doc = {"format": FORMAT, "kind": kind, "sid": sid, "resolver": resolver, "issued_at": issued_at,
           "expires_at": expires_at, "nonce": nonce, "issuer": issuer}
    if card is not None:
        doc["card"] = card
    if domain is not None:
        doc["domain"] = domain
    return sign_document(doc, alg, secret_hex)


def make_resolution(reference, status, issued_at, fresh_until, issuer, alg, secret_hex, certificate=None,
                    runtime=None, card=None, superseded_by=None):
    doc = {"format": RESOLUTION_FORMAT, "reference_hash": reference["hash"], "resolver": reference["resolver"],
           "status": status, "issued_at": issued_at, "fresh_until": fresh_until, "issuer": issuer}
    for k, v in (("certificate", certificate), ("runtime", runtime), ("card", card), ("superseded_by", superseded_by)):
        if v is not None:
            doc[k] = v
    return sign_document(doc, alg, secret_hex)


def to_wire(doc) -> str:
    """The text a QR code carries: the resolver's origin and the signed reference."""
    return f"{doc['resolver']}/q/{b64url(sid02._canon(doc).encode())}"


def parse_wire(text):
    """-> (origin, document) or raises ValueError with the reason."""
    if not isinstance(text, str):
        raise ValueError("a QR payload is text")
    m = WIRE_RE.match(text)
    if not m:
        raise ValueError("not a helix-qr URL: expected https://<resolver>/q/<payload>")
    try:
        doc = json.loads(b64url_decode(m.group(2)).decode("utf-8"))
    except Exception:
        raise ValueError("the payload is not base64url JSON")
    if not isinstance(doc, dict):
        raise ValueError("the payload is not a JSON object")
    return m.group(1), doc


# ── verifying a reference ────────────────────────────────────────────────────
def verify_reference(subject, trust=None, now=None):
    """`subject` is the scanned URL (preferred: it lets the domain binding be
    checked) or an already-parsed reference document."""
    v = _verdict()
    err, untrusted = v["errors"], v["untrusted"]
    origin = None
    if isinstance(subject, str):
        try:
            origin, doc = parse_wire(subject)
        except ValueError as e:
            err.append(str(e))
            return _finish(v)
    else:
        doc = subject
    if not isinstance(doc, dict):
        err.append("not an object")
        return _finish(v)

    unknown = sorted(set(doc) - REF_KEYS)
    if unknown:
        err.append(f"unknown field(s): {', '.join(unknown)}")
    if doc.get("format") != FORMAT:
        err.append(f"format must be {FORMAT}")
    if doc.get("kind") not in KINDS:
        err.append("kind must be agent or business")
    if not isinstance(doc.get("sid"), str) or not sid02.ID_RE.match(doc["sid"]):
        err.append("sid must be a sid_<slug> identifier")
    card = doc.get("card")
    if card is not None:
        if not (isinstance(card, dict) and set(card) == {"id", "hash"} and isinstance(card["id"], str)
                and SLUG.match(card["id"]) and isinstance(card["hash"], str) and HEX64.match(card["hash"])):
            err.append("card must be {id, hash}")
    if doc.get("kind") == "business" and card is None:
        err.append("a business reference must carry a card")
    problem = origin_problem(doc.get("resolver"))
    if problem:
        err.append(problem)
    if "domain" in doc and not (isinstance(doc["domain"], str) and public_host(doc["domain"])):
        err.append("domain must be a public DNS name")
    if not _time_ok(doc.get("issued_at")) or not _time_ok(doc.get("expires_at")):
        err.append("issued_at and expires_at must be RFC 3339 UTC")
    else:
        if doc["expires_at"] <= doc["issued_at"]:
            err.append("expires_at must be after issued_at")
        elif _ts(doc["expires_at"]) - _ts(doc["issued_at"]) > MAX_LIFETIME:
            err.append("a reference may not be valid for more than 400 days")
    if not isinstance(doc.get("nonce"), str) or not NONCE_RE.match(doc["nonce"]):
        err.append("nonce must be 16 random bytes, base64url")
    secrets = sid02._find_secrets(doc)
    if secrets:
        err.append("secret material must not be present: " + ", ".join(secrets))
    if err:
        return _finish(v)

    if doc.get("hash") != sid_hash(doc):
        err.append("hash does not match the document")
        return _finish(v)
    e, u, _ = sid02._issuer_check(doc, trust, doc["issued_at"])
    err.extend(e)
    untrusted.extend(u)

    # domain binding: the page the code sent you to must be the resolver the issuer signed
    if origin is None:
        untrusted.append("domain binding was not checked (no URL was supplied)")
    elif origin != doc["resolver"]:
        err.append(f"the URL's origin ({origin}) does not match the signed resolver ({doc['resolver']})")

    if now is None:
        untrusted.append("expiry not checked (no clock)")
    else:
        t = _ts(now)
        if t >= _ts(doc["expires_at"]):
            untrusted.append("the reference has expired")
        elif t + SKEW < _ts(doc["issued_at"]):
            untrusted.append("the reference is not valid yet")
    return _finish(v)


# ── verifying a resolution ───────────────────────────────────────────────────
def check_resolution_envelope(res, ref, trust=None, now=None, fetched_from=None):
    """Everything about a resolution that needs no knowledge of sid certificates:
    who signed it, which reference it answers, where it came from, whether it is
    current, and what status it reports. `ref` is the (verified) reference."""
    v = _verdict()
    err, untrusted = v["errors"], v["untrusted"]
    if not isinstance(res, dict):
        err.append("not an object")
        return _finish(v)
    unknown = sorted(set(res) - RES_KEYS)
    if unknown:
        err.append(f"unknown field(s): {', '.join(unknown)}")
    if res.get("format") != RESOLUTION_FORMAT:
        err.append(f"format must be {RESOLUTION_FORMAT}")
    if res.get("status") not in STATUSES:
        err.append("status must be active, suspended, revoked or superseded")
    if not isinstance(res.get("reference_hash"), str) or not HEX64.match(res["reference_hash"]):
        err.append("reference_hash must be 64 hex characters")
    if "superseded_by" in res and not (isinstance(res["superseded_by"], str) and HEX64.match(res["superseded_by"])):
        err.append("superseded_by must be 64 hex characters")
    if not _time_ok(res.get("issued_at")) or not _time_ok(res.get("fresh_until")):
        err.append("issued_at and fresh_until must be RFC 3339 UTC")
    elif res["fresh_until"] <= res["issued_at"]:
        err.append("fresh_until must be after issued_at")
    elif _ts(res["fresh_until"]) - _ts(res["issued_at"]) > MAX_FRESH:
        err.append("a resolution may not be fresh for more than 24 hours")
    if origin_problem(res.get("resolver")):
        err.append(origin_problem(res.get("resolver")))
    secrets = sid02._find_secrets({k: res[k] for k in res if k not in ("certificate", "runtime")})
    if secrets:
        err.append("secret material must not be present: " + ", ".join(secrets))
    if err:
        return _finish(v)

    if res.get("hash") != sid_hash(res):
        err.append("hash does not match the document")
        return _finish(v)
    e, u, _ = sid02._issuer_check(res, trust, res["issued_at"])
    err.extend(e)
    untrusted.extend(u)
    if (res.get("issuer") or {}).get("id") != (ref.get("issuer") or {}).get("id"):
        err.append("the resolution must be signed by the reference's issuer")
    if res["reference_hash"] != ref.get("hash"):
        err.append("this resolution answers a different reference")
    if res["resolver"] != ref.get("resolver"):
        err.append("the resolution's resolver differs from the reference's")
    if fetched_from is None:
        untrusted.append("where the resolution was fetched from was not checked")
    elif fetched_from != ref.get("resolver"):
        err.append(f"fetched from {fetched_from}, but the reference names {ref.get('resolver')}")

    if now is None:
        untrusted.append("freshness not checked (no clock)")
    else:
        t = _ts(now)
        if t >= _ts(res["fresh_until"]):
            untrusted.append("the resolution is stale")
        elif t + SKEW < _ts(res["issued_at"]):
            untrusted.append("the resolution is not valid yet")
    if res["status"] != "active":
        untrusted.append(f"the contact is {res['status']}")
    return _finish(v)


def _binding(cert, binding_id):
    return next((b for b in cert.get("bindings", []) if b.get("id") == binding_id), None)


def public_endpoints(runtime, cert, notes):
    """Typed contact endpoints from a VERIFIED runtime statement. Keys come from
    the certificate's bindings, never from the statement's free text, and a
    nostr key is never a LAN key. Private addresses are not published."""
    out = []
    for e in runtime.get("endpoints", []):
        t, addr = e.get("type"), e.get("address", "")
        if t == "nostr":
            m, b = WSS_RE.match(addr), _binding(cert, e.get("binding"))
            if m and public_host(m.group(1)) and b:
                out.append({"type": "nostr", "relay": addr, "binding": b["id"], "alg": b["alg"], "public_key": b["public_key"]})
            else:
                notes.append(f"nostr endpoint {addr!r} omitted: not a public wss:// relay")
        elif t == "meshenger-lan":
            notes.append("a LAN endpoint is not published through the public resolver")
        elif t == "sip":
            if isinstance(addr, str) and SIP_RE.match(addr):
                out.append({"type": "sip", "uri": addr})
            else:
                notes.append(f"sip endpoint {addr!r} omitted: not a sip: URI")
        elif t in ("a2a", "mcp", "https"):
            m = HTTPS_URL_RE.match(addr)
            if m and public_host(m.group(1)):
                out.append({"type": t, "url": addr})
            else:
                notes.append(f"{t} endpoint {addr!r} omitted: not a public https URL")
    return out


def pin_from(cert):
    """What a client stores when the user confirms a contact."""
    return {"sid": cert["id"], "version": cert["version"], "hash": cert["hash"], "certificate": cert}


def check_pin(pin, cert, trust):
    """-> (errors, key_changes). A pinned contact may move forward along its own
    chain; it may not become someone else, go backwards, or fork."""
    errors, changes = [], []
    if cert["id"] != pin["sid"]:
        return [f"the contact's identity changed ({pin['sid']} -> {cert['id']})"], changes
    if cert["version"] < pin["version"]:
        return ["the identity went back to an older version"], changes
    if cert["version"] == pin["version"]:
        if cert["hash"] != pin["hash"]:
            errors.append("the same version has different content")
    else:
        r = sid02.verify_sid(cert, trust=trust, previous=pin["certificate"])
        if not r["ok"]:
            errors.append("the new identity version does not extend the pinned one: " + "; ".join(r["errors"][:1]))
    old = {b["id"]: b["public_key"] for b in pin["certificate"].get("bindings", [])}
    new = {b["id"]: b["public_key"] for b in cert.get("bindings", [])}
    for k in sorted(set(old) | set(new)):
        if old.get(k) != new.get(k):
            changes.append({"binding": k, "change": "added" if k not in old else "removed" if k not in new else "rotated"})
    return errors, changes


def verify_resolution(res, ref, trust=None, now=None, fetched_from=None, pin=None, head=None):
    v = check_resolution_envelope(res, ref, trust, now, fetched_from)
    v.update({"endpoints": [], "sid": None, "card": None, "status": res.get("status") if isinstance(res, dict) else None,
              "needs_confirmation": False, "key_changes": [], "pin": None})
    err, untrusted, notes = v["errors"], v["untrusted"], v["notes"]
    if err or res.get("status") != "active":
        return _finish(v)

    cert, rt = res.get("certificate"), res.get("runtime")
    if not isinstance(cert, dict) or not isinstance(rt, dict):
        err.append("an active resolution must carry a certificate and a runtime statement")
        return _finish(v)
    cr = sid02.verify_sid(cert, trust=trust, head=head)
    if not cr["ok"]:
        err.append("the certificate does not verify: " + "; ".join(cr["errors"][:2]))
        return _finish(v)
    if cert.get("id") != ref.get("sid"):
        err.append(f"the resolution names a different agent ({cert.get('id')}) than the QR code ({ref.get('sid')})")
        return _finish(v)
    rr = sid02.verify_runtime(rt, cert, trust=trust, now=now, head=head)
    if not rr["ok"]:
        err.append("the runtime statement does not verify: " + "; ".join(rr["errors"][:2]))
        return _finish(v)
    for u in cr["untrusted"] + rr["untrusted"]:
        if u not in untrusted:
            untrusted.append(u)

    rcard, qcard = res.get("card"), ref.get("card")
    if qcard is not None:
        if not isinstance(rcard, dict) or rcard.get("id") != qcard["id"]:
            err.append("the resolution's card is not the card the QR code names")
            return _finish(v)
        if rcard.get("hash") != qcard["hash"]:
            notes.append("the business card has changed since this QR code was issued")
    v["card"] = rcard

    v["endpoints"] = public_endpoints(rt, cert, notes)
    v["sid"] = {"id": cert["id"], "version": cert["version"], "hash": cert["hash"], "acting_hash": cert.get("acting_hash"),
                "name": (cert.get("identity") or {}).get("name")}
    if pin is not None:
        perr, changes = check_pin(pin, cert, trust)
        err.extend(perr)
        v["key_changes"] = changes
        v["needs_confirmation"] = bool(changes)
        if perr:
            return _finish(v)
    else:
        v["needs_confirmation"] = True  # a first contact is always the user's decision
    v["pin"] = pin_from(cert)
    return _finish(v)
