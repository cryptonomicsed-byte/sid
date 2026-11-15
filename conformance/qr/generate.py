#!/usr/bin/env python3
"""Generate the helix-qr/1 conformance vectors.

Every vector is self-contained: the subject, the trust anchors, the clock and
the expected verdict. An implementation needs only a verifier to run them;
nothing has to be re-signed. Signatures are deterministic, so this script
always writes the same bytes.

Vector kinds
  reference            verify_reference(subject, trust, now)
  resolution-envelope  check_resolution_envelope(res, ref, trust, now, fetched_from)
  resolution           verify_resolution(res, ref, trust, now, fetched_from, pin)   (needs sid/0.2 verification)

`requires` lists capabilities a verifier must have to run a vector (`bip340`
for a Schnorr-signed issuer, `sid` for the full contact checks).

The keys are the PUBLIC TEST KEYS of conformance/v0.2. Never trust them.

    python3 conformance/qr/generate.py
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "implementations", "python"))

import qr  # noqa: E402
import sid02  # noqa: E402
import sigs  # noqa: E402

V02 = os.path.join(ROOT, "conformance", "v0.2")
KEYS = json.load(open(os.path.join(V02, "test-keys.json")))["keys"]
TRUST = json.load(open(os.path.join(V02, "trust.json")))
SID_VECTORS = {v["name"]: v for v in json.load(open(os.path.join(V02, "vectors.json")))["vectors"]}

ROOT_ISSUER = "issuer:helix-test-root"
ISSUER = {"id": ROOT_ISSUER, "kid": "root-1"}
NOW = "2026-11-20T12:00:00Z"
RESOLVER = "https://contact.example"
NONCE = qr.b64url(bytes(16))
CARD_HASH = hashlib.sha256(b"card v1").hexdigest()

# a second, unrelated issuer the verifier also trusts
OTHER_SECRET = hashlib.sha256(b"helix-qr/1 test key: other-issuer").hexdigest()
OTHER_ISSUER = "issuer:other-test"
TRUST = copy.deepcopy(TRUST)
TRUST["issuers"][OTHER_ISSUER] = {"keys": [{"kid": "o-1", "alg": "ed25519", "public_key": sigs.public_key("ed25519", OTHER_SECRET),
                                            "not_before": "2026-01-01T00:00:00Z"}]}

FULL = SID_VECTORS["full-valid"]["cert"]
MINIMAL = SID_VECTORS["minimal-valid"]["cert"]
RUNTIME = SID_VECTORS["runtime-valid"]["stmt"]
SID_ID = FULL["id"]


def sign(doc, signer="issuer-root"):
    k = KEYS[signer]
    return sid02.sign_document(doc, k["alg"], k["secret"])


def strip(doc):
    d = copy.deepcopy(doc)
    d.pop("hash", None)
    d.pop("proof", None)
    return d


def edit(doc, fn, signer="issuer-root"):
    """Change a document and sign it again (a well-formed document with new content)."""
    d = strip(doc)
    fn(d)
    return sign(d, signer)


def tamper(doc, fn):
    """Change a document and leave its hash and proof as they were."""
    d = copy.deepcopy(doc)
    fn(d)
    return d


def rehash_only(doc, fn):
    """Change a document, fix up the hash, keep the old proof."""
    d = copy.deepcopy(doc)
    fn(d)
    d["hash"] = sid02.sid_hash(d)
    return d


def reference(kind="agent", sid=SID_ID, **kw):
    args = dict(resolver=RESOLVER, issued_at="2026-11-14T00:00:00Z", expires_at="2027-11-14T00:00:00Z", nonce=NONCE,
                issuer=ISSUER, alg="ed25519", secret_hex=KEYS["issuer-root"]["secret"])
    args.update(kw)
    return qr.make_reference(kind, sid, **args)


REF = reference()
REF_BIZ = reference("business", card={"id": "dna_pizza01", "hash": CARD_HASH}, domain="santinos.example")


def resolution(ref=REF, status="active", cert=FULL, runtime=RUNTIME, card=None, issued_at="2026-11-20T11:00:00Z",
               fresh_until="2026-11-21T11:00:00Z", signer="issuer-root", **kw):
    k = KEYS[signer]
    return qr.make_resolution(ref, status, issued_at, fresh_until, kw.pop("issuer", ISSUER), k["alg"], k["secret"],
                              certificate=cert, runtime=runtime, card=card, **kw)


RES = resolution()
BINDING_NOSTR = next(b for b in FULL["bindings"] if b["id"] == "nostr-main")
EXPECT_ENDPOINTS = [
    {"type": "nostr", "relay": "wss://relay.example", "binding": "nostr-main", "alg": "bip340", "public_key": BINDING_NOSTR["public_key"]},
    {"type": "sip", "uri": "sip:95001@pbx.example"},
]

vectors = []
OK = {"ok": True, "trusted": True}


def ref_vec(name, subject, expect, trust=True, now=NOW, **extra):
    vectors.append({"name": name, "kind": "reference", "subject": subject, "trust": TRUST if trust else None, "now": now,
                    **extra, "expect": expect})


def env_vec(name, res, expect, ref=REF, trust=True, now=NOW, fetched_from=RESOLVER, **extra):
    vectors.append({"name": name, "kind": "resolution-envelope", "ref": ref, "res": res, "trust": TRUST if trust else None,
                    "now": now, "fetched_from": fetched_from, **extra, "expect": expect})


def res_vec(name, res, expect, ref=REF, trust=True, now=NOW, fetched_from=RESOLVER, pin=None, **extra):
    vectors.append({"name": name, "kind": "resolution", "ref": ref, "res": res, "trust": TRUST if trust else None, "now": now,
                    "fetched_from": fetched_from, "pin": pin, "requires": ["sid"], **extra, "expect": expect})


def err(text):
    return {"ok": False, "trusted": False, "error": text}


def untrusted(text):
    return {"ok": True, "trusted": False, "untrusted": text}


# ── references ──────────────────────────────────────────────────────────────
ref_vec("reference-valid-agent", qr.to_wire(REF), OK)
ref_vec("reference-valid-business", qr.to_wire(REF_BIZ), OK)
ref_vec("reference-schnorr-issuer", qr.to_wire(reference(issuer={"id": "issuer:nostr-test-root", "kid": "s-1"}, alg="bip340",
                                                         secret_hex=KEYS["issuer-schnorr"]["secret"])), OK, requires=["bip340"])
ref_vec("reference-no-trust-anchors", qr.to_wire(REF), untrusted("no trust anchors"), trust=False)
ref_vec("reference-unknown-issuer", qr.to_wire(edit(REF, lambda d: d.update(issuer={"id": "issuer:nobody", "kid": "x"}))),
        untrusted("is not a trust anchor"))
ref_vec("reference-unknown-key-id", qr.to_wire(edit(REF, lambda d: d["issuer"].update(kid="nope"))), untrusted("has no key"))
ref_vec("reference-expired", qr.to_wire(REF), untrusted("has expired"), now="2027-11-15T00:00:00Z")
ref_vec("reference-expires-at-the-instant", qr.to_wire(REF), untrusted("has expired"), now=REF["expires_at"])
ref_vec("reference-not-valid-yet", qr.to_wire(REF), untrusted("not valid yet"), now="2026-11-13T00:00:00Z")
ref_vec("reference-no-clock", qr.to_wire(REF), untrusted("expiry not checked"), now=None)
ref_vec("reference-issuer-key-compromised", qr.to_wire(edit(REF, lambda d: d["issuer"].update(kid="burned-1"), "issuer-burned")),
        untrusted("compromised"))
ref_vec("reference-signed-after-key-revoked", qr.to_wire(edit(REF, lambda d: d["issuer"].update(kid="old-1"), "issuer-old")),
        untrusted("was revoked"))
ref_vec("reference-signed-before-key-valid", qr.to_wire(edit(REF, lambda d: d["issuer"].update(kid="root-2"), "issuer-root-next")),
        untrusted("before issuer key"))
ref_vec("reference-document-without-url", REF, untrusted("domain binding was not checked"))

# tampering
ref_vec("reference-tampered-sid", qr.to_wire(tamper(REF, lambda d: d.update(sid="sid_someone-else"))), err("hash does not match"))
ref_vec("reference-tampered-and-rehashed", qr.to_wire(rehash_only(REF, lambda d: d.update(sid="sid_someone-else"))),
        err("issuer signature does not verify"))
ref_vec("reference-signed-by-attacker-claiming-root", qr.to_wire(edit(REF, lambda d: d.update(sid="sid_someone-else"), "attacker")),
        err("issuer signature does not verify"))
ref_vec("reference-proof-alg-differs-from-key", qr.to_wire(edit(REF, lambda d: None, "issuer-schnorr")),
        err("proof.alg does not match"))

# domain binding: a perfectly signed reference, re-hosted
payload = qr.to_wire(REF).split("/q/")[1]
ref_vec("reference-copied-to-another-domain", f"https://evil.example/q/{payload}", err("does not match the signed resolver"))
ref_vec("reference-copied-to-another-port", f"https://contact.example:8443/q/{payload}", err("does not match the signed resolver"))

# a resolver must be a public https origin
for name, resolver, why in [
    ("http", "http://contact.example", "https origin"),
    ("ip-address", "https://203.0.113.7", "public DNS name"),
    ("ip-address-with-port", "https://203.0.113.7:8443", "public DNS name"),
    ("ipv6-literal", "https://[::1]", "https origin"),
    ("localhost", "https://localhost", "public DNS name"),
    ("private-suffix", "https://kernel.internal", "public DNS name"),
    ("mdns-suffix", "https://printer.local", "public DNS name"),
    ("with-path", "https://contact.example/path", "https origin"),
    ("with-userinfo", "https://admin@contact.example", "https origin"),
    ("with-query", "https://contact.example?x=1", "https origin"),
    ("default-port-spelled-out", "https://contact.example:443", "default port"),
    ("upper-case", "https://Contact.Example", "public DNS name"),
    ("single-label", "https://intranet", "public DNS name"),
]:
    # carried at a well-formed URL, so it is the signed resolver field that is judged
    bad = edit(REF, lambda d, r=resolver: d.update(resolver=r))
    ref_vec(f"reference-resolver-{name}", f"{RESOLVER}/q/{qr.b64url(sid02._canon(bad).encode())}", err(why))

# structure
ref_vec("reference-unknown-field", qr.to_wire(edit(REF, lambda d: d.update(redirect="https://evil.example"))), err("unknown field"))
ref_vec("reference-secret-inside", qr.to_wire(edit(REF, lambda d: d.update(nsec="nsec1example"))), err("secret material"))
ref_vec("reference-business-without-card", qr.to_wire(edit(REF, lambda d: d.update(kind="business"))), err("must carry a card"))
ref_vec("reference-card-with-extra-field", qr.to_wire(edit(REF_BIZ, lambda d: d["card"].update(url="https://evil.example"))), err("card must be"))
ref_vec("reference-bad-nonce", qr.to_wire(edit(REF, lambda d: d.update(nonce="short"))), err("nonce must be"))
ref_vec("reference-bad-sid", qr.to_wire(edit(REF, lambda d: d.update(sid="Not A SID"))), err("sid must be"))
ref_vec("reference-unknown-kind", qr.to_wire(edit(REF, lambda d: d.update(kind="person"))), err("kind must be"))
ref_vec("reference-unknown-format", qr.to_wire(edit(REF, lambda d: d.update(format="helix-qr/2"))), err("format must be"))
ref_vec("reference-lifetime-too-long", qr.to_wire(edit(REF, lambda d: d.update(expires_at="2028-01-01T00:00:00Z"))), err("400 days"))
ref_vec("reference-expires-before-issued", qr.to_wire(edit(REF, lambda d: d.update(expires_at="2026-11-13T00:00:00Z"))), err("after issued_at"))
ref_vec("reference-timestamp-with-offset", qr.to_wire(edit(REF, lambda d: d.update(issued_at="2026-11-14T00:00:00+00:00"))), err("RFC 3339 UTC"))
ref_vec("reference-impossible-date", qr.to_wire(edit(REF, lambda d: d.update(issued_at="2026-13-45T00:00:00Z"))), err("RFC 3339 UTC"))
ref_vec("reference-non-ascii-digits-in-a-date", qr.to_wire(edit(REF, lambda d: d.update(issued_at="\u0662\u0660\u0662\u0666-11-14T00:00:00Z"))), err("RFC 3339 UTC"))
ref_vec("reference-domain-not-public", qr.to_wire(edit(REF_BIZ, lambda d: d.update(domain="shop.local"))), err("domain must be"))

# the wire form itself
ref_vec("wire-http", qr.to_wire(REF).replace("https://", "http://", 1), err("not a helix-qr URL"))
ref_vec("wire-extra-path", qr.to_wire(REF) + "/extra", err("not a helix-qr URL"))
ref_vec("wire-query-string", qr.to_wire(REF) + "?x=1", err("not a helix-qr URL"))
ref_vec("wire-fragment", qr.to_wire(REF) + "#x", err("not a helix-qr URL"))
ref_vec("wire-userinfo-trick", f"https://contact.example@evil.example/q/{payload}", err("not a helix-qr URL"))
ref_vec("wire-not-base64", f"{RESOLVER}/q/!!!", err("not a helix-qr URL"))
ref_vec("wire-not-json", f"{RESOLVER}/q/{qr.b64url(b'hello')}", err("not base64url JSON"))
ref_vec("wire-not-an-object", f"{RESOLVER}/q/{qr.b64url(b'[1,2]')}", err("not a JSON object"))
ref_vec("wire-empty-payload", f"{RESOLVER}/q/", err("not a helix-qr URL"))
ref_vec("wire-trailing-newline", qr.to_wire(REF) + "\n", err("not a helix-qr URL"))
ref_vec("wire-non-ascii-host", f"https://contact.exampl\u0435/q/{payload}", err("not a helix-qr URL"))
ref_vec("wire-another-path", f"{RESOLVER}/x/{payload}", err("not a helix-qr URL"))

# ── resolutions: the envelope ───────────────────────────────────────────────
env_vec("envelope-valid", RES, OK)
env_vec("envelope-for-another-reference", resolution(reference(sid="sid_another-agent")), err("answers a different reference"))
env_vec("envelope-fetched-from-another-origin", RES, err("fetched from https://evil.example"), fetched_from="https://evil.example")
env_vec("envelope-fetched-from-unknown", RES, untrusted("was not checked"), fetched_from=None)
env_vec("envelope-resolver-field-differs", edit(RES, lambda d: d.update(resolver="https://other.example")), err("resolver differs"))
env_vec("envelope-signed-by-another-issuer", edit(RES, lambda d: d.update(issuer={"id": OTHER_ISSUER, "kid": "o-1"}), "issuer-root"),
        err("issuer signature does not verify"))
SIGNED_BY_OTHER = sid02.sign_document(strip(RES) | {"issuer": {"id": OTHER_ISSUER, "kid": "o-1"}}, "ed25519", OTHER_SECRET)
env_vec("envelope-issuer-is-not-the-references", SIGNED_BY_OTHER, err("must be signed by the reference's issuer"))
env_vec("envelope-tampered-status", tamper(resolution(status="revoked", cert=None, runtime=None), lambda d: d.update(status="active")),
        err("hash does not match"))
env_vec("envelope-tampered-and-rehashed", rehash_only(resolution(status="revoked", cert=None, runtime=None), lambda d: d.update(status="active")),
        err("issuer signature does not verify"))
env_vec("envelope-stale", RES, untrusted("stale"), now="2026-11-21T11:00:00Z")
env_vec("envelope-stale-after-a-day", RES, untrusted("stale"), now="2026-11-25T00:00:00Z")
env_vec("envelope-not-valid-yet", RES, untrusted("not valid yet"), now="2026-11-20T10:00:00Z")
env_vec("envelope-no-clock", RES, untrusted("freshness not checked"), now=None)
env_vec("envelope-window-too-long", resolution(fresh_until="2026-11-22T11:00:01Z"), err("more than 24 hours"))
env_vec("envelope-fresh-before-issued", resolution(fresh_until="2026-11-20T10:00:00Z"), err("after issued_at"))
env_vec("envelope-revoked", resolution(status="revoked", cert=None, runtime=None), untrusted("the contact is revoked"))
env_vec("envelope-suspended", resolution(status="suspended", cert=None, runtime=None), untrusted("the contact is suspended"))
env_vec("envelope-superseded", resolution(status="superseded", cert=None, runtime=None, superseded_by="c" * 64),
        untrusted("the contact is superseded"))
env_vec("envelope-superseded-by-garbage", resolution(status="superseded", cert=None, runtime=None, superseded_by="nothex"), err("superseded_by"))
env_vec("envelope-unknown-status", edit(RES, lambda d: d.update(status="maybe")), err("status must be"))
env_vec("envelope-unknown-field", edit(RES, lambda d: d.update(callback="https://evil.example")), err("unknown field"))
env_vec("envelope-no-trust-anchors", RES, untrusted("no trust anchors"), trust=False)
env_vec("envelope-resolver-ip", edit(RES, lambda d: d.update(resolver="https://203.0.113.7")), err("public DNS name"))
env_vec("envelope-secret-inside", edit(RES, lambda d: d.update(card={"id": "x", "hash": "a" * 64, "private_key": "00"})), err("secret material"))

# ── resolutions: the contact ────────────────────────────────────────────────
res_vec("contact-valid", RES, {**OK, "endpoints": EXPECT_ENDPOINTS, "needs_confirmation": True, "notes": ["LAN endpoint is not published"]})
BIZ_RES = resolution(REF_BIZ, card={"id": "dna_pizza01", "hash": CARD_HASH})
res_vec("contact-business-card-unchanged", BIZ_RES, {**OK, "endpoints": EXPECT_ENDPOINTS}, ref=REF_BIZ)
NEW_CARD = hashlib.sha256(b"card v2").hexdigest()
res_vec("contact-business-card-changed", resolution(REF_BIZ, card={"id": "dna_pizza01", "hash": NEW_CARD}),
        {**OK, "endpoints": EXPECT_ENDPOINTS, "notes": ["business card has changed"]}, ref=REF_BIZ)
res_vec("contact-business-card-is-another-card", resolution(REF_BIZ, card={"id": "dna_other", "hash": CARD_HASH}),
        err("not the card the QR code names"), ref=REF_BIZ)
res_vec("contact-business-card-missing", resolution(REF_BIZ), err("not the card the QR code names"), ref=REF_BIZ)

res_vec("contact-certificate-of-another-agent", resolution(cert=MINIMAL), err("names a different agent"))
res_vec("contact-certificate-tampered", resolution(cert=tamper(FULL, lambda c: c["identity"].update(name="Evil Pizza"))),
        err("the certificate does not verify"))
res_vec("contact-certificate-signed-by-attacker", resolution(cert=edit(FULL, lambda c: None, "attacker")), err("the certificate does not verify"))
OTHER_RT = sign({**strip(RUNTIME), "sid": "sid_front-desk"})
res_vec("contact-runtime-for-another-agent", resolution(runtime=OTHER_RT), err("the runtime statement does not verify"))
res_vec("contact-runtime-tampered", resolution(runtime=tamper(RUNTIME, lambda r: r["endpoints"][0].update(address="wss://evil.example"))),
        err("the runtime statement does not verify"))
CROSS = edit(RUNTIME, lambda r: r["endpoints"][0].update(binding="lan-main"))
res_vec("contact-nostr-endpoint-on-a-lan-key", resolution(runtime=CROSS), err("the runtime statement does not verify"))
# a resolution issued on the runtime statement's last day, still fresh, but the statement itself has just expired
res_vec("contact-runtime-expired", resolution(issued_at="2026-12-12T12:00:00Z", fresh_until="2026-12-13T11:00:00Z"),
        {"ok": True, "trusted": False, "untrusted": "has expired", "endpoints": EXPECT_ENDPOINTS}, now="2026-12-13T00:00:00Z")
res_vec("contact-active-without-runtime", resolution(runtime=None), err("must carry a certificate and a runtime"))
res_vec("contact-active-without-certificate", resolution(cert=None), err("must carry a certificate and a runtime"))
res_vec("contact-revoked-carries-nothing", resolution(status="revoked", cert=None, runtime=None),
        {"ok": True, "trusted": False, "untrusted": "the contact is revoked", "endpoints": []})


def suspend(c):
    c["status"] = "suspended"
    c["lifecycle"]["state"] = "suspended"
    c["lifecycle"]["history"].append({"state": "suspended", "at": "2026-11-18T00:00:00Z"})
    c["version"] = 2
    c["previous_version"] = 1
    c["previous_hash"] = FULL["hash"]
    c["updated"] = "2026-11-18T00:00:00Z"


SUSPENDED = edit(FULL, suspend)
res_vec("contact-agent-suspended", resolution(cert=SUSPENDED), {"ok": True, "trusted": False, "untrusted": "status is suspended"})

# what is published, and what is not
PRIVATE_RELAY = edit(RUNTIME, lambda r: r["endpoints"][0].update(address="wss://relay.internal"))
res_vec("contact-private-relay-is-omitted", resolution(runtime=PRIVATE_RELAY),
        {**OK, "endpoints": [EXPECT_ENDPOINTS[1]], "notes": ["not a public wss:// relay"]})
PLAIN_WS = edit(RUNTIME, lambda r: r["endpoints"][0].update(address="ws://relay.example"))
res_vec("contact-unencrypted-relay-is-omitted", resolution(runtime=PLAIN_WS), {**OK, "endpoints": [EXPECT_ENDPOINTS[1]]})
BAD_SIP = edit(RUNTIME, lambda r: r["endpoints"][2].update(address="sip:nobody"))
res_vec("contact-malformed-sip-is-omitted", resolution(runtime=BAD_SIP), {**OK, "endpoints": [EXPECT_ENDPOINTS[0]], "notes": ["not a sip: URI"]})
HTTPS_EPS = edit(RUNTIME, lambda r: r["endpoints"].__setitem__(slice(None), [
    {"type": "a2a", "address": "https://a2a.example/agent"}, {"type": "mcp", "address": "https://192.168.1.5/mcp"},
    {"type": "https", "address": "http://insecure.example/x"}]))
res_vec("contact-only-public-https-endpoints", resolution(runtime=HTTPS_EPS),
        {**OK, "endpoints": [{"type": "a2a", "url": "https://a2a.example/agent"}]})

# ── pins: the contact the user already confirmed ────────────────────────────
def next_version(prev, fn, signer="issuer-root"):
    c = strip(prev)
    c["version"] = prev["version"] + 1
    c["previous_version"] = prev["version"]
    c["previous_hash"] = prev["hash"]
    c["updated"] = "2026-11-19T10:00:00Z"
    fn(c)
    return sign(c, signer)


def add_permission(c):
    c["capabilities"]["permissions"].append("booking.create")


NEW_NOSTR_SECRET = hashlib.sha256(b"sid/0.2 test key: agent-nostr-next").hexdigest()
NEW_NOSTR_BINDING = sid02.make_binding(SID_ID, "nostr-main", "nostr", "bip340", NEW_NOSTR_SECRET, "2026-11-19T10:00:00Z", ["messaging", "call-signaling"])


def rotate_nostr(c):
    c["bindings"][0] = NEW_NOSTR_BINDING


V2_SAME_KEYS = next_version(FULL, add_permission)
V2_ROTATED = next_version(FULL, rotate_nostr)
PIN_V1 = qr.pin_from(FULL)
PIN_V2 = qr.pin_from(V2_SAME_KEYS)
res_vec("pin-same-version", RES, {**OK, "needs_confirmation": False, "key_changes": []}, pin=PIN_V1)
res_vec("pin-moves-forward-with-the-same-keys", resolution(cert=V2_SAME_KEYS), {**OK, "needs_confirmation": False, "key_changes": []}, pin=PIN_V1)
res_vec("pin-key-rotated-needs-the-user", resolution(cert=V2_ROTATED),
        {**OK, "needs_confirmation": True, "key_changes": [{"binding": "nostr-main", "change": "rotated"}],
         "endpoints": [{**EXPECT_ENDPOINTS[0], "public_key": NEW_NOSTR_BINDING["public_key"]}, EXPECT_ENDPOINTS[1]]}, pin=PIN_V1)
res_vec("pin-binding-removed", resolution(cert=next_version(FULL, lambda c: c["bindings"].pop()), runtime=sign(strip(RUNTIME) | {"endpoints": [RUNTIME["endpoints"][0], RUNTIME["endpoints"][2]]})),
        {**OK, "needs_confirmation": True, "key_changes": [{"binding": "lan-main", "change": "removed"}]}, pin=PIN_V1)
res_vec("pin-a-different-agent", resolution(cert=FULL), err("identity changed"), pin=qr.pin_from(MINIMAL))
res_vec("pin-rolled-back", RES, err("older version"), pin=PIN_V2)
FORK = edit(FULL, lambda c: c["identity"].update(name="Santino's Pizza (impostor)"))
res_vec("pin-same-version-different-content", resolution(cert=FORK, runtime=sign(strip(RUNTIME))), err("different content"), pin=PIN_V1)
res_vec("pin-new-version-does-not-extend", resolution(cert=next_version(FULL, lambda c: c.update(previous_hash="d" * 64))),
        err("does not extend the pinned one"), pin=PIN_V1)

# ── write ───────────────────────────────────────────────────────────────────
names = [v["name"] for v in vectors]
assert len(names) == len(set(names)), "duplicate vector names"
out = {"note": "helix-qr/1 conformance vectors. Generated by generate.py; test keys only.", "vectors": vectors}
with open(os.path.join(HERE, "vectors.json"), "w") as f:
    json.dump(out, f, indent=1, sort_keys=True)
    f.write("\n")
print(f"{len(vectors)} vectors")
