#!/usr/bin/env python3
"""Generate the sid/0.2 fixtures and conformance vectors.

Every vector is a complete, self-contained case: the documents, the options
and the expected verdict. An implementation needs only a verifier to run them;
nothing has to be re-signed. Signatures are deterministic (Ed25519 by
definition, BIP-340 with zero auxiliary randomness), so this script always
writes the same bytes.

The keys in test-keys.json are PUBLIC TEST KEYS. Never trust them.

    python3 conformance/v0.2/generate.py
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "implementations", "python"))

import sid02  # noqa: E402
import sigs  # noqa: E402


def key(label):
    """A deterministic test secret for a label."""
    return hashlib.sha256(f"sid/0.2 test key: {label}".encode()).hexdigest()


KEYS = {name: {"alg": alg, "secret": key(name), "public_key": sigs.public_key(alg, key(name))}
        for name, alg in (("issuer-root", "ed25519"), ("issuer-root-next", "ed25519"),
                          ("issuer-old", "ed25519"), ("issuer-burned", "ed25519"),
                          ("issuer-schnorr", "bip340"), ("attacker", "ed25519"),
                          ("agent-nostr", "bip340"), ("agent-mesh", "ed25519"))}

ROOT_ISSUER = "issuer:helix-test-root"
SCHNORR_ISSUER = "issuer:nostr-test-root"

TRUST = {"issuers": {
    ROOT_ISSUER: {"keys": [
        {"kid": "root-1", "alg": "ed25519", "public_key": KEYS["issuer-root"]["public_key"],
         "not_before": "2026-01-01T00:00:00Z"},
        {"kid": "root-2", "alg": "ed25519", "public_key": KEYS["issuer-root-next"]["public_key"],
         "not_before": "2027-01-01T00:00:00Z"},
        {"kid": "old-1", "alg": "ed25519", "public_key": KEYS["issuer-old"]["public_key"],
         "not_before": "2025-01-01T00:00:00Z", "revoked_at": "2026-06-01T00:00:00Z"},
        {"kid": "burned-1", "alg": "ed25519", "public_key": KEYS["issuer-burned"]["public_key"],
         "not_before": "2025-01-01T00:00:00Z", "compromised": True},
    ]},
    SCHNORR_ISSUER: {"keys": [
        {"kid": "s-1", "alg": "bip340", "public_key": KEYS["issuer-schnorr"]["public_key"],
         "not_before": "2026-01-01T00:00:00Z"},
    ]},
}}

BORN = "2026-11-12T09:00:00Z"


def sign(doc, signer="issuer-root"):
    return sid02.sign_document(doc, KEYS[signer]["alg"], KEYS[signer]["secret"])


def minimal_body():
    return {
        "format": "sid/0.2", "id": "sid_front-desk", "version": 1,
        "status": "live", "born_at": BORN, "updated": BORN,
        "issuer": {"id": ROOT_ISSUER, "kid": "root-1"},
        "identity": {"name": "Front Desk", "type": "agent"},
        "lifecycle": {"state": "live", "history": [{"state": "cast", "at": BORN}, {"state": "live", "at": BORN}]},
    }


def full_body():
    sid_id = "sid_santinos-agent"
    return {
        "format": "sid/0.2", "id": sid_id, "version": 1,
        "status": "live", "born_at": BORN, "updated": "2026-11-12T09:05:00Z",
        "issuer": {"id": ROOT_ISSUER, "kid": "root-1"},
        "identity": {"name": "Santino's Pizza agent", "type": "agent",
                     "description": "Answers calls and messages for Santino's Pizza.",
                     "parent": None, "controller": "tenant:santinos"},
        "bindings": [
            sid02.make_binding(sid_id, "nostr-main", "nostr", "bip340", KEYS["agent-nostr"]["secret"],
                               BORN, ["messaging", "call-signaling"]),
            sid02.make_binding(sid_id, "lan-main", "meshenger", "ed25519", KEYS["agent-mesh"]["secret"],
                               BORN, ["call-signaling"]),
        ],
        "capabilities": {"skills": ["front-desk"], "permissions": ["kb.search", "ticket.create", "call.transfer"],
                         "namespaces": ["mem/card/dna_pizza01"]},
        "memory": {"provider": "minipae", "locator": None},
        "lifecycle": {"state": "live", "history": [{"state": "cast", "at": BORN},
                                                   {"state": "live", "at": "2026-11-12T09:05:00Z"}]},
        "provenance": {"profile_id": "helix/front-desk@1"},
        "extensions": {"helix": {"card_id": "dna_pizza01"}},
        "changelog": ["v1: issued"],
        "appendix": {"notes": "Not quotable. Not in acting_hash."},
    }


def runtime_body(cert):
    return {
        "format": "sid-runtime/0.2", "sid": cert["id"], "runtime_id": "agent-voice-santinos",
        "adapter": {"kind": "agent-voice", "version": "0.1.0"},
        "endpoints": [
            {"type": "nostr", "address": "wss://relay.example", "binding": "nostr-main"},
            {"type": "meshenger-lan", "address": "192.0.2.10:10001", "binding": "lan-main"},
            {"type": "sip", "address": "sip:95001@pbx.example"},
        ],
        "capabilities": ["kb.search", "call.transfer"],
        "issued_at": "2026-11-13T00:00:00Z", "expires_at": "2026-12-13T00:00:00Z",
        "issuer": {"id": ROOT_ISSUER, "kid": "root-1"},
    }


MINIMAL = sign(minimal_body())
FULL = sign(full_body())
RUNTIME = sign(runtime_body(FULL))
NOW = "2026-11-20T12:00:00Z"
LEGACY = json.load(open(os.path.join(ROOT, "conformance", "fixtures", "full-sid.json")))

vectors = []


def sid_vec(name, cert, expect, trust=True, **options):
    vectors.append({"name": name, "kind": "sid", "cert": cert, "trust": trust, **options, "expect": expect})


def rt_vec(name, stmt, cert, expect, trust=True, **options):
    vectors.append({"name": name, "kind": "runtime", "stmt": stmt, "cert": cert, "trust": trust,
                    **options, "expect": expect})


def edit(doc, fn, signer="issuer-root", resign=True):
    out = copy.deepcopy(doc)
    for k in ("hash", "acting_hash", "proof"):
        if resign:
            out.pop(k, None)
    fn(out)
    return sign(out, signer) if resign else out


OK = {"ok": True, "trusted": True}

# -- valid documents and trust -------------------------------------------------
sid_vec("minimal-valid", MINIMAL, OK)
sid_vec("full-valid", FULL, OK)
sid_vec("no-trust-anchors", FULL, {"ok": True, "trusted": False, "untrusted": "no trust anchors"}, trust=False)
sid_vec("unknown-issuer", edit(FULL, lambda c: c["issuer"].update(id="issuer:someone-else")),
        {"ok": True, "trusted": False, "untrusted": "is not a trust anchor"})
sid_vec("unknown-key-id", edit(FULL, lambda c: c["issuer"].update(kid="root-9")),
        {"ok": True, "trusted": False, "untrusted": "has no key"})
sid_vec("schnorr-issuer-valid",
        edit(MINIMAL, lambda c: c.update(issuer={"id": SCHNORR_ISSUER, "kid": "s-1"}), "issuer-schnorr"), OK)

# -- forgery -------------------------------------------------------------------
sid_vec("tampered-acting-field", edit(FULL, lambda c: c["identity"].update(name="Someone Else"), resign=False),
        {"ok": False, "trusted": False, "error": "hash does not match"})


def rehash_only(c):
    c["identity"]["name"] = "Someone Else"
    c["acting_hash"] = sid02.acting_hash(c)
    c["hash"] = sid02.sid_hash(c)


sid_vec("tampered-and-rehashed", edit(FULL, rehash_only, resign=False),
        {"ok": False, "trusted": False, "error": "issuer signature does not verify"})
sid_vec("signed-by-attacker-claiming-root", edit(FULL, lambda c: None, "attacker"),
        {"ok": False, "trusted": False, "error": "issuer signature does not verify"})
sid_vec("missing-proof", edit(FULL, lambda c: c.pop("proof"), resign=False),
        {"ok": False, "trusted": False, "error": "proof must be"})
sid_vec("proof-alg-differs-from-key",
        edit(MINIMAL, lambda c: c["proof"].update(alg="bip340"), resign=False),
        {"ok": False, "trusted": False, "error": "proof.alg does not match"})

# -- issuer key lifecycle ------------------------------------------------------
sid_vec("issuer-key-compromised", edit(MINIMAL, lambda c: c["issuer"].update(kid="burned-1"), "issuer-burned"),
        {"ok": True, "trusted": False, "untrusted": "compromised"})
sid_vec("signed-after-key-revoked", edit(MINIMAL, lambda c: c["issuer"].update(kid="old-1"), "issuer-old"),
        {"ok": True, "trusted": False, "untrusted": "was revoked"})


def before_revocation(c):
    c["issuer"]["kid"] = "old-1"
    c["born_at"] = c["updated"] = "2026-03-01T00:00:00Z"
    c["lifecycle"]["history"] = [{"state": "live", "at": "2026-03-01T00:00:00Z"}]


sid_vec("signed-before-key-revoked", edit(MINIMAL, before_revocation, "issuer-old"), OK)
sid_vec("signed-before-key-valid", edit(MINIMAL, lambda c: c["issuer"].update(kid="root-2"), "issuer-root-next"),
        {"ok": True, "trusted": False, "untrusted": "before issuer key"})

# -- bindings ------------------------------------------------------------------
OTHER_ID_BINDING = sid02.make_binding("sid_another-agent", "nostr-main", "nostr", "bip340",
                                      KEYS["agent-nostr"]["secret"], BORN)
sid_vec("binding-proof-made-for-another-sid", edit(FULL, lambda c: c["bindings"].__setitem__(0, OTHER_ID_BINDING)),
        {"ok": False, "trusted": False, "error": "proof of possession does not verify"})
ED_NOSTR = sid02.make_binding("sid_santinos-agent", "nostr-main", "nostr", "ed25519", KEYS["agent-mesh"]["secret"], BORN)
sid_vec("nostr-binding-with-ed25519-key", edit(FULL, lambda c: c["bindings"].__setitem__(0, ED_NOSTR)),
        {"ok": False, "trusted": False, "error": "a nostr binding must use bip340"})
sid_vec("duplicate-binding-id", edit(FULL, lambda c: c["bindings"].append(copy.deepcopy(c["bindings"][0]))),
        {"ok": False, "trusted": False, "error": "is used twice"})
sid_vec("binding-key-swapped",
        edit(FULL, lambda c: c["bindings"][0].update(public_key=KEYS["attacker"]["public_key"])),
        {"ok": False, "trusted": False, "error": "proof of possession does not verify"})

# -- status, lifecycle, structure ---------------------------------------------
for status in ("cast", "suspended", "retired"):
    def set_status(c, s=status):
        c["status"] = s
        c["lifecycle"]["state"] = s
        c["lifecycle"]["history"].append({"state": s, "at": c["updated"]})
    sid_vec(f"status-{status}", edit(MINIMAL, set_status),
            {"ok": True, "trusted": False, "untrusted": f"status is {status}"})
sid_vec("lifecycle-state-disagrees", edit(MINIMAL, lambda c: c["lifecycle"].update(state="suspended")),
        {"ok": False, "trusted": False, "error": "lifecycle.state must equal status"})
sid_vec("updated-before-born", edit(MINIMAL, lambda c: c.update(updated="2026-11-12T08:59:59Z")),
        {"ok": False, "trusted": False, "error": "updated must not be before born_at"})
sid_vec("timestamp-with-offset", edit(MINIMAL, lambda c: c.update(updated="2026-11-12T09:00:00+00:00")),
        {"ok": False, "trusted": False, "error": "updated must be RFC 3339 UTC"})
sid_vec("v1-carrying-a-chain", edit(MINIMAL, lambda c: c.update(previous_hash="a" * 64)),
        {"ok": False, "trusted": False, "error": 'v1 must have previous_hash = "none"'})
sid_vec("secret-in-extensions", edit(FULL, lambda c: c["extensions"]["helix"].update(nsec="nsec1example")),
        {"ok": False, "trusted": False, "error": "must not be present"})
sid_vec("bad-extension-namespace", edit(FULL, lambda c: c["extensions"].update({"Bad Name": {}})),
        {"ok": False, "trusted": False, "error": "must be a namespaced object"})
sid_vec("unknown-format", edit(MINIMAL, lambda c: c.update(format="sid/0.3")),
        {"ok": False, "trusted": False, "error": "format must be sid/0.2"})
sid_vec("identity-type-not-agent", edit(MINIMAL, lambda c: c["identity"].update(type="business")),
        {"ok": False, "trusted": False, "error": 'identity.type must be "agent"'})


# -- the chain -----------------------------------------------------------------
def next_version(prev, fn=lambda c: None, signer="issuer-root"):
    c = copy.deepcopy(prev)
    for k in ("hash", "acting_hash", "proof"):
        c.pop(k)
    c["version"] = prev["version"] + 1
    c["previous_version"] = prev["version"]
    c["previous_hash"] = prev["hash"]
    c["updated"] = "2026-11-14T10:00:00Z"
    fn(c)
    return sign(c, signer)


V2 = next_version(FULL, lambda c: c["capabilities"]["permissions"].append("booking.create"))
sid_vec("v2-valid-chain", V2, OK, previous=FULL)
sid_vec("v2-wrong-previous-hash", next_version(FULL, lambda c: c.update(previous_hash="b" * 64)),
        {"ok": False, "trusted": False, "error": "previous_hash does not match"}, previous=FULL)
sid_vec("v2-issuer-changed",
        next_version(FULL, lambda c: c.update(issuer={"id": SCHNORR_ISSUER, "kid": "s-1"}), "issuer-schnorr"),
        {"ok": False, "trusted": False, "error": "issuer.id differs"}, previous=FULL)
sid_vec("v2-history-rewritten", next_version(FULL, lambda c: c["lifecycle"].update(
    history=[{"state": "live", "at": "2026-11-12T09:05:00Z"}])),
        {"ok": False, "trusted": False, "error": "does not extend the previous version's history"}, previous=FULL)


def retire(c):
    c["status"] = "retired"
    c["lifecycle"]["state"] = "retired"
    c["lifecycle"]["history"].append({"state": "retired", "at": c["updated"]})


RETIRED = next_version(FULL, retire)


def revive(c):
    c["status"] = "live"
    c["lifecycle"]["state"] = "live"
    c["lifecycle"]["history"].append({"state": "live", "at": c["updated"]})


sid_vec("version-after-retirement", next_version(RETIRED, revive),
        {"ok": False, "trusted": False, "error": "the previous version is retired"}, previous=RETIRED)
sid_vec("older-version-when-head-is-known", FULL,
        {"ok": True, "trusted": False, "untrusted": "a newer version"},
        head={"version": V2["version"], "hash": V2["hash"]})
sid_vec("current-version-when-head-is-known", V2, OK, head={"version": V2["version"], "hash": V2["hash"]})

# -- migration from sid/0.1 ----------------------------------------------------
MIGRATED = sign(sid02.migrate_from_01(LEGACY, {"id": ROOT_ISSUER, "kid": "root-1"}, "2026-11-14T00:00:00Z"))
expect_status = MIGRATED["status"]
migrated_expect = ({"ok": True, "trusted": True} if expect_status == "live"
                   else {"ok": True, "trusted": False, "untrusted": f"status is {expect_status}"})
sid_vec("migrated-with-source", MIGRATED, {**migrated_expect, "migration": "verified"}, legacy=LEGACY)
sid_vec("migrated-source-not-supplied", MIGRATED, {**migrated_expect, "migration": "unchecked"})
tampered_legacy = copy.deepcopy(LEGACY)
tampered_legacy["identity"]["name"] = "impostor"
sid_vec("migrated-with-tampered-source", MIGRATED,
        {"ok": False, "trusted": False, "error": "sid/0.1 certificate does not verify"}, legacy=tampered_legacy)
sid_vec("migrated-claims-a-different-source",
        edit(MIGRATED, lambda c: c["provenance"]["migrated_from"].update(hash="c" * 64)),
        {"ok": False, "trusted": False, "error": "does not match the supplied sid/0.1 certificate"}, legacy=LEGACY)

# -- runtime statements --------------------------------------------------------
rt_vec("runtime-valid", RUNTIME, FULL, OK, now=NOW)
rt_vec("runtime-expired", RUNTIME, FULL, {"ok": True, "trusted": False, "untrusted": "has expired"},
       now="2026-12-13T00:00:00Z")
rt_vec("runtime-not-valid-yet", RUNTIME, FULL, {"ok": True, "trusted": False, "untrusted": "not valid yet"},
       now="2026-11-12T23:59:59Z")
rt_vec("runtime-no-clock", RUNTIME, FULL, {"ok": True, "trusted": False, "untrusted": "expiry not checked"})
rt_vec("runtime-nostr-endpoint-on-lan-key", edit(RUNTIME, lambda s: s["endpoints"][0].update(binding="lan-main")), FULL,
       {"ok": False, "trusted": False, "error": "a nostr endpoint cannot use a meshenger binding"}, now=NOW)
rt_vec("runtime-nostr-endpoint-without-binding", edit(RUNTIME, lambda s: s["endpoints"][0].pop("binding")), FULL,
       {"ok": False, "trusted": False, "error": "must name a nostr binding"}, now=NOW)
rt_vec("runtime-binding-not-in-certificate", edit(RUNTIME, lambda s: s["endpoints"][0].update(binding="nostr-old")), FULL,
       {"ok": False, "trusted": False, "error": "is not in the certificate"}, now=NOW)
rt_vec("runtime-capability-beyond-certificate", edit(RUNTIME, lambda s: s["capabilities"].append("payment.charge")), FULL,
       {"ok": False, "trusted": False, "error": "capabilities exceed"}, now=NOW)
rt_vec("runtime-signed-by-another-issuer",
       edit(RUNTIME, lambda s: s.update(issuer={"id": SCHNORR_ISSUER, "kid": "s-1"}), "issuer-schnorr"), FULL,
       {"ok": False, "trusted": False, "error": "must be signed by the certificate's issuer"}, now=NOW)
rt_vec("runtime-endpoint-tampered", edit(RUNTIME, lambda s: s["endpoints"][2].update(address="sip:666@evil.example"),
                                         resign=False), FULL,
       {"ok": False, "trusted": False, "error": "hash does not match"}, now=NOW)
rt_vec("runtime-for-another-sid", RUNTIME, MINIMAL,
       {"ok": False, "trusted": False, "error": "sid does not name this certificate"}, now=NOW)


def suspend(c):
    c["status"] = "suspended"
    c["lifecycle"]["state"] = "suspended"
    c["lifecycle"]["history"].append({"state": "suspended", "at": c["updated"]})


rt_vec("runtime-of-a-suspended-agent", RUNTIME, next_version(FULL, suspend),
       {"ok": True, "trusted": False, "untrusted": "status is suspended"}, now=NOW)
rt_vec("runtime-without-trust-anchors", RUNTIME, FULL,
       {"ok": True, "trusted": False, "untrusted": "no trust anchors"}, trust=False, now=NOW)


def dump(path, obj):
    with open(os.path.join(HERE, path), "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


dump("trust.json", TRUST)
dump("test-keys.json", {"note": "PUBLIC TEST KEYS for the conformance suite. Never trust them.", "keys": KEYS})
dump("fixtures/minimal-sid.json", MINIMAL)
dump("fixtures/full-sid.json", FULL)
dump("fixtures/full-sid-v2.json", V2)
dump("fixtures/runtime.json", RUNTIME)
dump("fixtures/migrated-sid.json", MIGRATED)
dump("vectors.json", {
    "note": "sid/0.2 conformance vectors. Each vector is self-contained; `trust: true` means the "
            "anchors in trust.json, `false` means none. `expect.error` / `expect.untrusted` are "
            "substrings that must appear in the corresponding list.",
    "vectors": vectors})
print(f"wrote {len(vectors)} vectors")
