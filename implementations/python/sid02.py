#!/usr/bin/env python3
"""sid/0.2 — the Python reference implementation.

sid/0.2 is the neutral profile: no application-specific required fields, an
issuer signature checked against trust anchors the *verifier* supplies, typed
key bindings each carrying a proof of possession, and a separate signed
runtime statement. sid/0.1 is untouched and still verified by `sid.verify_sid`.

Mirrors `implementations/typescript/src/sid02.ts` rule for rule;
`conformance/v0.2/vectors.json` is the shared proof.

    from sid02 import verify_sid
    r = verify_sid(cert, trust=anchors)
    # {"ok": bool, "trusted": bool, "errors": [...], "untrusted": [...], "migration": ...}

`ok`      the document is well formed and internally consistent: hashes
          recompute, the chain rules hold, every binding's proof of possession
          verifies, and the issuer proof verifies if its key is known.
`trusted` `ok`, AND the issuer proof verified against a supplied trust anchor,
          AND status is `live`, AND (if the caller knows the current head) this
          is that version. Act only on `trusted`.
"""
from __future__ import annotations

import hashlib
import json
import re

import sigs
from canonical import _canon_numbers, _prune

FORMAT = "sid/0.2"
RUNTIME_FORMAT = "sid-runtime/0.2"
LEGACY_FORMAT = "sid/0.1"
ACTING_KEYS = ("identity", "bindings", "capabilities", "memory", "lifecycle", "status")
STATUSES = ("cast", "live", "suspended", "retired")
#: Excluded from `hash`: the hash itself, the proof made over it, and "_" keys.
UNHASHED = ("hash", "proof")
#: Binding types whose key algorithm is fixed by their protocol.
BINDING_ALG = {"nostr": "bip340", "meshenger": "ed25519"}
#: Endpoint types that must be reached through a binding of a matching type.
ENDPOINT_BINDING = {"nostr": "nostr", "meshenger-lan": "meshenger"}
ENDPOINT_TYPES = ("nostr", "meshenger-lan", "sip", "a2a", "mcp", "https")
SECRET_KEYS = ("seed", "mnemonic", "private_key", "nsec", "secret", "secret_key")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
ID_RE = re.compile(r"^sid_[a-z0-9][a-z0-9-]*$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
NS_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_time(v) -> bool:
    return isinstance(v, str) and bool(TIME_RE.match(v))


def _canon(obj) -> str:
    return json.dumps(_prune(_canon_numbers(obj)), sort_keys=True, separators=(",", ":"))


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _body(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k not in UNHASHED and not k.startswith("_")}


def acting_hash(cert: dict) -> str:
    return _sha(_canon({k: cert[k] for k in ACTING_KEYS if k in cert}))


def sid_hash(doc: dict) -> str:
    """Hash of a certificate or runtime statement: everything except hash, proof, "_" keys."""
    return _sha(_canon(_body(doc)))


# ── what gets signed ─────────────────────────────────────────────────────────
def issue_message(fmt: str, doc_hash: str) -> str:
    return f"{fmt}\nissue\n{doc_hash}"


def bind_message(sid_id: str, binding: dict) -> str:
    return "\n".join([FORMAT, "bind", sid_id, str(binding.get("id")), str(binding.get("alg")),
                      str(binding.get("public_key"))])


# ── minting (tooling and fixtures; production issuers sign in the kernel) ────
def make_binding(sid_id: str, binding_id: str, btype: str, alg: str, secret_hex: str,
                 added_at: str, purposes=None) -> dict:
    binding = {"id": binding_id, "type": btype, "alg": alg,
               "public_key": sigs.public_key(alg, secret_hex), "added_at": added_at}
    if purposes:
        binding["purposes"] = list(purposes)
    binding["proof"] = sigs.sign(alg, secret_hex, bind_message(sid_id, binding))
    return binding


def sign_document(doc: dict, alg: str, secret_hex: str) -> dict:
    """Fill v1 defaults, then acting_hash (certificates), hash and the issuer proof."""
    out = dict(doc)
    if out.get("format") == FORMAT:
        if out.get("version") == 1:
            out.setdefault("previous_version", None)
            if out.get("previous_hash") is None:
                out["previous_hash"] = "none"
        out["acting_hash"] = acting_hash(out)
    out["hash"] = sid_hash(out)
    out["proof"] = {"alg": alg,
                    "signature": sigs.sign(alg, secret_hex, issue_message(out["format"], out["hash"]))}
    return out


# ── issuer authority ─────────────────────────────────────────────────────────
def _issuer_check(doc: dict, trust, signed_at) -> tuple[list, list, bool]:
    """Returns (errors, untrusted reasons, issuer_verified)."""
    errors, untrusted = [], []
    issuer = doc.get("issuer")
    proof = doc.get("proof")
    if not isinstance(issuer, dict) or not isinstance(issuer.get("id"), str) or not issuer.get("id") \
            or not isinstance(issuer.get("kid"), str) or not issuer.get("kid"):
        errors.append("issuer must be {id, kid}")
        return errors, untrusted, False
    if not isinstance(proof, dict) or proof.get("alg") not in sigs.ALGS \
            or not isinstance(proof.get("signature"), str) or not HEX128.match(proof["signature"]):
        errors.append("proof must be {alg, signature} with a supported alg and a 128-hex signature")
        return errors, untrusted, False
    if not isinstance(trust, dict) or not isinstance(trust.get("issuers"), dict):
        untrusted.append("no trust anchors supplied")
        return errors, untrusted, False
    anchor = trust["issuers"].get(issuer["id"])
    if not isinstance(anchor, dict):
        untrusted.append(f"issuer {issuer['id']} is not a trust anchor")
        return errors, untrusted, False
    key = next((k for k in anchor.get("keys", []) if isinstance(k, dict) and k.get("kid") == issuer["kid"]), None)
    if key is None:
        untrusted.append(f"issuer {issuer['id']} has no key {issuer['kid']}")
        return errors, untrusted, False
    if key.get("alg") != proof["alg"]:
        errors.append("proof.alg does not match the issuer key")
        return errors, untrusted, False
    if not sigs.verify(proof["alg"], str(key.get("public_key")),
                       issue_message(str(doc.get("format")), str(doc.get("hash"))), proof["signature"]):
        errors.append("issuer signature does not verify")
        return errors, untrusted, False
    # The signature is genuine; is the key allowed to have made it?
    if key.get("compromised") is True:
        untrusted.append(f"issuer key {issuer['kid']} is marked compromised")
        return errors, untrusted, False
    if _is_time(signed_at):
        if _is_time(key.get("not_before")) and signed_at < key["not_before"]:
            untrusted.append(f"signed before issuer key {issuer['kid']} was valid")
            return errors, untrusted, False
        if _is_time(key.get("not_after")) and signed_at >= key["not_after"]:
            untrusted.append(f"signed after issuer key {issuer['kid']} expired")
            return errors, untrusted, False
        if _is_time(key.get("revoked_at")) and signed_at >= key["revoked_at"]:
            untrusted.append(f"signed after issuer key {issuer['kid']} was revoked")
            return errors, untrusted, False
    return errors, untrusted, True


def _find_secrets(node, path="") -> list:
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}" if path else k
            if k in SECRET_KEYS:
                found.append(here)
            found.extend(_find_secrets(v, here))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_find_secrets(v, f"{path}[{i}]"))
    return found


# ── the certificate ──────────────────────────────────────────────────────────
def verify_sid(cert, trust=None, previous=None, head=None, legacy=None) -> dict:
    """Verify a sid/0.2 certificate.

    trust     {"issuers": {id: {"keys": [{kid, alg, public_key, not_before?,
              not_after?, revoked_at?, compromised?}]}}} — supplied by the
              relying party, never read from the certificate.
    previous  the previous version, to check the chain link.
    head      {"version", "hash"} of the newest version the caller knows; an
              older version is then not trusted.
    legacy    the sid/0.1 certificate named by provenance.migrated_from.
    """
    errors, untrusted = [], []
    add = errors.append
    result = {"ok": False, "trusted": False, "errors": errors, "untrusted": untrusted,
              "migration": None}
    if not isinstance(cert, dict):
        add("not an object")
        return result

    if cert.get("format") != FORMAT:
        add(f"format must be {FORMAT}")
    sid_id = cert.get("id")
    if not isinstance(sid_id, str) or not ID_RE.match(sid_id) or len(sid_id) > 96:
        add("id must match sid_<slug>")
    if not _is_int(cert.get("version")) or cert["version"] < 1:
        add("version must be an integer >= 1")
    if cert.get("status") not in STATUSES:
        add("status must be cast|live|suspended|retired")
    if not _is_time(cert.get("born_at")):
        add("born_at must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)")
    if not _is_time(cert.get("updated")):
        add("updated must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)")
    elif _is_time(cert.get("born_at")) and cert["updated"] < cert["born_at"]:
        add("updated must not be before born_at")

    ident = cert.get("identity")
    if not isinstance(ident, dict):
        add("identity is required")
    else:
        if not isinstance(ident.get("name"), str) or not ident["name"]:
            add("identity.name is required")
        if ident.get("type") != "agent":
            add('identity.type must be "agent"')
        parent = ident.get("parent")
        if parent is not None and (not isinstance(parent, str) or not ID_RE.match(parent)):
            add("identity.parent must be a sid id or null")

    # bindings: typed public keys, each proving possession of its key
    bindings = cert.get("bindings", [])
    seen = set()
    if not isinstance(bindings, list):
        add("bindings must be an array")
        bindings = []
    for i, b in enumerate(bindings):
        where = f"bindings[{i}]"
        if not isinstance(b, dict):
            add(f"{where} must be an object")
            continue
        bid = b.get("id")
        if not isinstance(bid, str) or not SLUG_RE.match(bid):
            add(f"{where}.id must be a slug")
        elif bid in seen:
            add(f"{where}.id {bid} is used twice")
        else:
            seen.add(bid)
        if not isinstance(b.get("type"), str) or not SLUG_RE.match(b["type"]):
            add(f"{where}.type must be a slug")
        if b.get("alg") not in sigs.ALGS:
            add(f"{where}.alg must be one of {'|'.join(sigs.ALGS)}")
        elif BINDING_ALG.get(b.get("type"), b["alg"]) != b["alg"]:
            add(f"{where}: a {b['type']} binding must use {BINDING_ALG[b['type']]}")
        if not isinstance(b.get("public_key"), str) or not HEX64.match(b["public_key"]):
            add(f"{where}.public_key must be 64-hex")
        if not _is_time(b.get("added_at")):
            add(f"{where}.added_at must be RFC 3339 UTC")
        if not isinstance(b.get("proof"), str) or not HEX128.match(b["proof"]):
            add(f"{where}.proof must be a 128-hex signature")
        elif not sigs.verify(str(b.get("alg")), str(b.get("public_key")),
                             bind_message(str(sid_id), b), b["proof"]):
            add(f"{where}: proof of possession does not verify")

    ext = cert.get("extensions")
    if ext is not None:
        if not isinstance(ext, dict):
            add("extensions must be an object")
        else:
            for ns, val in ext.items():
                if not NS_RE.match(ns) or not isinstance(val, dict):
                    add(f"extensions.{ns} must be a namespaced object")

    h = cert.get("hash")
    if not isinstance(h, str) or not HEX64.match(h):
        add("hash must be 64-hex")
    elif sid_hash(cert) != h:
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

    life = cert.get("lifecycle")
    history = []
    if not isinstance(life, dict):
        add("lifecycle is required")
    else:
        if life.get("state") != cert.get("status"):
            add("lifecycle.state must equal status")
        history = life.get("history", [])
        if not isinstance(history, list) or any(
                not isinstance(e, dict) or e.get("state") not in STATUSES or not _is_time(e.get("at"))
                for e in history):
            add("lifecycle.history must be an array of {state, at}")
            history = []

    if isinstance(previous, dict):
        if cert.get("previous_hash") != previous.get("hash"):
            add("previous_hash does not match the hash of the supplied previous version")
        if cert.get("version") != (previous.get("version") or 0) + 1:
            add("version is not previous.version + 1")
        if cert.get("id") != previous.get("id"):
            add("id differs from the previous version")
        if cert.get("born_at") != previous.get("born_at"):
            add("born_at differs from the previous version")
        if (cert.get("issuer") or {}).get("id") != (previous.get("issuer") or {}).get("id"):
            add("issuer.id differs from the previous version")
        if previous.get("status") == "retired":
            add("the previous version is retired; no further versions are allowed")
        if _is_time(cert.get("updated")) and _is_time(previous.get("updated")) \
                and cert["updated"] < previous["updated"]:
            add("updated is earlier than the previous version")
        prev_history = (previous.get("lifecycle") or {}).get("history", [])
        if isinstance(prev_history, list) and history[:len(prev_history)] != prev_history:
            add("lifecycle.history does not extend the previous version's history")

    for path in _find_secrets(_body(cert)):
        add(f"{path} must not be present: certificates carry no secrets")

    issuer_errors, issuer_untrusted, issuer_ok = _issuer_check(cert, trust, cert.get("updated"))
    errors.extend(issuer_errors)
    untrusted.extend(issuer_untrusted)

    migrated = (cert.get("provenance") or {}).get("migrated_from") if isinstance(cert.get("provenance"), dict) else None
    if migrated is not None:
        if not isinstance(migrated, dict) or migrated.get("format") != LEGACY_FORMAT \
                or not isinstance(migrated.get("id"), str) or not _is_int(migrated.get("version")) \
                or not isinstance(migrated.get("hash"), str) or not HEX64.match(migrated["hash"]):
            add("provenance.migrated_from must be {format: sid/0.1, id, version, hash}")
        elif legacy is None:
            result["migration"] = "unchecked"
        else:
            import sid as sid01
            old = sid01.verify_sid(legacy)
            if not old["ok"]:
                add("the supplied sid/0.1 certificate does not verify: " + "; ".join(old["errors"][:2]))
            elif (legacy.get("id"), legacy.get("version"), legacy.get("hash")) != (
                    migrated["id"], migrated["version"], migrated["hash"]):
                add("provenance.migrated_from does not match the supplied sid/0.1 certificate")
            else:
                result["migration"] = "verified"

    if cert.get("status") != "live":
        untrusted.append(f"status is {cert.get('status')}, not live")
    if isinstance(head, dict) and (head.get("version"), head.get("hash")) != (cert.get("version"), cert.get("hash")):
        untrusted.append("a newer version of this certificate is known")

    result["ok"] = not errors
    result["trusted"] = result["ok"] and issuer_ok and not untrusted
    return result


# ── runtime statement ────────────────────────────────────────────────────────
def verify_runtime(stmt, cert, trust=None, now=None, head=None) -> dict:
    """Verify a sid-runtime/0.2 statement against its certificate.

    A runtime statement says: this installation may serve as this agent, at
    these endpoints, with at most these capabilities, until it expires. It is
    signed by the certificate's issuer and is separate from the certificate so
    that a runtime can change without minting a new identity version.
    """
    errors, untrusted = [], []
    add = errors.append
    result = {"ok": False, "trusted": False, "errors": errors, "untrusted": untrusted}
    if not isinstance(stmt, dict):
        add("not an object")
        return result
    cert_result = verify_sid(cert, trust=trust, head=head)
    if not cert_result["ok"]:
        add("the certificate does not verify: " + "; ".join(cert_result["errors"][:2]))
        return result
    untrusted.extend(cert_result["untrusted"])

    if stmt.get("format") != RUNTIME_FORMAT:
        add(f"format must be {RUNTIME_FORMAT}")
    if stmt.get("sid") != cert.get("id"):
        add("sid does not name this certificate")
    if not isinstance(stmt.get("runtime_id"), str) or not SLUG_RE.match(stmt["runtime_id"]):
        add("runtime_id must be a slug")
    adapter = stmt.get("adapter")
    if not isinstance(adapter, dict) or not isinstance(adapter.get("kind"), str) or not adapter.get("kind"):
        add("adapter must be {kind, version?}")
    if not _is_time(stmt.get("issued_at")) or not _is_time(stmt.get("expires_at")):
        add("issued_at and expires_at must be RFC 3339 UTC")
    elif stmt["expires_at"] <= stmt["issued_at"]:
        add("expires_at must be after issued_at")
    if (stmt.get("issuer") or {}).get("id") != (cert.get("issuer") or {}).get("id"):
        add("a runtime statement must be signed by the certificate's issuer")

    by_id = {b.get("id"): b for b in cert.get("bindings", []) if isinstance(b, dict)}
    endpoints = stmt.get("endpoints", [])
    if not isinstance(endpoints, list) or not endpoints:
        add("endpoints must be a non-empty array")
        endpoints = []
    for i, ep in enumerate(endpoints):
        where = f"endpoints[{i}]"
        if not isinstance(ep, dict) or ep.get("type") not in ENDPOINT_TYPES \
                or not isinstance(ep.get("address"), str) or not ep.get("address"):
            add(f"{where} must be {{type, address}} with a known type")
            continue
        ref = ep.get("binding")
        needs = ENDPOINT_BINDING.get(ep["type"])
        if needs and ref is None:
            add(f"{where}: a {ep['type']} endpoint must name a {needs} binding")
        if ref is not None:
            bound = by_id.get(ref)
            if bound is None:
                add(f"{where}: binding {ref} is not in the certificate")
            elif needs and bound.get("type") != needs:
                # A key of one protocol never stands in for another's.
                add(f"{where}: a {ep['type']} endpoint cannot use a {bound.get('type')} binding")

    declared = set(((cert.get("capabilities") or {}).get("permissions")) or [])
    caps = stmt.get("capabilities", [])
    if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps):
        add("capabilities must be an array of strings")
    else:
        extra = sorted(set(caps) - declared)
        if extra:
            add("capabilities exceed the certificate's permissions: " + ", ".join(extra))

    h = stmt.get("hash")
    if not isinstance(h, str) or not HEX64.match(h):
        add("hash must be 64-hex")
    elif sid_hash(stmt) != h:
        add("hash does not match the canonical body")
    for path in _find_secrets(_body(stmt)):
        add(f"{path} must not be present: statements carry no secrets")

    issuer_errors, issuer_untrusted, issuer_ok = _issuer_check(stmt, trust, stmt.get("issued_at"))
    errors.extend(issuer_errors)
    untrusted.extend(issuer_untrusted)

    if now is None:
        untrusted.append("no current time supplied; expiry not checked")
    elif not _is_time(now):
        add("now must be RFC 3339 UTC")
    elif _is_time(stmt.get("issued_at")) and _is_time(stmt.get("expires_at")):
        if now < stmt["issued_at"]:
            untrusted.append("the statement is not valid yet")
        elif now >= stmt["expires_at"]:
            untrusted.append("the statement has expired")

    result["ok"] = not errors
    result["trusted"] = result["ok"] and issuer_ok and not untrusted
    return result


# ── migration from sid/0.1 ───────────────────────────────────────────────────
def migrate_from_01(legacy: dict, issuer: dict, updated: str) -> dict:
    """Deterministically map a sid/0.1 certificate to an UNSIGNED sid/0.2 body.

    The result starts a new chain (version 1) that records where it came from.
    It is never called equivalent to the old document: the old hash is quoted,
    not reproduced. Application-specific 0.1 fields move under `extensions`.
    The 0.1 `npub` is NOT turned into a binding — a binding needs the key
    holder's proof of possession, which a migration cannot supply. It is kept
    under extensions.legacy until the holder adds a real binding in a later
    version.
    """
    ident = legacy.get("identity") or {}
    memory = legacy.get("memory") or {}
    ifa = {k: ident[k] for k in ("odu_link", "odu_primary", "odu_secondary", "odu", "calabash") if k in ident}
    ifa.update({k: memory[k] for k in ("glyph_root", "birth_glyph") if memory.get(k) is not None})
    extensions = {}
    if ifa:
        extensions["ifa"] = ifa
    for src, ns in (("genesis", "genesis"), ("time", "time")):
        if isinstance(legacy.get(src), dict) and legacy[src]:
            extensions[ns] = legacy[src]
    old_keys = {k: ident[k] for k in ("npub", "principal") if ident.get(k) is not None}
    if old_keys:
        extensions["legacy"] = old_keys

    provenance = dict(legacy.get("provenance") or {})
    provenance["migrated_from"] = {"format": LEGACY_FORMAT, "id": legacy.get("id"),
                                   "version": legacy.get("version"), "hash": legacy.get("hash")}
    life = legacy.get("lifecycle") or {}
    out = {
        "format": FORMAT,
        "id": legacy.get("id"),
        "version": 1,
        "previous_version": None,
        "previous_hash": "none",
        "status": legacy.get("status"),
        "born_at": legacy.get("born_at"),
        "updated": updated,
        "issuer": {"id": issuer["id"], "kid": issuer["kid"]},
        "identity": {k: v for k, v in (("name", ident.get("name")), ("type", "agent"),
                                       ("description", ident.get("description")),
                                       ("parent", ident.get("parent"))) if v is not None},
        "bindings": [],
        "capabilities": legacy.get("capabilities") or {},
        "memory": {k: memory[k] for k in ("locator", "namespace_root") if memory.get(k) is not None},
        "lifecycle": {"state": legacy.get("status"), "history": list(life.get("history") or [])},
        "provenance": provenance,
        "extensions": extensions,
        "changelog": list(legacy.get("changelog") or [])
        + [f"migrated from sid/0.1 v{legacy.get('version')} {legacy.get('hash')}"],
    }
    if isinstance(legacy.get("appendix"), dict) and legacy["appendix"]:
        out["appendix"] = legacy["appendix"]
    return out


def verify_any(cert, **kwargs) -> dict:
    """Dispatch on `format`. Unknown formats are rejected, never guessed."""
    fmt = cert.get("format") if isinstance(cert, dict) else None
    if fmt == FORMAT:
        return verify_sid(cert, **kwargs)
    if fmt == LEGACY_FORMAT:
        import sid as sid01
        r = sid01.verify_sid(cert, kwargs.get("previous"))
        # sid/0.1 carries no issuer signature, so it can never be `trusted`.
        return {"ok": r["ok"], "trusted": False, "errors": r["errors"],
                "untrusted": ["sid/0.1 has no issuer signature"], "migration": None}
    return {"ok": False, "trusted": False, "errors": [f"unknown format {fmt!r}"],
            "untrusted": [], "migration": None}
