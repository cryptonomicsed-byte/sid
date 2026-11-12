"""Canonical JSON for the SID hash — the Python side of the byte-identical pair.

A SID's `hash` must be identical whether computed here (the OKF pipeline is
Python) or in TypeScript (`implementations/typescript/src/canonical.ts`). JS
numbers are all doubles, so the canonical form normalizes integral floats to
ints: Python's json.dumps writes 4.0 as "4.0" while JSON.stringify writes "4".
Normalizing first keeps both sides in agreement.
"""
from __future__ import annotations

import hashlib
import json


def _canon_numbers(v):
    if isinstance(v, dict):
        return {k: _canon_numbers(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_canon_numbers(x) for x in v]
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return v


def _prune(v):
    """Drop empty arrays/objects as object values: `"threats": []` is the
    same as a missing `threats` for identity purposes. Applied bottom-up so
    `{"swot": {"threats": []}}` prunes to `{}` and then away entirely."""
    if isinstance(v, (list, tuple)):
        return [_prune(x) for x in v]
    if isinstance(v, dict):
        out = {}
        for k in sorted(v):
            pv = _prune(v[k])
            if pv == [] or pv == {}:
                continue
            out[k] = pv
        return out
    return v


def canonical_json(cert: dict) -> str:
    body = _canon_numbers(
        {k: v for k, v in cert.items() if k != "hash" and not k.startswith("_")}
    )
    return json.dumps(_prune(body), sort_keys=True, separators=(",", ":"))


def canonical_hash(cert: dict) -> str:
    return hashlib.sha256(canonical_json(cert).encode()).hexdigest()


#: SID acting keys — the fields an agent acts on. Genesis, time, provenance,
#: changelog and appendix are attestation/history, never acting state.
#: MUST match ACTING_KEYS in implementations/typescript/src/sid.ts exactly.
ACTING_KEYS = (
    "identity",
    "capabilities",
    "memory",
    "lifecycle",
    "status",
)


def acting_fields(cert: dict) -> dict:
    return {k: cert[k] for k in ACTING_KEYS if k in cert}


def acting_hash(cert: dict) -> str:
    """SHA-256 of the canonical JSON of the acting layer only."""
    return hashlib.sha256(canonical_json(acting_fields(cert)).encode()).hexdigest()
