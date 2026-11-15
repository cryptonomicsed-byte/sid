# SID — `sid/0.2`, the neutral profile

**Status:** draft standard · 2026-11-15
**Supersedes for new issuance:** `sid/0.1`. Existing `sid/0.1` documents stay valid under
their own rules and are never rewritten (§11).

## 1. What changed, and why

`sid/0.1` proves that a document has not been altered: its hash recomputes and its versions
chain. It does not prove who issued it. Anyone can mint a well-formed `sid/0.1` certificate
for any name, and a verifier holding only the document cannot tell.

`sid/0.2` adds authority to integrity:

1. **Issuer signature.** Every certificate is signed by its issuer. The verifier decides
   which issuers it trusts by supplying *trust anchors*; nothing in the certificate can
   make itself trusted.
2. **Key bindings with proof of possession.** A public key appears in a certificate only
   with a signature, made by that key, over the binding. Listing someone else's key is
   detectable.
3. **Typed bindings.** A Nostr key and a LAN-calling key are different kinds of key. Each
   binding names its type, and a runtime endpoint of one protocol cannot be served by a
   key of another.
4. **Runtime statements.** Which installation currently serves as the agent, and where, is
   a separate signed document. A runtime can change without a new identity version.
5. **Neutral core.** No application-specific field is required. Anything specific to one
   ecosystem lives under `extensions`, hashed but not interpreted.

A SID is not a Nostr key, a model name, a business or a human account. It grants no
permission to act: `capabilities` declares what an agent is built to do, and spending,
tool use and data access are authorised separately by the party whose resources they are.

## 2. Two verdicts

A verifier returns two booleans.

| verdict | meaning |
|---|---|
| `ok` | The document is well formed and internally consistent: hashes recompute, chain rules hold, every binding's proof of possession verifies, and the issuer signature verifies if its key is known to the verifier. |
| `trusted` | `ok`, **and** the issuer signature verified against a supplied trust anchor whose key was valid when the document was signed, **and** `status` is `live`, **and**, when the verifier knows the newest version, this is it. |

Act only on `trusted`. `ok` without `trusted` means "not forged, as far as can be checked,
but not established" — for example, no anchors were supplied, or the agent is suspended.
Reasons a document is not trusted are reported separately from errors.

## 3. Certificate shape

```json
{
  "format": "sid/0.2",
  "id": "sid_<slug>",
  "version": 1,
  "previous_version": null,
  "previous_hash": "none",
  "hash": "<64-hex>",
  "acting_hash": "<64-hex>",
  "status": "live",
  "born_at": "2026-11-12T09:00:00Z",
  "updated": "2026-11-12T09:05:00Z",
  "issuer": { "id": "<issuer id>", "kid": "<key id>" },
  "identity": { "name": "…", "type": "agent", "description": "…", "parent": null, "controller": "…" },
  "bindings": [ … ],
  "capabilities": { "skills": [], "permissions": [], "namespaces": [] },
  "memory": { "provider": "…", "locator": null, "namespace_root": null },
  "lifecycle": { "state": "live", "history": [ { "state": "cast", "at": "…" } ] },
  "provenance": { "profile_id": "…", "manifest_hash": null, "migrated_from": { … } },
  "extensions": { "<namespace>": { … } },
  "changelog": [ "v1: issued" ],
  "appendix": { },
  "proof": { "alg": "ed25519", "signature": "<128-hex>" }
}
```

Required: `format`, `id`, `version`, `hash`, `acting_hash`, `status`, `born_at`, `updated`,
`issuer`, `identity` (`name`, `type: "agent"`), `lifecycle` (`state`), `proof`.

- **Timestamps** are RFC 3339 UTC to the second, written `YYYY-MM-DDTHH:MM:SSZ`. No offsets,
  no fractions: one spelling, so string comparison is time comparison.
- **`identity.controller`** names who operates the agent (a tenant, a person). It is a
  label, not a credential.
- **`identity.parent`** is a SID id or `null`.
- **`extensions`** maps a namespace (`[a-z0-9][a-z0-9_.-]*`) to an object. The core verifier
  does not interpret it. It is covered by `hash`.
- **`appendix`** is for humans. It is not quotable and not in `acting_hash`.
- No field anywhere may be named `seed`, `mnemonic`, `private_key`, `secret_key`, `nsec`
  or `secret`. A certificate is publishable.

## 4. Bindings

```json
{ "id": "nostr-main", "type": "nostr", "alg": "bip340", "public_key": "<64-hex>",
  "added_at": "2026-11-12T09:00:00Z", "purposes": ["messaging", "call-signaling"],
  "proof": "<128-hex>" }
```

- `id` is a slug, unique within the certificate. Runtime endpoints refer to it.
- `type` names the protocol family the key belongs to. Two types fix their algorithm:
  `nostr` → `bip340`, `meshenger` → `ed25519`. Other types may use either suite.
- `proof` is the key's own signature over the **bind message** (§6). It binds the key to
  this SID `id`, so a binding copied into another agent's certificate fails.
- A binding is removed or replaced by issuing a new version. There is no in-place edit.

Bindings are how a relying party goes from "a message signed by key K" to "from agent
`sid_x`": find a trusted certificate whose bindings contain K with the right type.

## 5. Hashing

Canonical JSON is unchanged from `sid/0.1` (§5 there): prune empty arrays and objects that
are object values, sort keys, compact separators, escape non-ASCII.

```
hash        = sha256(canonicalJson(cert minus "hash", "proof" and every "_"-prefixed key))
acting_hash = sha256(canonicalJson({ identity, bindings, capabilities, memory, lifecycle, status }))
```

`proof` is excluded from `hash` because it signs the hash. `acting_hash` is inside `hash`.
Acting keys are exactly `identity`, `bindings`, `capabilities`, `memory`, `lifecycle`,
`status`: a consumer that reloads on `acting_hash` reloads when a key is bound or removed
and ignores a changelog edit.

## 6. Signatures

Two suites. Public keys are 32 bytes and signatures 64 bytes, lowercase hex.

| `alg` | scheme | signed bytes |
|---|---|---|
| `ed25519` | RFC 8032 Ed25519 | the UTF-8 message |
| `bip340` | BIP-340 Schnorr over secp256k1, x-only key | SHA-256 of the UTF-8 message |

Messages are line-separated and start with the format, so a signature made for one purpose
cannot be replayed for another:

```
issue message:  "<format>\nissue\n<hash>"                    format = sid/0.2 or sid-runtime/0.2
bind message:   "sid/0.2\nbind\n<sid id>\n<binding id>\n<alg>\n<public_key>"
```

`proof.signature` is the issuer's signature over the issue message. A verifier that does
not implement a suite reports the signature as failing; it never skips the check.

## 7. Trust anchors

Supplied by the relying party, out of band. Never read from the certificate.

```json
{ "issuers": { "<issuer id>": { "keys": [
  { "kid": "root-1", "alg": "ed25519", "public_key": "<64-hex>",
    "not_before": "2026-01-01T00:00:00Z", "not_after": null,
    "revoked_at": null, "compromised": false } ] } } }
```

The issuer check, in order:

1. `issuer` and `proof` are well formed, else **error**.
2. No anchors, unknown issuer, or unknown `kid` → **not trusted** (not an error: the
   document may be genuine, the verifier just cannot tell).
3. `proof.alg` differs from the key's `alg`, or the signature does not verify → **error**.
   A signature that fails under a known key is a forgery.
4. The key is `compromised` → **not trusted**, whatever the date.
5. The signing time (`updated` for a certificate, `issued_at` for a runtime statement) is
   before `not_before`, at or after `not_after`, or at or after `revoked_at` → **not trusted**.

**Rotation** is adding a key with a later `not_before`; old signatures stay valid.
**Revocation** sets `revoked_at`; signatures dated before it stay valid.
**Compromise** sets `compromised`, because a stolen key can sign any date: everything it
signed stops being trusted and its certificates must be re-issued under another key.

## 8. Chain and lifecycle

Chain rules are those of `sid/0.1` §6: v1 has `previous_version: null` and
`previous_hash: "none"`; later versions name the previous version number and hash.

When the previous version is supplied, a verifier also requires:

- the same `id`, `born_at` and `issuer.id` (the issuer's key may rotate; the issuer may not
  change — handing an agent to another issuer is a retirement plus a new SID naming it as
  `parent`);
- `updated` not earlier than the previous version's;
- `lifecycle.history` extends the previous history without rewriting it;
- the previous version is not `retired`. Retirement is terminal.

`lifecycle.state` equals `status`. Statuses are those of `sid/0.1`: `cast`, `live`,
`suspended`, `retired`. Only `live` is trusted.

**Knowing the head.** A suspended or retired agent still has older `live` versions in
circulation. A verifier that knows the newest version (from a registry, a relay, or the
issuer) passes it as `head: {version, hash}`; any other version is then not trusted. A
verifier with no source for the head is trusting that the copy it holds is current, and
should say so.

## 9. Runtime statements — `sid-runtime/0.2`

```json
{
  "format": "sid-runtime/0.2",
  "sid": "sid_santinos-agent",
  "runtime_id": "agent-voice-santinos",
  "adapter": { "kind": "agent-voice", "version": "0.1.0" },
  "endpoints": [
    { "type": "nostr", "address": "wss://relay.example", "binding": "nostr-main" },
    { "type": "meshenger-lan", "address": "192.0.2.10:10001", "binding": "lan-main" },
    { "type": "sip", "address": "sip:95001@pbx.example" }
  ],
  "capabilities": ["kb.search", "call.transfer"],
  "issued_at": "2026-11-13T00:00:00Z",
  "expires_at": "2026-12-13T00:00:00Z",
  "issuer": { "id": "<issuer id>", "kid": "<key id>" },
  "hash": "<64-hex>",
  "proof": { "alg": "ed25519", "signature": "<128-hex>" }
}
```

A runtime statement says: this installation may serve as this agent, at these endpoints,
with at most these capabilities, until it expires. Rules:

- The certificate it names must itself verify; its untrusted reasons carry over.
- It is signed by the **certificate's issuer** (same `issuer.id`).
- `endpoints[].type` is one of `nostr`, `meshenger-lan`, `sip`, `a2a`, `mcp`, `https`.
  A `nostr` endpoint must name a `nostr` binding and a `meshenger-lan` endpoint a
  `meshenger` binding. An endpoint may never use a binding of another protocol's type.
- `capabilities` is a subset of the certificate's `capabilities.permissions`. A runtime
  never has more than its identity declares.
- `hash` covers everything except `hash`, `proof` and `_`-prefixed keys.
- It is trusted only between `issued_at` (inclusive) and `expires_at` (exclusive). A
  verifier with no clock cannot trust it.

Keep lifetimes short. Revoking a runtime early is done by suspending the agent or by not
renewing; there is no separate revocation list.

## 10. Conformance

A document claiming `sid/0.2` is conformant only when a verifier returns `ok`. Schema
validity (`schema/sid-0.2.schema.json`, `schema/sid-runtime-0.2.schema.json`) is necessary
and proves nothing about hashes, signatures or the chain.

`conformance/v0.2/vectors.json` holds self-contained cases — documents, options and the
expected `ok`, `trusted`, and error or untrusted reason. Every implementation must agree
with every vector. The Python reference generates them
(`conformance/v0.2/generate.py`); signatures are deterministic, so regeneration is
byte-identical. The keys in `conformance/v0.2/test-keys.json` are public test keys.

## 11. `sid/0.1` and migration

`sid/0.1` documents are verified by the `sid/0.1` rules, unchanged. They carry no issuer
signature, so they are never `trusted` in the sense of §2.

Migration issues a **new** `sid/0.2` chain (version 1) that records its origin:

```json
"provenance": { "migrated_from": { "format": "sid/0.1", "id": "…", "version": 3, "hash": "<64-hex>" } }
```

The mapping is deterministic (`migrate_from_01` / `migrateFrom01`):

| `sid/0.1` | `sid/0.2` |
|---|---|
| `identity.name`, `description`, `parent` | `identity` |
| `identity.odu_*`, `odu`, `calabash`; `memory.glyph_root`, `birth_glyph` | `extensions.ifa` |
| `genesis`, `time` | `extensions.genesis`, `extensions.time` |
| `identity.npub`, `identity.principal` | `extensions.legacy` |
| `capabilities`, `memory.locator`, `memory.namespace_root`, `lifecycle`, `changelog`, `appendix` | same |

Three rules:

- The old hash is quoted, never reproduced. The new document has its own hash and is not
  called equivalent to the old one.
- The old `npub` does **not** become a binding. A binding needs the key holder's proof of
  possession, which a migration cannot supply. The holder adds a real binding in a later
  version.
- A verifier given the old document checks that it verifies under `sid/0.1` and matches
  `migrated_from`, and reports the migration as `verified`. Without it, `unchecked`.

## 12. Security notes

- **Trust is the verifier's.** A certificate that names a well-known issuer id proves
  nothing until the signature verifies under that issuer's anchored key.
- **A valid SID authorises nothing.** It establishes who an agent is. What it may spend,
  call or read is a separate, scoped, expiring grant.
- **Backdating.** `updated` is written by the issuer. Key validity windows therefore
  protect against a *retired* key, not a *stolen* one; mark stolen keys `compromised`.
- **Reference signers.** The Python reference signs with plain big-integer arithmetic. It
  is correct and not constant-time: use it for fixtures and tooling, and sign with
  production issuer keys in hardened code.
- **Format.** A parser rejects an unknown `format`. `sid/0.2` is never reinterpreted
  silently; an incompatible change takes a new format name.
