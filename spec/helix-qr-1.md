# `helix-qr/1`: signed QR contact references

A QR code that opens a conversation with a business or an agent. It is a **pointer**,
never an identity: it carries no key, no address and no secret. Everything a caller will
rely on is fetched, signed, and verified. Builds on `sid/0.2` (document hash, issuer
proof, trust anchors, certificates, runtime statements); read `sid-0.2.md` first.

Anyone can print a QR code, so a scanned code proves nothing by being scanned. The
questions are: who issued this, is it still good, is the page it sent me to the page the
issuer meant, and is the contact it leads to really the agent it names.

## 1. Two documents

**Reference**, what the QR carries. Signed by an issuer in the verifier's trust anchors.

```json
{ "format": "helix-qr/1", "kind": "agent", "sid": "sid_santinos-agent",
  "card": { "id": "dna_pizza01", "hash": "<64-hex>" },
  "resolver": "https://contact.example", "domain": "santinos.example",
  "issued_at": "2026-11-14T00:00:00Z", "expires_at": "2027-11-14T00:00:00Z",
  "nonce": "<16 random bytes, base64url>",
  "issuer": { "id": "issuer:helix-root", "kid": "root-1" },
  "hash": "<64-hex>", "proof": { "alg": "ed25519", "signature": "<128-hex>" } }
```

`kind` is `agent` or `business` (a business reference must carry a `card`, the CARD id
and hash it expects). `domain` is optional and informational. `hash` and `proof` are
exactly those of `sid/0.2` (§4 there): hash of the canonical JSON without `hash`/`proof`,
signature over `helix-qr/1\nissue\n<hash>`. Unknown fields are rejected, so nothing can be
smuggled in beside the signed ones. Lifetime is at most 400 days.

**Resolution**, what the resolver serves for a reference. Signed by the same issuer.

```json
{ "format": "helix-qr-resolution/1", "reference_hash": "<the reference's hash>",
  "resolver": "https://contact.example", "status": "active",
  "issued_at": "…", "fresh_until": "…",
  "certificate": { "format": "sid/0.2", … }, "runtime": { "format": "sid-runtime/0.2", … },
  "card": { "id": "…", "hash": "…" }, "issuer": {…}, "hash": "…", "proof": {…} }
```

`status` is `active`, `suspended`, `revoked` or `superseded` (+ `superseded_by`).
Only an active resolution carries `certificate` and `runtime`. `fresh_until` is at most
24 hours after `issued_at`. Resolutions are short-lived on purpose: that is how
revocation reaches clients (§5).

## 2. The wire form

```
https://<resolver origin>/q/<base64url, no padding, of the canonical JSON of the reference>
```

An ordinary https URL, so a phone's camera opens the resolver's page and the app can
claim the link. No query, no fragment, no userinfo, payload ≤ 4096 characters; the
origin is lowercase ASCII.

**The resolver is a public DNS name**: an https origin, no path, no IP address
(v4 or v6), not `localhost`, not a private-use suffix (`.local .internal .lan .home
.home.arpa .corp .intranet .private .localdomain .localhost`), at least two labels with an
alphabetic TLD, default port omitted. A public QR never carries a private address; LAN
contact is a separate, local advertisement (not specified here).

## 3. Verifying a reference

Verdicts have the `sid` shape: `ok` (well-formed, untampered), `trusted` (ok, anchored,
current, bound), `errors`, `untrusted`.

1. Parse the URL (§2). Anything else is an **error**.
2. Structure: every field above, nothing else; secrets (`nsec`, `private_key`, …) are an error.
3. `hash` must match the document (**error**: tampered).
4. Issuer: the issuer and key must be in the supplied trust anchors and valid when the
   reference was issued (not revoked, not compromised); the signature must verify. A
   signature that fails against a key we hold is an **error**; an issuer or key we do not
   know is **untrusted**.
5. **Domain binding**: the origin of the URL that was scanned must equal the signed
   `resolver`. A perfectly signed reference re-hosted on another domain is an **error**.
   Verified from a bare document with no URL, this is *untrusted*: it was not checked.
6. Expiry: at or after `expires_at` is *untrusted* (expired); before `issued_at − 5 min`
   is *untrusted* (not valid yet); no clock is *untrusted*.

## 4. Verifying a resolution

`verify_resolution(res, ref, trust, now, fetched_from, pin)`, in two layers.

**Envelope** (no `sid` knowledge needed; the resolver does this too): structure; hash;
issuer signature; the issuer **id** must be the reference's issuer's; `reference_hash` must
equal the reference's `hash` (**error** otherwise: a resolution for another contact);
`resolver` must equal the reference's; **`fetched_from` must equal the reference's resolver**
(**error** otherwise: a malicious resolver redirect); `now ≥ fresh_until` is *untrusted*
(stale: what a replayed old response looks like); any status other than `active` is
*untrusted* with the status named.

**Contact** (needs `sid/0.2`): an active resolution must carry a certificate and a
runtime. The certificate must verify (`sid02.verify_sid`) and **its `id` must be the
reference's `sid`**; the runtime statement must verify against that certificate
(`sid02.verify_runtime`, with its own expiry). The certificate's and runtime's untrusted
reasons carry over. If the reference names a CARD, the resolution's card must have the
same id (hash differences are a note: the card changed since the code was printed).

### Typed endpoints

From the verified runtime only. **A key is never assumed to be another protocol's key**:
the public key of a `nostr` endpoint is the `bip340` key of the certificate binding the
endpoint names (sid/0.2 already refuses a nostr endpoint on a non-nostr binding); keys in
free text are not read. Published:

| type | what is published |
|---|---|
| `nostr` | `{relay: wss://…, binding, alg: "bip340", public_key}` if the relay is a public `wss://` name |
| `sip` | `{uri: sip:user@host}` |
| `a2a`, `mcp`, `https` | `{url: https://public-host/…}` |
| `meshenger-lan` | **never**, with a note; LAN addresses are not published through a public resolver |

Anything that does not meet the rule is omitted with a note, never rewritten.

### Pinning, rotation, revocation (client side)

When the user confirms a contact the client stores a **pin** `{sid, version, hash,
certificate}`. On every later resolution: a different `sid` is an error (the contact
became someone else); an older version is an error (rollback); the same version with a
different hash is an error (fork); a newer version must **extend the pinned chain**
(`verify_sid(…, previous=pin.certificate)`), otherwise an error. If any binding key was
added, removed or rotated the result carries `needs_confirmation: true` and the list of
changes: the app asks the user again. A first contact always needs confirmation.
Suspending or retiring the agent (`sid/0.2` status) or a resolution status of `revoked`
or `superseded` makes the contact untrusted; the app shows why instead of connecting.

## 5. The resolver

A resolver **holds no signing key and is untrusted for content**. It stores resolutions
the issuer signed, serves them, and refuses to serve anything that does not verify.
Compromising it lets an attacker withhold a contact or serve a stale one (clients reject
by `fresh_until`), not forge one. It serves a reference only if the reference verifies
under its trust anchors, names *this* resolver, and was requested at this host (421
otherwise). A revoked or superseded reference answers **410 with the signed document**, so
the client can say why. Publishing needs a bearer token *and* a valid issuer signature;
resolutions only move forward in time, revocation wins a tie, and **a revoked or
superseded contact never becomes active again**: issue a new QR code.

## 6. Threats and where they are tested

| Threat | Rule | Vectors (conformance/qr) |
|---|---|---|
| Edited QR (other agent, other resolver) | hash + signature | `reference-tampered-*`, `reference-signed-by-attacker-*` |
| Real QR printed over by a copy that sends you elsewhere | domain binding | `reference-copied-to-another-*`, `wire-userinfo-trick` |
| Resolver that answers with someone else's contact | `reference_hash`, certificate id = `sid` | `envelope-for-another-reference`, `contact-certificate-of-another-agent` |
| Resolver or redirect on another origin | `fetched_from` | `envelope-fetched-from-another-origin` |
| Old response replayed after revocation | `fresh_until`, no reactivation | `envelope-stale*`, resolver tests |
| Expired or revoked contact | expiry, status | `reference-expired`, `envelope-revoked/suspended/superseded` |
| A nostr key presented for a LAN key, or the reverse | typed endpoints from verified bindings | `contact-nostr-endpoint-on-a-lan-key` |
| Private addresses leaking through a public QR | resolver origin and endpoint rules | `reference-resolver-*`, `contact-private-relay-is-omitted` |
| Phishing display name | no free-text name in the reference; name comes from the verified certificate | structure vectors |
| Key rotation or takeover of a saved contact | pins | `pin-*` |
| Hostile payloads | strict parsing, no unknown fields, ASCII-only patterns | `wire-*`, `reference-non-ascii-*` |

## 7. Conformance

`conformance/qr/vectors.json` (111 vectors, generated by `conformance/qr/generate.py`) holds
self-contained cases: subject, trust anchors, clock and expected verdict. Kinds:
`reference`, `resolution-envelope`, `resolution`. The Python reference and the TypeScript
implementation pass all of them; the Go implementation (HELIX gateway, the resolver) passes the
`reference` and `resolution-envelope` vectors and lists, by name, the ones it does not
run (`resolution` needs `sid/0.2` certificates, which the resolver deliberately does not
verify, and one vector needs a BIP-340 issuer key).

## 8. Not specified here

Camera scanning and the contact UI; LAN/offline contact advertisement (it needs a local,
separately signed form); a revocation transparency log; delegated resolver keys.
