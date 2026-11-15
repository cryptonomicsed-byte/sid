/**
 * helix-qr/1 tests. Run: npm test
 *
 * The shared vectors (conformance/qr/vectors.json) are produced by the Python
 * reference; passing them here is the proof the two implementations agree.
 */
export {};

const { test } = require("node:test");
const assert = require("node:assert/strict");
const qr = require("../qr");
const sid = require("../sid02");

const V = "../../../../conformance/qr/";
const { vectors } = require(V + "vectors.json");

function run(v: any): any {
  if (v.kind === "reference") return qr.verifyReference(v.subject, { trust: v.trust, now: v.now });
  if (v.kind === "resolution-envelope") return qr.checkResolutionEnvelope(v.res, v.ref, { trust: v.trust, now: v.now, fetchedFrom: v.fetched_from });
  return qr.verifyResolution(v.res, v.ref, { trust: v.trust, now: v.now, fetchedFrom: v.fetched_from, pin: v.pin });
}

function mismatches(v: any, r: any): string[] {
  const e = v.expect;
  const bad: string[] = [];
  if (r.ok !== e.ok) bad.push(`ok is ${r.ok}, want ${e.ok}`);
  if (r.trusted !== e.trusted) bad.push(`trusted is ${r.trusted}, want ${e.trusted}`);
  if (e.error !== undefined && !r.errors.some((x: string) => x.includes(e.error))) bad.push(`no error contains '${e.error}': ${JSON.stringify(r.errors)}`);
  if (e.untrusted !== undefined && !r.untrusted.some((x: string) => x.includes(e.untrusted))) bad.push(`no untrusted reason contains '${e.untrusted}': ${JSON.stringify(r.untrusted)}`);
  for (const n of e.notes || []) if (!(r.notes || []).some((x: string) => x.includes(n))) bad.push(`no note contains '${n}': ${JSON.stringify(r.notes)}`);
  for (const k of ["endpoints", "needs_confirmation", "key_changes"]) {
    if (k in e) {
      try { assert.deepEqual(r[k], e[k]); } catch { bad.push(`${k} is ${JSON.stringify(r[k])}, want ${JSON.stringify(e[k])}`); }
    }
  }
  return bad;
}

test("every shared vector agrees with the Python reference", () => {
  assert.ok(vectors.length >= 100, `only ${vectors.length} vectors`);
  const failures: string[] = [];
  for (const v of vectors) {
    const bad = mismatches(v, run(v));
    if (bad.length) failures.push(`${v.name}: ${bad.join("; ")}`);
  }
  assert.deepEqual(failures, []);
});

test("the vector set covers every kind and the cases that matter", () => {
  const kinds = new Set(vectors.map((v: any) => v.kind));
  assert.deepEqual([...kinds].sort(), ["reference", "resolution", "resolution-envelope"]);
  const names = vectors.map((v: any) => v.name);
  for (const needed of ["reference-copied-to-another-domain", "reference-expired", "reference-tampered-and-rehashed",
    "envelope-fetched-from-another-origin", "envelope-stale", "envelope-for-another-reference", "envelope-revoked",
    "contact-certificate-of-another-agent", "contact-nostr-endpoint-on-a-lan-key", "pin-key-rotated-needs-the-user"]) {
    assert.ok(names.includes(needed), `missing vector ${needed}`);
  }
});

// Round trip: a reference made here is byte-identical to the Python one, and verifies.
test("making a reference in TypeScript reproduces the Python reference byte for byte", () => {
  const py = vectors.find((v: any) => v.name === "reference-valid-agent");
  const { doc } = qr.parseWire(py.subject);
  const keys = require(V + "../v0.2/test-keys.json").keys;
  const mine = qr.makeReference({
    kind: doc.kind, sid: doc.sid, resolver: doc.resolver, issuedAt: doc.issued_at, expiresAt: doc.expires_at, nonce: doc.nonce,
    issuer: doc.issuer, alg: "ed25519", secretHex: keys["issuer-root"].secret,
  });
  assert.deepEqual(mine, doc);
  assert.equal(qr.toWire(mine), py.subject);
  assert.equal(qr.verifyReference(qr.toWire(mine), { trust: py.trust, now: py.now }).trusted, true);
});

test("a hostile payload never throws", () => {
  const trust = vectors[0].trust;
  for (const s of [null, undefined, 5, [], {}, "", "https://x", "https://contact.example/q/", `https://contact.example/q/${"A".repeat(5000)}`,
    "https://contact.example/q/" + qr.b64url(Buffer.from('{"format":"helix-qr/1"}')), "https://contact.example/q/" + qr.b64url(Buffer.from("\u0000\u0001ÿ"))]) {
    const r = qr.verifyReference(s as any, { trust, now: "2026-11-20T12:00:00Z" });
    assert.equal(r.ok, false);
    assert.ok(r.errors.length > 0);
  }
  for (const s of [null, 5, [], {}]) {
    assert.equal(qr.checkResolutionEnvelope(s, {}, { trust, now: "2026-11-20T12:00:00Z" }).ok, false);
    assert.equal(qr.verifyResolution(s, {}, { trust, now: "2026-11-20T12:00:00Z" }).ok, false);
  }
});

test("sid/0.2 is what makes an endpoint's key a nostr key", () => {
  // A nostr endpoint that names a LAN binding is not a thing sid/0.2 will verify, so no QR resolution can carry it.
  const lanKey = vectors.find((v: any) => v.name === "contact-nostr-endpoint-on-a-lan-key");
  const r = qr.verifyResolution(lanKey.res, lanKey.ref, { trust: lanKey.trust, now: lanKey.now, fetchedFrom: lanKey.fetched_from });
  assert.equal(r.ok, false);
  assert.ok(r.errors[0].includes("the runtime statement does not verify"));
  assert.ok(sid.verifyRuntime(lanKey.res.runtime, lanKey.res.certificate, { trust: lanKey.trust, now: lanKey.now }).errors.join(" ").includes("nostr endpoint cannot use a meshenger binding"));
});
