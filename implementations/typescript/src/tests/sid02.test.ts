/**
 * sid/0.2 tests. Run: npm test
 *
 * The shared vectors (conformance/v0.2/vectors.json) are produced by the Python
 * reference; passing them here is the proof the two implementations agree.
 * The signing tests show the reverse direction: the same key and document give
 * byte-identical hashes and signatures in TypeScript.
 */
export {};

const { test } = require("node:test");
const assert = require("node:assert/strict");
const s = require("../sid02");
const sigs = require("../sigs");
const Ajv = require("ajv/dist/2020");

const V = "../../../../conformance/v0.2/";
const trust = require(V + "trust.json");
const { keys } = require(V + "test-keys.json");
const { vectors } = require(V + "vectors.json");
const minimal = require(V + "fixtures/minimal-sid.json");
const full = require(V + "fixtures/full-sid.json");
const fullV2 = require(V + "fixtures/full-sid-v2.json");
const runtime = require(V + "fixtures/runtime.json");
const migrated = require(V + "fixtures/migrated-sid.json");
const legacy = require("../../../../conformance/fixtures/full-sid.json");
const certSchema = require("../../../../schema/sid-0.2.schema.json");
const runtimeSchema = require("../../../../schema/sid-runtime-0.2.schema.json");

const ajv = new Ajv({ strict: false });
const validateCert = ajv.compile(certSchema);
const validateRuntime = ajv.compile(runtimeSchema);
const clone = (x: any): any => JSON.parse(JSON.stringify(x));
const strip = (doc: any): any => {
  const c = clone(doc);
  delete c.hash; delete c.acting_hash; delete c.proof;
  return c;
};

test("contract constants are what the spec says", () => {
  assert.equal(s.FORMAT, "sid/0.2");
  assert.equal(s.RUNTIME_FORMAT, "sid-runtime/0.2");
  assert.deepEqual([...s.ACTING_KEYS], ["identity", "bindings", "capabilities", "memory", "lifecycle", "status"]);
  assert.deepEqual([...sigs.ALGS], ["ed25519", "bip340"]);
});

for (const v of vectors) {
  test(`vector: ${v.name}`, () => {
    const anchors = v.trust === true ? trust : v.trust === false ? undefined : v.trust;
    const r = v.kind === "sid"
      ? s.verifySid(v.cert, { trust: anchors, previous: v.previous, head: v.head, legacy: v.legacy })
      : s.verifyRuntime(v.stmt, v.cert, { trust: anchors, now: v.now, head: v.head });
    const detail = JSON.stringify({ errors: r.errors, untrusted: r.untrusted });
    assert.equal(r.ok, v.expect.ok, detail);
    assert.equal(r.trusted, v.expect.trusted, detail);
    if (v.expect.error) assert.ok(r.errors.some((e: string) => e.includes(v.expect.error)), detail);
    if (v.expect.untrusted) assert.ok(r.untrusted.some((e: string) => e.includes(v.expect.untrusted)), detail);
    if ("migration" in v.expect) assert.equal(r.migration, v.expect.migration);
  });
}

test("fixtures are schema-valid", () => {
  for (const cert of [minimal, full, fullV2, migrated]) {
    assert.equal(validateCert(cert), true, JSON.stringify(validateCert.errors));
  }
  assert.equal(validateRuntime(runtime), true, JSON.stringify(validateRuntime.errors));
});

test("schema rejects what it can see: wrong format, missing proof, unknown top-level field", () => {
  assert.equal(validateCert({ ...clone(minimal), format: "sid/0.1" }), false);
  const noProof = clone(minimal); delete noProof.proof;
  assert.equal(validateCert(noProof), false);
  assert.equal(validateCert({ ...clone(minimal), surprise: 1 }), false);
});

test("public keys derive identically in both suites", () => {
  for (const name of Object.keys(keys)) {
    assert.equal(sigs.publicKey(keys[name].alg, keys[name].secret), keys[name].public_key, name);
  }
});

test("signing parity: TypeScript reproduces the Python-signed fixtures byte for byte", () => {
  const root = keys["issuer-root"];
  for (const doc of [minimal, full, fullV2, runtime, migrated]) {
    assert.deepEqual(s.signDocument(strip(doc), root.alg, root.secret), doc);
  }
});

test("signing parity holds for the BIP-340 suite", () => {
  const schnorrVector = vectors.find((v: any) => v.name === "schnorr-issuer-valid").cert;
  const key = keys["issuer-schnorr"];
  assert.deepEqual(s.signDocument(strip(schnorrVector), key.alg, key.secret), schnorrVector);
});

test("binding proofs of possession are reproduced exactly", () => {
  const [nostr, lan] = full.bindings;
  assert.deepEqual(
    s.makeBinding(full.id, "nostr-main", "nostr", "bip340", keys["agent-nostr"].secret, nostr.added_at, nostr.purposes),
    nostr);
  assert.deepEqual(
    s.makeBinding(full.id, "lan-main", "meshenger", "ed25519", keys["agent-mesh"].secret, lan.added_at, lan.purposes),
    lan);
});

test("migration is deterministic and matches the Python result", () => {
  const root = keys["issuer-root"];
  const body = s.migrateFrom01(legacy, migrated.issuer, migrated.updated);
  assert.deepEqual(s.signDocument(body, root.alg, root.secret), migrated);
  // the 0.1 npub is carried as a legacy claim, never as a binding
  assert.deepEqual(migrated.bindings, []);
  assert.equal(migrated.extensions.legacy.npub, legacy.identity.npub);
  // and the old document still verifies under its own rules, hash untouched
  assert.equal(require("../sid").verifySid(legacy).ok, true);
  assert.equal(migrated.provenance.migrated_from.hash, legacy.hash);
});

test("acting_hash ignores provenance, changelog and appendix; hash does not", () => {
  const root = keys["issuer-root"];
  const edited = strip(full);
  edited.changelog.push("v1: note");
  edited.appendix.notes = "changed";
  const resigned = s.signDocument(edited, root.alg, root.secret);
  assert.equal(resigned.acting_hash, full.acting_hash);
  assert.notEqual(resigned.hash, full.hash);
});

test("verifyAny dispatches on format and never trusts sid/0.1", () => {
  assert.equal(s.verifyAny(full, { trust }).trusted, true);
  const old = s.verifyAny(legacy, { trust });
  assert.equal(old.ok, true);
  assert.equal(old.trusted, false);
  assert.equal(s.verifyAny({ format: "sid/9.9" }).ok, false);
});

test("signature verification never throws on garbage", () => {
  for (const alg of ["ed25519", "bip340", "rsa", undefined]) {
    assert.equal(sigs.verify(alg, "zz", "m", "zz"), false);
    assert.equal(sigs.verify(alg, "00".repeat(32), "m", "00".repeat(64)), false);
  }
});
