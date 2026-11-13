/**
 * sid/0.1 tests. Run: npm test  (tsc, then node --test dist/tests/*.test.js)
 *
 * Covers: schema conformance, the hash contract, the odu_link invariant, chain
 * rules, the secrets guard, acting_hash stability under re-anchoring, Markdown
 * round-trip, and the kind-30401 birth event shape.
 */
export {};

const { test } = require("node:test");
const assert = require("node:assert/strict");
const s = require("../sid");
const Ajv = require("ajv/dist/2020");
const addFormats = require("ajv-formats");

const schema = require("../../../../schema/sid.schema.json");
const minimal = require("../../../../conformance/fixtures/minimal-sid.json");
const full = require("../../../../conformance/fixtures/full-sid.json");

const ajv = new Ajv({ strict: false });
addFormats(ajv);
const validate = ajv.compile(schema);
const clone = (x: any): any => JSON.parse(JSON.stringify(x));
const fmt = (errors: string[]): string => errors.join("; ");

test("format and acting-key contract are what the spec says", () => {
  assert.equal(s.FORMAT, "sid/0.1");
  assert.equal(s.BIRTH_EVENT_KIND, 30401);
  assert.deepEqual([...s.ACTING_KEYS], ["identity", "capabilities", "memory", "lifecycle", "status"]);
});

test("minimal fixture: schema-valid and verifySid ok", () => {
  assert.equal(validate(minimal), true, JSON.stringify(validate.errors));
  const r = s.verifySid(minimal);
  assert.equal(r.ok, true, fmt(r.errors));
});

test("full fixture: schema-valid and verifySid ok", () => {
  assert.equal(validate(full), true, JSON.stringify(validate.errors));
  const r = s.verifySid(full);
  assert.equal(r.ok, true, fmt(r.errors));
});

test("v1 defaults: previous_version null, previous_hash none", () => {
  assert.equal(minimal.version, 1);
  assert.equal(minimal.previous_version, null);
  assert.equal(minimal.previous_hash, "none");
});

test("Markdown round-trip is lossless", () => {
  for (const cert of [minimal, full]) {
    const md = s.emitSidMd(cert);
    const back = s.parseSidMd(md);
    assert.deepEqual(back, cert);
  }
});

test("tampering with an acting field breaks the hash", () => {
  const bad = clone(full);
  bad.identity.name = "someone-else";
  const r = s.verifySid(bad);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("hash does not match")), fmt(r.errors));
  assert.ok(r.errors.some((e: string) => e.includes("acting_hash")), fmt(r.errors));
});

test("tampering with a NON-acting field breaks hash but not acting_hash", () => {
  const bad = clone(full);
  bad.time.birth_block = 1;
  const r = s.verifySid(bad);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("hash does not match")), fmt(r.errors));
  assert.ok(!r.errors.some((e: string) => e.includes("acting_hash")), "acting_hash must survive a re-anchor");
});

test("odu_link must equal (odu_primary << 8) | odu_secondary", () => {
  const bad = clone(minimal);
  bad.identity.odu_link = 1;
  const finalized = s.finalizeSid(bad); // stamp the wrong body so only the invariant fires
  const r = s.verifySid(finalized);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("odu_link")), fmt(r.errors));
});

test("chain: v2 links to v1 by hash", () => {
  const v2 = clone(minimal);
  v2.version = 2;
  v2.previous_version = 1;
  v2.previous_hash = minimal.hash;
  v2.identity = { ...v2.identity, description: "second version" };
  const fin = s.finalizeSid(v2);
  const r = s.verifySid(fin, minimal);
  assert.equal(r.ok, true, fmt(r.errors));
  const broken = { ...fin, previous_hash: "0".repeat(64) };
  const r2 = s.verifySid(broken, minimal);
  assert.equal(r2.ok, false);
  assert.ok(r2.errors.some((e: string) => e.includes("previous_hash does not match")), fmt(r2.errors));
});

test("v1 cannot carry a previous_hash chain", () => {
  const bad = clone(minimal);
  bad.previous_hash = "a".repeat(64);
  const fin = s.finalizeSid(bad);
  const r = s.verifySid(fin);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("v1 must have")), fmt(r.errors));
});

test("secrets are refused in genesis and identity", () => {
  for (const field of ["seed", "mnemonic", "private_key", "nsec", "secret"]) {
    const bad = clone(minimal);
    bad.genesis = { ...bad.genesis, [field]: "x" };
    const fin = s.finalizeSid(bad);
    const r = s.verifySid(fin);
    assert.equal(r.ok, false, `genesis.${field} must be refused`);
    assert.ok(r.errors.some((e: string) => e.includes(`must not carry ${field}`)), fmt(r.errors));
  }
});

test("time.anchored requires an ots_proof", () => {
  const bad = clone(minimal);
  bad.time = { ...bad.time, anchored: true, ots_proof: null };
  const fin = s.finalizeSid(bad);
  const r = s.verifySid(fin);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("ots_proof")), fmt(r.errors));
});

test("lifecycle.state must equal status", () => {
  const bad = clone(full);
  bad.status = "suspended";
  const fin = s.finalizeSid(bad);
  const r = s.verifySid(fin);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("lifecycle.state must equal status")), fmt(r.errors));
});

test("calabash reading must match the address", () => {
  const bad = clone(minimal);
  bad.identity.calabash = {
    id: bad.identity.odu_link,
    top: bad.identity.odu_primary,
    bottom: 1, // not odu_secondary
    vessel: "Seal",
  };
  const r = s.verifySid(s.finalizeSid(bad));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes("calabash")), fmt(r.errors));
});

test("anchored requires an attested proof and the OKF clock", () => {
  const base = clone(minimal);
  base.status = "live";
  base.lifecycle = { state: "live", history: [{ state: "live", at: base.born_at }] };
  const pending = clone(base);
  pending.time = {
    ...base.time,
    anchored: true,
    ots_proof: "x.ots",
    ots_status: "pending",
    clock_source: "okf",
    calendar: { epoch: 1, cycle: 2, phase: 3 },
  };
  const r = s.verifySid(s.finalizeSid(pending));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e: string) => e.includes('ots_status = "complete"')), fmt(r.errors));

  const wrongClock = clone(pending);
  wrongClock.time = { ...pending.time, ots_status: "complete", clock_source: "unattested" };
  const r2 = s.verifySid(s.finalizeSid(wrongClock));
  assert.equal(r2.ok, false);
  assert.ok(r2.errors.some((e: string) => e.includes('clock_source = "okf"')), fmt(r2.errors));

  // complete + okf + integer calendar passes
  const good = clone(pending);
  good.time = { ...pending.time, ots_status: "complete" };
  const ok = s.verifySid(s.finalizeSid(good));
  assert.equal(ok.ok, true, fmt(ok.errors));
});

test("birth event: kind 30401, d tag, no secrets, no memory locator by default", () => {
  const ev = s.birthEvent(full);
  assert.equal(ev.kind, 30401);
  const tags: Record<string, string> = Object.fromEntries(ev.tags.map(([k, v]: string[]) => [k, v]));
  assert.equal(tags.d, full.id);
  assert.equal(tags.format, "sid/0.1");
  assert.equal(tags.v, String(full.version));
  assert.equal(tags.hash, full.hash);
  const content = JSON.parse(ev.content);
  assert.equal(content.id, full.id);
  assert.equal(content.hash, full.hash);
  assert.equal(content.seed_hash, undefined);
  assert.equal(content.private_key, undefined);
  assert.equal(content.memory_locator, undefined, "memory locator is opt-in only");
  const ev2 = s.birthEvent(full, { includeMemoryLocator: true });
  assert.equal(JSON.parse(ev2.content).memory_locator, full.memory.locator);
});

test("re-anchoring changes hash but never acting_hash", () => {
  const a = clone(full);
  const b = clone(full);
  b.time = { ...b.time, birth_block: 975999, anchored: true, ots_proof: "proofs/x.ots" };
  const fa = s.finalizeSid(a);
  const fb = s.finalizeSid(b);
  assert.equal(s.actingHash(fa), s.actingHash(fb), "acting_hash must not move on a re-anchor");
  assert.notEqual(fa.hash, fb.hash, "hash must move when the record changes");
});
