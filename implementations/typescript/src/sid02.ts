/**
 * sid02.ts — sid/0.2, the neutral profile.
 *
 * No application-specific required fields; an issuer signature checked against
 * trust anchors the VERIFIER supplies; typed key bindings each carrying a proof
 * of possession; a separate signed runtime statement. sid/0.1 is untouched and
 * still verified by sid.ts.
 *
 * Mirrors implementations/python/sid02.py rule for rule;
 * conformance/v0.2/vectors.json is the shared proof.
 *
 *   ok       well formed and internally consistent: hashes recompute, chain
 *            rules hold, every binding's proof of possession verifies, and the
 *            issuer proof verifies if its key is known.
 *   trusted  ok, AND the issuer proof verified against a supplied trust
 *            anchor, AND status is live, AND (if the caller knows the head)
 *            this is that version. Act only on `trusted`.
 */
import { createHash } from "crypto";
import { canonicalJson } from "./canonical";
import * as legacy01 from "./sid";
import * as sigs from "./sigs";

export const FORMAT = "sid/0.2";
export const RUNTIME_FORMAT = "sid-runtime/0.2";
export const LEGACY_FORMAT = "sid/0.1";
export const ACTING_KEYS = ["identity", "bindings", "capabilities", "memory", "lifecycle", "status"] as const;
export const STATUSES = ["cast", "live", "suspended", "retired"] as const;
/** Excluded from `hash`: the hash itself, the proof made over it, and "_" keys. */
const UNHASHED = ["hash", "proof"];
/** Binding types whose key algorithm is fixed by their protocol. */
const BINDING_ALG: Record<string, string> = { nostr: "bip340", meshenger: "ed25519" };
/** Endpoint types that must be reached through a binding of a matching type. */
const ENDPOINT_BINDING: Record<string, string> = { nostr: "nostr", "meshenger-lan": "meshenger" };
const ENDPOINT_TYPES = ["nostr", "meshenger-lan", "sip", "a2a", "mcp", "https"];
const SECRET_KEYS = ["seed", "mnemonic", "private_key", "nsec", "secret", "secret_key"];

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const ID_RE = /^sid_[a-z0-9][a-z0-9-]*$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]*$/;
const NS_RE = /^[a-z0-9][a-z0-9_.-]*$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

export interface Verdict {
  ok: boolean;
  trusted: boolean;
  errors: string[];
  untrusted: string[];
  migration?: "verified" | "unchecked" | null;
}

export interface VerifyOptions {
  trust?: any;
  previous?: any;
  head?: { version: number; hash: string } | null;
  legacy?: any;
}

const isObj = (v: any): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
const isInt = (v: any): boolean => typeof v === "number" && Number.isInteger(v);
const isTime = (v: any): boolean => typeof v === "string" && TIME_RE.test(v);
const sha = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

function body(doc: any): any {
  const out: any = {};
  for (const k of Object.keys(doc)) {
    if (!UNHASHED.includes(k) && k.charAt(0) !== "_") out[k] = doc[k];
  }
  return out;
}

export function actingHash(cert: any): string {
  const acting: any = {};
  for (const k of ACTING_KEYS) if (cert[k] !== undefined) acting[k] = cert[k];
  return sha(canonicalJson(acting));
}

/** Hash of a certificate or runtime statement: everything except hash, proof, "_" keys. */
export function sidHash(doc: any): string {
  return sha(canonicalJson(body(doc)));
}

// ── what gets signed ─────────────────────────────────────────────────────────
export function issueMessage(format: string, docHash: string): string {
  return `${format}\nissue\n${docHash}`;
}

export function bindMessage(sidId: string, binding: any): string {
  return [FORMAT, "bind", sidId, String(binding?.id), String(binding?.alg), String(binding?.public_key)].join("\n");
}

// ── minting (tooling and fixtures; production issuers sign in the kernel) ────
export function makeBinding(
  sidId: string, bindingId: string, type: string, alg: string, secretHex: string,
  addedAt: string, purposes?: string[],
): any {
  const binding: any = { id: bindingId, type, alg, public_key: sigs.publicKey(alg, secretHex), added_at: addedAt };
  if (purposes && purposes.length) binding.purposes = [...purposes];
  binding.proof = sigs.sign(alg, secretHex, bindMessage(sidId, binding));
  return binding;
}

/** Fill v1 defaults, then acting_hash (certificates), hash and the issuer proof. */
export function signDocument(doc: any, alg: string, secretHex: string): any {
  const out = JSON.parse(JSON.stringify(doc));
  if (out.format === FORMAT) {
    if (out.version === 1) {
      if (out.previous_version === undefined) out.previous_version = null;
      if (out.previous_hash === undefined || out.previous_hash === null) out.previous_hash = "none";
    }
    out.acting_hash = actingHash(out);
  }
  out.hash = sidHash(out);
  out.proof = { alg, signature: sigs.sign(alg, secretHex, issueMessage(out.format, out.hash)) };
  return out;
}

// ── issuer authority ─────────────────────────────────────────────────────────
function issuerCheck(doc: any, trust: any, signedAt: any): { errors: string[]; untrusted: string[]; verified: boolean } {
  const errors: string[] = [];
  const untrusted: string[] = [];
  const done = (verified: boolean) => ({ errors, untrusted, verified });
  const issuer = doc.issuer;
  const proof = doc.proof;
  if (!isObj(issuer) || typeof issuer.id !== "string" || !issuer.id || typeof issuer.kid !== "string" || !issuer.kid) {
    errors.push("issuer must be {id, kid}");
    return done(false);
  }
  if (!isObj(proof) || !(sigs.ALGS as readonly string[]).includes(proof.alg)
      || typeof proof.signature !== "string" || !HEX128.test(proof.signature)) {
    errors.push("proof must be {alg, signature} with a supported alg and a 128-hex signature");
    return done(false);
  }
  if (!isObj(trust) || !isObj(trust.issuers)) {
    untrusted.push("no trust anchors supplied");
    return done(false);
  }
  const anchor = trust.issuers[issuer.id];
  if (!isObj(anchor)) {
    untrusted.push(`issuer ${issuer.id} is not a trust anchor`);
    return done(false);
  }
  const key = (Array.isArray(anchor.keys) ? anchor.keys : []).find((k: any) => isObj(k) && k.kid === issuer.kid);
  if (!key) {
    untrusted.push(`issuer ${issuer.id} has no key ${issuer.kid}`);
    return done(false);
  }
  if (key.alg !== proof.alg) {
    errors.push("proof.alg does not match the issuer key");
    return done(false);
  }
  if (!sigs.verify(proof.alg, key.public_key, issueMessage(String(doc.format), String(doc.hash)), proof.signature)) {
    errors.push("issuer signature does not verify");
    return done(false);
  }
  // The signature is genuine; is the key allowed to have made it?
  if (key.compromised === true) {
    untrusted.push(`issuer key ${issuer.kid} is marked compromised`);
    return done(false);
  }
  if (isTime(signedAt)) {
    if (isTime(key.not_before) && signedAt < key.not_before) {
      untrusted.push(`signed before issuer key ${issuer.kid} was valid`);
      return done(false);
    }
    if (isTime(key.not_after) && signedAt >= key.not_after) {
      untrusted.push(`signed after issuer key ${issuer.kid} expired`);
      return done(false);
    }
    if (isTime(key.revoked_at) && signedAt >= key.revoked_at) {
      untrusted.push(`signed after issuer key ${issuer.kid} was revoked`);
      return done(false);
    }
  }
  return done(true);
}

function findSecrets(node: any, path = ""): string[] {
  const found: string[] = [];
  if (Array.isArray(node)) {
    node.forEach((v, i) => found.push(...findSecrets(v, `${path}[${i}]`)));
  } else if (isObj(node)) {
    for (const k of Object.keys(node)) {
      const here = path ? `${path}.${k}` : k;
      if (SECRET_KEYS.includes(k)) found.push(here);
      found.push(...findSecrets(node[k], here));
    }
  }
  return found;
}

// ── the certificate ──────────────────────────────────────────────────────────
export function verifySid(cert: any, options: VerifyOptions = {}): Verdict {
  const errors: string[] = [];
  const untrusted: string[] = [];
  const result: Verdict = { ok: false, trusted: false, errors, untrusted, migration: null };
  const add = (e: string) => errors.push(e);
  if (!isObj(cert)) {
    add("not an object");
    return result;
  }
  const { trust, previous, head, legacy } = options;

  if (cert.format !== FORMAT) add(`format must be ${FORMAT}`);
  const sidId = cert.id;
  if (typeof sidId !== "string" || !ID_RE.test(sidId) || sidId.length > 96) add("id must match sid_<slug>");
  if (!isInt(cert.version) || cert.version < 1) add("version must be an integer >= 1");
  if (!(STATUSES as readonly string[]).includes(cert.status)) add("status must be cast|live|suspended|retired");
  if (!isTime(cert.born_at)) add("born_at must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)");
  if (!isTime(cert.updated)) add("updated must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)");
  else if (isTime(cert.born_at) && cert.updated < cert.born_at) add("updated must not be before born_at");

  const ident = cert.identity;
  if (!isObj(ident)) {
    add("identity is required");
  } else {
    if (typeof ident.name !== "string" || !ident.name) add("identity.name is required");
    if (ident.type !== "agent") add('identity.type must be "agent"');
    const parent = ident.parent;
    if (parent !== undefined && parent !== null && (typeof parent !== "string" || !ID_RE.test(parent))) {
      add("identity.parent must be a sid id or null");
    }
  }

  // bindings: typed public keys, each proving possession of its key
  let bindings: any[] = cert.bindings === undefined ? [] : cert.bindings;
  const seen = new Set<string>();
  if (!Array.isArray(bindings)) {
    add("bindings must be an array");
    bindings = [];
  }
  bindings.forEach((b, i) => {
    const where = `bindings[${i}]`;
    if (!isObj(b)) {
      add(`${where} must be an object`);
      return;
    }
    if (typeof b.id !== "string" || !SLUG_RE.test(b.id)) add(`${where}.id must be a slug`);
    else if (seen.has(b.id)) add(`${where}.id ${b.id} is used twice`);
    else seen.add(b.id);
    if (typeof b.type !== "string" || !SLUG_RE.test(b.type)) add(`${where}.type must be a slug`);
    if (!(sigs.ALGS as readonly string[]).includes(b.alg)) add(`${where}.alg must be one of ${sigs.ALGS.join("|")}`);
    else if ((BINDING_ALG[b.type] ?? b.alg) !== b.alg) add(`${where}: a ${b.type} binding must use ${BINDING_ALG[b.type]}`);
    if (typeof b.public_key !== "string" || !HEX64.test(b.public_key)) add(`${where}.public_key must be 64-hex`);
    if (!isTime(b.added_at)) add(`${where}.added_at must be RFC 3339 UTC`);
    if (typeof b.proof !== "string" || !HEX128.test(b.proof)) add(`${where}.proof must be a 128-hex signature`);
    else if (!sigs.verify(String(b.alg), String(b.public_key), bindMessage(String(sidId), b), b.proof)) {
      add(`${where}: proof of possession does not verify`);
    }
  });

  const ext = cert.extensions;
  if (ext !== undefined && ext !== null) {
    if (!isObj(ext)) add("extensions must be an object");
    else {
      for (const ns of Object.keys(ext)) {
        if (!NS_RE.test(ns) || !isObj(ext[ns])) add(`extensions.${ns} must be a namespaced object`);
      }
    }
  }

  if (typeof cert.hash !== "string" || !HEX64.test(cert.hash)) add("hash must be 64-hex");
  else if (sidHash(cert) !== cert.hash) add("hash does not match the canonical body");
  if (typeof cert.acting_hash !== "string" || !HEX64.test(cert.acting_hash)) add("acting_hash must be 64-hex");
  else if (actingHash(cert) !== cert.acting_hash) add("acting_hash does not match the acting keys");

  if (cert.version === 1) {
    if (cert.previous_version !== undefined && cert.previous_version !== null) add("v1 must have previous_version = null");
    if (cert.previous_hash !== "none" && cert.previous_hash !== undefined && cert.previous_hash !== null) {
      add('v1 must have previous_hash = "none"');
    }
  } else if (isInt(cert.version)) {
    if (cert.previous_version !== cert.version - 1) add("previous_version must be version - 1");
    if (typeof cert.previous_hash !== "string" || !HEX64.test(cert.previous_hash)) add("previous_hash must be 64-hex for v>1");
  }

  const life = cert.lifecycle;
  let history: any[] = [];
  if (!isObj(life)) {
    add("lifecycle is required");
  } else {
    if (life.state !== cert.status) add("lifecycle.state must equal status");
    history = life.history === undefined ? [] : life.history;
    if (!Array.isArray(history) || history.some((e) => !isObj(e)
        || !(STATUSES as readonly string[]).includes(e.state) || !isTime(e.at))) {
      add("lifecycle.history must be an array of {state, at}");
      history = [];
    }
  }

  if (isObj(previous)) {
    if (cert.previous_hash !== previous.hash) add("previous_hash does not match the hash of the supplied previous version");
    if (cert.version !== (previous.version || 0) + 1) add("version is not previous.version + 1");
    if (cert.id !== previous.id) add("id differs from the previous version");
    if (cert.born_at !== previous.born_at) add("born_at differs from the previous version");
    if (cert.issuer?.id !== previous.issuer?.id) add("issuer.id differs from the previous version");
    if (previous.status === "retired") add("the previous version is retired; no further versions are allowed");
    if (isTime(cert.updated) && isTime(previous.updated) && cert.updated < previous.updated) {
      add("updated is earlier than the previous version");
    }
    const prevHistory = previous.lifecycle?.history;
    if (Array.isArray(prevHistory)
        && canonicalJson(history.slice(0, prevHistory.length)) !== canonicalJson(prevHistory)) {
      add("lifecycle.history does not extend the previous version's history");
    }
  }

  for (const path of findSecrets(body(cert))) add(`${path} must not be present: certificates carry no secrets`);

  const issuer = issuerCheck(cert, trust, cert.updated);
  errors.push(...issuer.errors);
  untrusted.push(...issuer.untrusted);

  const migrated = isObj(cert.provenance) ? cert.provenance.migrated_from : undefined;
  if (migrated !== undefined && migrated !== null) {
    if (!isObj(migrated) || migrated.format !== LEGACY_FORMAT || typeof migrated.id !== "string"
        || !isInt(migrated.version) || typeof migrated.hash !== "string" || !HEX64.test(migrated.hash)) {
      add("provenance.migrated_from must be {format: sid/0.1, id, version, hash}");
    } else if (legacy === undefined || legacy === null) {
      result.migration = "unchecked";
    } else {
      const old = legacy01.verifySid(legacy);
      if (!old.ok) {
        add("the supplied sid/0.1 certificate does not verify: " + old.errors.slice(0, 2).join("; "));
      } else if (legacy.id !== migrated.id || legacy.version !== migrated.version || legacy.hash !== migrated.hash) {
        add("provenance.migrated_from does not match the supplied sid/0.1 certificate");
      } else {
        result.migration = "verified";
      }
    }
  }

  if (cert.status !== "live") untrusted.push(`status is ${cert.status}, not live`);
  if (isObj(head) && (head!.version !== cert.version || head!.hash !== cert.hash)) {
    untrusted.push("a newer version of this certificate is known");
  }

  result.ok = errors.length === 0;
  result.trusted = result.ok && issuer.verified && untrusted.length === 0;
  return result;
}

// ── runtime statement ────────────────────────────────────────────────────────
/**
 * Verify a sid-runtime/0.2 statement against its certificate. The statement
 * says: this installation may serve as this agent, at these endpoints, with at
 * most these capabilities, until it expires. It is signed by the certificate's
 * issuer and kept separate so a runtime can change without a new identity version.
 */
export function verifyRuntime(
  stmt: any, cert: any, options: { trust?: any; now?: string | null; head?: any } = {},
): Verdict {
  const errors: string[] = [];
  const untrusted: string[] = [];
  const result: Verdict = { ok: false, trusted: false, errors, untrusted };
  const add = (e: string) => errors.push(e);
  if (!isObj(stmt)) {
    add("not an object");
    return result;
  }
  const { trust, now, head } = options;
  const certResult = verifySid(cert, { trust, head });
  if (!certResult.ok) {
    add("the certificate does not verify: " + certResult.errors.slice(0, 2).join("; "));
    return result;
  }
  untrusted.push(...certResult.untrusted);

  if (stmt.format !== RUNTIME_FORMAT) add(`format must be ${RUNTIME_FORMAT}`);
  if (stmt.sid !== cert.id) add("sid does not name this certificate");
  if (typeof stmt.runtime_id !== "string" || !SLUG_RE.test(stmt.runtime_id)) add("runtime_id must be a slug");
  if (!isObj(stmt.adapter) || typeof stmt.adapter.kind !== "string" || !stmt.adapter.kind) {
    add("adapter must be {kind, version?}");
  }
  if (!isTime(stmt.issued_at) || !isTime(stmt.expires_at)) add("issued_at and expires_at must be RFC 3339 UTC");
  else if (stmt.expires_at <= stmt.issued_at) add("expires_at must be after issued_at");
  if (stmt.issuer?.id !== cert.issuer?.id) add("a runtime statement must be signed by the certificate's issuer");

  const byId = new Map<string, any>();
  for (const b of Array.isArray(cert.bindings) ? cert.bindings : []) if (isObj(b)) byId.set(b.id, b);
  let endpoints: any[] = stmt.endpoints;
  if (!Array.isArray(endpoints) || endpoints.length === 0) {
    add("endpoints must be a non-empty array");
    endpoints = [];
  }
  endpoints.forEach((ep, i) => {
    const where = `endpoints[${i}]`;
    if (!isObj(ep) || !ENDPOINT_TYPES.includes(ep.type) || typeof ep.address !== "string" || !ep.address) {
      add(`${where} must be {type, address} with a known type`);
      return;
    }
    const ref = ep.binding;
    const needs = ENDPOINT_BINDING[ep.type];
    if (needs && (ref === undefined || ref === null)) add(`${where}: a ${ep.type} endpoint must name a ${needs} binding`);
    if (ref !== undefined && ref !== null) {
      const bound = byId.get(ref);
      if (!bound) add(`${where}: binding ${ref} is not in the certificate`);
      // A key of one protocol never stands in for another's.
      else if (needs && bound.type !== needs) add(`${where}: a ${ep.type} endpoint cannot use a ${bound.type} binding`);
    }
  });

  const declared = new Set<string>(cert.capabilities?.permissions ?? []);
  const caps = stmt.capabilities === undefined ? [] : stmt.capabilities;
  if (!Array.isArray(caps) || caps.some((c: any) => typeof c !== "string")) {
    add("capabilities must be an array of strings");
  } else {
    const extra = [...new Set<string>(caps)].filter((c) => !declared.has(c)).sort();
    if (extra.length) add("capabilities exceed the certificate's permissions: " + extra.join(", "));
  }

  if (typeof stmt.hash !== "string" || !HEX64.test(stmt.hash)) add("hash must be 64-hex");
  else if (sidHash(stmt) !== stmt.hash) add("hash does not match the canonical body");
  for (const path of findSecrets(body(stmt))) add(`${path} must not be present: statements carry no secrets`);

  const issuer = issuerCheck(stmt, trust, stmt.issued_at);
  errors.push(...issuer.errors);
  untrusted.push(...issuer.untrusted);

  if (now === undefined || now === null) {
    untrusted.push("no current time supplied; expiry not checked");
  } else if (!isTime(now)) {
    add("now must be RFC 3339 UTC");
  } else if (isTime(stmt.issued_at) && isTime(stmt.expires_at)) {
    if (now < stmt.issued_at) untrusted.push("the statement is not valid yet");
    else if (now >= stmt.expires_at) untrusted.push("the statement has expired");
  }

  result.ok = errors.length === 0;
  result.trusted = result.ok && issuer.verified && untrusted.length === 0;
  return result;
}

// ── migration from sid/0.1 ───────────────────────────────────────────────────
/**
 * Deterministically map a sid/0.1 certificate to an UNSIGNED sid/0.2 body.
 *
 * The result starts a new chain (version 1) that records where it came from; it
 * is never called equivalent to the old document. Application-specific 0.1
 * fields move under `extensions`. The 0.1 `npub` is NOT turned into a binding:
 * a binding needs the key holder's proof of possession, which a migration
 * cannot supply. It stays under extensions.legacy until the holder adds a real
 * binding in a later version.
 */
export function migrateFrom01(legacy: any, issuer: { id: string; kid: string }, updated: string): any {
  const ident = legacy.identity || {};
  const memory = legacy.memory || {};
  const ifa: any = {};
  for (const k of ["odu_link", "odu_primary", "odu_secondary", "odu", "calabash"]) if (k in ident) ifa[k] = ident[k];
  for (const k of ["glyph_root", "birth_glyph"]) if (memory[k] !== undefined && memory[k] !== null) ifa[k] = memory[k];
  const extensions: any = {};
  if (Object.keys(ifa).length) extensions.ifa = ifa;
  for (const k of ["genesis", "time"]) if (isObj(legacy[k]) && Object.keys(legacy[k]).length) extensions[k] = legacy[k];
  const oldKeys: any = {};
  for (const k of ["npub", "principal"]) if (ident[k] !== undefined && ident[k] !== null) oldKeys[k] = ident[k];
  if (Object.keys(oldKeys).length) extensions.legacy = oldKeys;

  const identity: any = {};
  for (const [k, v] of [["name", ident.name], ["type", "agent"], ["description", ident.description], ["parent", ident.parent]]) {
    if (v !== undefined && v !== null) identity[k as string] = v;
  }
  const mem: any = {};
  for (const k of ["locator", "namespace_root"]) if (memory[k] !== undefined && memory[k] !== null) mem[k] = memory[k];

  const out: any = {
    format: FORMAT,
    id: legacy.id,
    version: 1,
    previous_version: null,
    previous_hash: "none",
    status: legacy.status,
    born_at: legacy.born_at,
    updated,
    issuer: { id: issuer.id, kid: issuer.kid },
    identity,
    bindings: [],
    capabilities: legacy.capabilities || {},
    memory: mem,
    lifecycle: { state: legacy.status, history: [...(legacy.lifecycle?.history || [])] },
    provenance: {
      ...(legacy.provenance || {}),
      migrated_from: { format: LEGACY_FORMAT, id: legacy.id, version: legacy.version, hash: legacy.hash },
    },
    extensions,
    changelog: [...(legacy.changelog || []), `migrated from sid/0.1 v${legacy.version} ${legacy.hash}`],
  };
  if (isObj(legacy.appendix) && Object.keys(legacy.appendix).length) out.appendix = legacy.appendix;
  return out;
}

/** Dispatch on `format`. Unknown formats are rejected, never guessed. */
export function verifyAny(cert: any, options: VerifyOptions = {}): Verdict {
  const format = isObj(cert) ? cert.format : undefined;
  if (format === FORMAT) return verifySid(cert, options);
  if (format === LEGACY_FORMAT) {
    const r = legacy01.verifySid(cert, options.previous);
    // sid/0.1 carries no issuer signature, so it can never be `trusted`.
    return { ok: r.ok, trusted: false, errors: r.errors, untrusted: ["sid/0.1 has no issuer signature"], migration: null };
  }
  return { ok: false, trusted: false, errors: [`unknown format ${JSON.stringify(format)}`], untrusted: [], migration: null };
}
