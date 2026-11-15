/**
 * helix-qr/1: signed QR contact references and their resolutions.
 *
 * TypeScript implementation (see spec/helix-qr-1.md), for the browser PWA scanner
 * and Node tooling. It agrees with the Python reference on every vector in
 * conformance/qr/vectors.json. A QR code is a pointer: it never carries a key, an
 * address or a secret. Everything a caller will rely on is fetched, signed, and
 * verified here, on the sid/0.2 document hash, issuer proof and trust anchors.
 */
import * as sid from "./sid02";
import { canonicalJson } from "./canonical";

export const FORMAT = "helix-qr/1";
export const RESOLUTION_FORMAT = "helix-qr-resolution/1";
const MAX_LIFETIME_MS = 400 * 24 * 3600 * 1000;
const MAX_FRESH_MS = 24 * 3600 * 1000;
const SKEW_MS = 5 * 60 * 1000;
const STATUSES = ["active", "suspended", "revoked", "superseded"];
const KINDS = ["agent", "business"];

const REF_KEYS = new Set(["format", "kind", "sid", "card", "resolver", "domain", "issued_at", "expires_at", "nonce", "issuer", "hash", "proof"]);
const RES_KEYS = new Set(["format", "reference_hash", "resolver", "status", "superseded_by", "issued_at", "fresh_until",
  "certificate", "runtime", "card", "issuer", "hash", "proof"]);

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
// ASCII-only and strictly anchored, so these mean the same in Python, JavaScript and Go.
const HOST_RE = new RegExp(`^(?:${LABEL}\\.)+(?:[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z])$`);
const ORIGIN_RE = /^https:\/\/([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/;
const HTTPS_URL_RE = /^https:\/\/([A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:\/[!-~]*)?$/;
const WSS_RE = /^wss:\/\/([A-Za-z0-9.-]+)(?::[0-9]{1,5})?(?:\/[!-~]*)?$/;
const WIRE_RE = /^(https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?)\/q\/([A-Za-z0-9_-]{1,4096})$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SLUG = /^[a-z0-9][a-z0-9_.-]*$/;
const SIP_RE = /^sips?:[!-~]+@[!-~]+$/;
const TIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const PRIVATE_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".intranet", ".private", ".localdomain"];

export interface Verdict {
  ok: boolean;
  trusted: boolean;
  errors: string[];
  untrusted: string[];
  notes: string[];
}

export interface ResolutionVerdict extends Verdict {
  endpoints: any[];
  sid: any;
  card: any;
  status: string | null;
  needs_confirmation: boolean;
  key_changes: { binding: string; change: string }[];
  pin: any;
}

const isObj = (v: any): boolean => v !== null && typeof v === "object" && !Array.isArray(v);
const sorted = (a: string[]) => [...a].sort();

function ms(t: string): number {
  return Date.parse(t);
}

/** RFC 3339 UTC to the second, and a real date. */
function timeOk(v: any): boolean {
  if (typeof v !== "string" || !TIME_RE.test(v)) return false;
  const t = Date.parse(v);
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + "Z" === v;
}

export function b64url(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/** A name that could be reached on the public internet. */
export function publicHost(host: string): boolean {
  if (!HOST_RE.test(host) || host === "localhost" || PRIVATE_SUFFIXES.some((x) => host.endsWith(x))) return false;
  return !/^[0-9]+$/.test(host.split(".").pop() as string);
}

export function originProblem(origin: any): string | null {
  if (typeof origin !== "string") return "resolver must be a string";
  const m = ORIGIN_RE.exec(origin);
  if (!m) return "resolver must be an https origin: scheme and host, nothing else";
  if (!publicHost(m[1])) return "resolver must be a lowercase public DNS name, not an IP address, localhost or a private-use name";
  if (m[2] !== undefined) {
    const p = Number(m[2]);
    if (p < 1 || p > 65535 || p === 443 || m[2].startsWith("0")) return "resolver has a bad or default port";
  }
  return null;
}

const verdict = (): Verdict => ({ ok: false, trusted: false, errors: [], untrusted: [], notes: [] });
function finish<T extends Verdict>(v: T): T {
  v.ok = v.errors.length === 0;
  v.trusted = v.ok && v.untrusted.length === 0;
  return v;
}

// ── making documents (issuer side) ───────────────────────────────────────────
export function makeReference(a: {
  kind: string; sid: string; resolver: string; issuedAt: string; expiresAt: string; nonce: string;
  issuer: { id: string; kid: string }; alg: string; secretHex: string; card?: { id: string; hash: string }; domain?: string;
}): any {
  const doc: any = { format: FORMAT, kind: a.kind, sid: a.sid, resolver: a.resolver, issued_at: a.issuedAt, expires_at: a.expiresAt, nonce: a.nonce, issuer: a.issuer };
  if (a.card !== undefined) doc.card = a.card;
  if (a.domain !== undefined) doc.domain = a.domain;
  return sid.signDocument(doc, a.alg, a.secretHex);
}

export function makeResolution(reference: any, a: {
  status: string; issuedAt: string; freshUntil: string; issuer: { id: string; kid: string }; alg: string; secretHex: string;
  certificate?: any; runtime?: any; card?: any; supersededBy?: string;
}): any {
  const doc: any = { format: RESOLUTION_FORMAT, reference_hash: reference.hash, resolver: reference.resolver, status: a.status,
    issued_at: a.issuedAt, fresh_until: a.freshUntil, issuer: a.issuer };
  if (a.certificate !== undefined) doc.certificate = a.certificate;
  if (a.runtime !== undefined) doc.runtime = a.runtime;
  if (a.card !== undefined) doc.card = a.card;
  if (a.supersededBy !== undefined) doc.superseded_by = a.supersededBy;
  return sid.signDocument(doc, a.alg, a.secretHex);
}

/** The text a QR code carries: the resolver's origin and the signed reference. */
export function toWire(doc: any): string {
  return `${doc.resolver}/q/${b64url(Buffer.from(canonicalJson(doc), "utf8"))}`;
}

export function parseWire(text: any): { origin: string; doc: any } {
  if (typeof text !== "string") throw new Error("a QR payload is text");
  const m = WIRE_RE.exec(text);
  if (!m) throw new Error("not a helix-qr URL: expected https://<resolver>/q/<payload>");
  let doc: any;
  try {
    doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(b64urlDecode(m[2])));
  } catch {
    throw new Error("the payload is not base64url JSON");
  }
  if (!isObj(doc)) throw new Error("the payload is not a JSON object");
  return { origin: m[1], doc };
}

// ── verifying a reference ────────────────────────────────────────────────────
export function verifyReference(subject: any, opts: { trust?: any; now?: string | null } = {}): Verdict {
  const v = verdict();
  const { errors: err, untrusted } = v;
  let origin: string | null = null;
  let doc: any;
  if (typeof subject === "string") {
    try {
      const p = parseWire(subject);
      origin = p.origin;
      doc = p.doc;
    } catch (e: any) {
      err.push(e.message);
      return finish(v);
    }
  } else {
    doc = subject;
  }
  if (!isObj(doc)) {
    err.push("not an object");
    return finish(v);
  }

  const unknown = sorted(Object.keys(doc).filter((k) => !REF_KEYS.has(k)));
  if (unknown.length) err.push(`unknown field(s): ${unknown.join(", ")}`);
  if (doc.format !== FORMAT) err.push(`format must be ${FORMAT}`);
  if (!KINDS.includes(doc.kind)) err.push("kind must be agent or business");
  if (typeof doc.sid !== "string" || !sid.ID_RE.test(doc.sid)) err.push("sid must be a sid_<slug> identifier");
  const card = doc.card;
  if (card !== undefined && card !== null) {
    const keys = isObj(card) ? sorted(Object.keys(card)).join(",") : "";
    if (!(keys === "hash,id" && typeof card.id === "string" && SLUG.test(card.id) && typeof card.hash === "string" && HEX64.test(card.hash))) {
      err.push("card must be {id, hash}");
    }
  }
  if (doc.kind === "business" && (card === undefined || card === null)) err.push("a business reference must carry a card");
  const problem = originProblem(doc.resolver);
  if (problem) err.push(problem);
  if ("domain" in doc && !(typeof doc.domain === "string" && publicHost(doc.domain))) err.push("domain must be a public DNS name");
  if (!timeOk(doc.issued_at) || !timeOk(doc.expires_at)) {
    err.push("issued_at and expires_at must be RFC 3339 UTC");
  } else if (doc.expires_at <= doc.issued_at) {
    err.push("expires_at must be after issued_at");
  } else if (ms(doc.expires_at) - ms(doc.issued_at) > MAX_LIFETIME_MS) {
    err.push("a reference may not be valid for more than 400 days");
  }
  if (typeof doc.nonce !== "string" || !NONCE_RE.test(doc.nonce)) err.push("nonce must be 16 random bytes, base64url");
  const secrets = sid.findSecrets(doc);
  if (secrets.length) err.push("secret material must not be present: " + secrets.join(", "));
  if (err.length) return finish(v);

  if (doc.hash !== sid.sidHash(doc)) {
    err.push("hash does not match the document");
    return finish(v);
  }
  const ic = sid.issuerCheck(doc, opts.trust, doc.issued_at);
  err.push(...ic.errors);
  untrusted.push(...ic.untrusted);

  if (origin === null) untrusted.push("domain binding was not checked (no URL was supplied)");
  else if (origin !== doc.resolver) err.push(`the URL's origin (${origin}) does not match the signed resolver (${doc.resolver})`);

  if (opts.now === undefined || opts.now === null) {
    untrusted.push("expiry not checked (no clock)");
  } else {
    const t = ms(opts.now);
    if (t >= ms(doc.expires_at)) untrusted.push("the reference has expired");
    else if (t + SKEW_MS < ms(doc.issued_at)) untrusted.push("the reference is not valid yet");
  }
  return finish(v);
}

// ── verifying a resolution ───────────────────────────────────────────────────
export function checkResolutionEnvelope(
  res: any, ref: any, opts: { trust?: any; now?: string | null; fetchedFrom?: string | null } = {},
): Verdict {
  const v = verdict();
  const { errors: err, untrusted } = v;
  if (!isObj(res)) {
    err.push("not an object");
    return finish(v);
  }
  const unknown = sorted(Object.keys(res).filter((k) => !RES_KEYS.has(k)));
  if (unknown.length) err.push(`unknown field(s): ${unknown.join(", ")}`);
  if (res.format !== RESOLUTION_FORMAT) err.push(`format must be ${RESOLUTION_FORMAT}`);
  if (!STATUSES.includes(res.status)) err.push("status must be active, suspended, revoked or superseded");
  if (typeof res.reference_hash !== "string" || !HEX64.test(res.reference_hash)) err.push("reference_hash must be 64 hex characters");
  if ("superseded_by" in res && !(typeof res.superseded_by === "string" && HEX64.test(res.superseded_by))) err.push("superseded_by must be 64 hex characters");
  if (!timeOk(res.issued_at) || !timeOk(res.fresh_until)) {
    err.push("issued_at and fresh_until must be RFC 3339 UTC");
  } else if (res.fresh_until <= res.issued_at) {
    err.push("fresh_until must be after issued_at");
  } else if (ms(res.fresh_until) - ms(res.issued_at) > MAX_FRESH_MS) {
    err.push("a resolution may not be fresh for more than 24 hours");
  }
  const rp = originProblem(res.resolver);
  if (rp) err.push(rp);
  const rest: any = {};
  for (const k of Object.keys(res)) if (k !== "certificate" && k !== "runtime") rest[k] = res[k];
  const secrets = sid.findSecrets(rest);
  if (secrets.length) err.push("secret material must not be present: " + secrets.join(", "));
  if (err.length) return finish(v);

  if (res.hash !== sid.sidHash(res)) {
    err.push("hash does not match the document");
    return finish(v);
  }
  const ic = sid.issuerCheck(res, opts.trust, res.issued_at);
  err.push(...ic.errors);
  untrusted.push(...ic.untrusted);
  if ((res.issuer || {}).id !== ((ref || {}).issuer || {}).id) err.push("the resolution must be signed by the reference's issuer");
  if (res.reference_hash !== (ref || {}).hash) err.push("this resolution answers a different reference");
  if (res.resolver !== (ref || {}).resolver) err.push("the resolution's resolver differs from the reference's");
  if (opts.fetchedFrom === undefined || opts.fetchedFrom === null) untrusted.push("where the resolution was fetched from was not checked");
  else if (opts.fetchedFrom !== (ref || {}).resolver) err.push(`fetched from ${opts.fetchedFrom}, but the reference names ${(ref || {}).resolver}`);

  if (opts.now === undefined || opts.now === null) {
    untrusted.push("freshness not checked (no clock)");
  } else {
    const t = ms(opts.now);
    if (t >= ms(res.fresh_until)) untrusted.push("the resolution is stale");
    else if (t + SKEW_MS < ms(res.issued_at)) untrusted.push("the resolution is not valid yet");
  }
  if (res.status !== "active") untrusted.push(`the contact is ${res.status}`);
  return finish(v);
}

const bindingOf = (cert: any, id: any): any => (cert.bindings || []).find((b: any) => b.id === id);

/** Typed endpoints from a VERIFIED runtime statement. Keys come from the
 * certificate's bindings, never from the statement's free text; a nostr key is
 * never a LAN key; private addresses are not published. */
export function publicEndpoints(runtime: any, cert: any, notes: string[]): any[] {
  const out: any[] = [];
  for (const e of runtime.endpoints || []) {
    const t = e.type;
    const addr = typeof e.address === "string" ? e.address : "";
    if (t === "nostr") {
      const m = WSS_RE.exec(addr);
      const b = bindingOf(cert, e.binding);
      if (m && publicHost(m[1]) && b) out.push({ type: "nostr", relay: addr, binding: b.id, alg: b.alg, public_key: b.public_key });
      else notes.push(`nostr endpoint '${addr}' omitted: not a public wss:// relay`);
    } else if (t === "meshenger-lan") {
      notes.push("a LAN endpoint is not published through the public resolver");
    } else if (t === "sip") {
      if (SIP_RE.test(addr)) out.push({ type: "sip", uri: addr });
      else notes.push(`sip endpoint '${addr}' omitted: not a sip: URI`);
    } else if (t === "a2a" || t === "mcp" || t === "https") {
      const m = HTTPS_URL_RE.exec(addr);
      if (m && publicHost(m[1])) out.push({ type: t, url: addr });
      else notes.push(`${t} endpoint '${addr}' omitted: not a public https URL`);
    }
  }
  return out;
}

/** What a client stores when the user confirms a contact. */
export function pinFrom(cert: any): any {
  return { sid: cert.id, version: cert.version, hash: cert.hash, certificate: cert };
}

export function checkPin(pin: any, cert: any, trust: any): { errors: string[]; changes: { binding: string; change: string }[] } {
  const errors: string[] = [];
  const changes: { binding: string; change: string }[] = [];
  if (cert.id !== pin.sid) return { errors: [`the contact's identity changed (${pin.sid} -> ${cert.id})`], changes };
  if (cert.version < pin.version) return { errors: ["the identity went back to an older version"], changes };
  if (cert.version === pin.version) {
    if (cert.hash !== pin.hash) errors.push("the same version has different content");
  } else {
    const r = sid.verifySid(cert, { trust, previous: pin.certificate });
    if (!r.ok) errors.push("the new identity version does not extend the pinned one: " + r.errors.slice(0, 1).join("; "));
  }
  const map = (c: any) => new Map<string, string>((c.bindings || []).map((b: any) => [b.id, b.public_key]));
  const oldB = map(pin.certificate);
  const newB = map(cert);
  for (const k of sorted([...new Set([...oldB.keys(), ...newB.keys()])])) {
    if (oldB.get(k) !== newB.get(k)) changes.push({ binding: k, change: !oldB.has(k) ? "added" : !newB.has(k) ? "removed" : "rotated" });
  }
  return { errors, changes };
}

export function verifyResolution(
  res: any, ref: any,
  opts: { trust?: any; now?: string | null; fetchedFrom?: string | null; pin?: any; head?: any } = {},
): ResolutionVerdict {
  const v = checkResolutionEnvelope(res, ref, opts) as ResolutionVerdict;
  v.endpoints = [];
  v.sid = null;
  v.card = null;
  v.status = isObj(res) ? res.status ?? null : null;
  v.needs_confirmation = false;
  v.key_changes = [];
  v.pin = null;
  const { errors: err, untrusted, notes } = v;
  if (err.length || res.status !== "active") return finish(v);

  const cert = res.certificate;
  const rt = res.runtime;
  if (!isObj(cert) || !isObj(rt)) {
    err.push("an active resolution must carry a certificate and a runtime statement");
    return finish(v);
  }
  const cr = sid.verifySid(cert, { trust: opts.trust, head: opts.head });
  if (!cr.ok) {
    err.push("the certificate does not verify: " + cr.errors.slice(0, 2).join("; "));
    return finish(v);
  }
  if (cert.id !== ref.sid) {
    err.push(`the resolution names a different agent (${cert.id}) than the QR code (${ref.sid})`);
    return finish(v);
  }
  const rr = sid.verifyRuntime(rt, cert, { trust: opts.trust, now: opts.now, head: opts.head });
  if (!rr.ok) {
    err.push("the runtime statement does not verify: " + rr.errors.slice(0, 2).join("; "));
    return finish(v);
  }
  for (const u of [...cr.untrusted, ...rr.untrusted]) if (!untrusted.includes(u)) untrusted.push(u);

  const rcard = res.card;
  const qcard = ref.card;
  if (qcard !== undefined && qcard !== null) {
    if (!isObj(rcard) || rcard.id !== qcard.id) {
      err.push("the resolution's card is not the card the QR code names");
      return finish(v);
    }
    if (rcard.hash !== qcard.hash) notes.push("the business card has changed since this QR code was issued");
  }
  v.card = rcard ?? null;
  v.endpoints = publicEndpoints(rt, cert, notes);
  v.sid = { id: cert.id, version: cert.version, hash: cert.hash, acting_hash: cert.acting_hash ?? null, name: (cert.identity || {}).name ?? null };
  if (opts.pin !== undefined && opts.pin !== null) {
    const { errors: perr, changes } = checkPin(opts.pin, cert, opts.trust);
    err.push(...perr);
    v.key_changes = changes;
    v.needs_confirmation = changes.length > 0;
    if (perr.length) return finish(v);
  } else {
    v.needs_confirmation = true; // a first contact is always the user's decision
  }
  v.pin = pinFrom(cert);
  return finish(v);
}
