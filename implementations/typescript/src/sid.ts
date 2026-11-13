/**
 * sid.ts — SID (Sovereign ID / Super Intelligence Document) core, `sid/0.1`.
 *
 * A SID is an agent birth certificate: issuing v1 is the birth, and every later
 * version is a mutation chained by hash. The canonicalization and hash contract
 * are inherited from card-protocol (see canonical.ts); the business-card format
 * stays there.
 *
 * Everything here is deterministic and offline. Signing a Nostr event is NOT done
 * here: an unsigned event template is returned so the key-holding gatekeeper (not
 * the format library) signs.
 */
import { createHash } from "crypto";
import { canonicalJson, canonicalHash } from "./canonical";

export const FORMAT = "sid/0.1";
export const BIRTH_EVENT_KIND = 30401;

/** The keys an agent may ACT on. Genesis, time, provenance, changelog and
 *  appendix are attestation/history, so a re-anchor never forces a reload. */
export const ACTING_KEYS = ["identity", "capabilities", "memory", "lifecycle", "status"] as const;

export const STATUSES = ["cast", "live", "suspended", "retired"] as const;

const HEX64 = /^[0-9a-f]{64}$/;
const ID_RE = /^sid_[a-z0-9][a-z0-9-]*$/;

/** SHA-256 hex over the acting keys only. */
export function actingHash(cert: any): string {
  const body: any = {};
  for (const k of ACTING_KEYS) if (cert[k] !== undefined) body[k] = cert[k];
  return createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
}

/** SHA-256 hex over the full canonical body (minus `hash` and `_`-prefixed keys). */
export function sidHash(cert: any): string {
  return canonicalHash(cert);
}

/** Stamp hash + acting_hash onto a copy. Call this, then emit.
 *  Order matters: acting_hash first, because `hash` covers it.
 *
 *  v1 defaults are only FILLED when absent — never overwritten. A caller that
 *  hands in a v1 carrying a chain keeps it, and verifySid() rejects it: silently
 *  normalising a malformed certificate is how a fail-closed check becomes a
 *  no-op. */
export function finalizeSid(cert: any): any {
  const c = JSON.parse(JSON.stringify(cert));
  if (c.version === 1) {
    if (c.previous_version === undefined) c.previous_version = null;
    if (c.previous_hash === undefined || c.previous_hash === null) c.previous_hash = "none";
  }
  c.acting_hash = actingHash(c);
  c.hash = sidHash(c);
  return c;
}

/** Verify a certificate in isolation (v>1 chain links are checked by the caller,
 *  which needs the previous version). Returns every problem found, not the first. */
export function verifySid(cert: any, previous?: any): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  const add = (m: string) => errors.push(m);
  if (!cert || typeof cert !== "object") return { ok: false, errors: ["not an object"] };

  if (cert.format !== FORMAT) add(`format must be ${FORMAT}`);
  if (typeof cert.id !== "string" || !ID_RE.test(cert.id)) add("id must match sid_<slug>");
  if (!Number.isInteger(cert.version) || cert.version < 1) add("version must be an integer >= 1");
  if (!STATUSES.includes(cert.status)) add("status must be cast|live|suspended|retired");
  if (typeof cert.born_at !== "string" || !cert.born_at) add("born_at is required");

  const i = cert.identity;
  if (!i || typeof i !== "object") {
    add("identity is required");
  } else {
    if (i.type !== "agent") add('identity.type must be "agent"');
    if (!Number.isInteger(i.odu_primary) || i.odu_primary < 0 || i.odu_primary > 255)
      add("identity.odu_primary must be 0-255");
    if (!Number.isInteger(i.odu_secondary) || i.odu_secondary < 0 || i.odu_secondary > 255)
      add("identity.odu_secondary must be 0-255");
    if (Number.isInteger(i.odu_primary) && Number.isInteger(i.odu_secondary)) {
      const expected = (i.odu_primary << 8) | i.odu_secondary;
      if (i.odu_link !== expected)
        add(`identity.odu_link ${i.odu_link} != (odu_primary<<8|odu_secondary) ${expected}`);
    }
    // Digital Calabash: the reading is derived from the address, so it must
    // agree with it. Data-only — no Odù corpus needed to check this.
    const cal = i.calabash;
    if (cal !== undefined) {
      if (!cal || typeof cal !== "object") {
        add("identity.calabash must be an object");
      } else {
        if (
          !Number.isInteger(cal.id) ||
          !Number.isInteger(cal.top) ||
          !Number.isInteger(cal.bottom)
        ) {
          add("identity.calabash id/top/bottom must be integers");
        } else if (cal.id !== i.odu_link || cal.top !== i.odu_primary || cal.bottom !== i.odu_secondary) {
          add(
            `identity.calabash ${cal.id}/${cal.top}/${cal.bottom} disagrees with the Odu fields ` +
              `${i.odu_link}/${i.odu_primary}/${i.odu_secondary}`,
          );
        }
        if (typeof cal.vessel !== "string" || !cal.vessel)
          add("identity.calabash.vessel must name one of the 16 Action Vessels");
      }
    }
  }

  if (!HEX64.test(String(cert.hash || ""))) add("hash must be 64-hex");
  else if (sidHash(cert) !== cert.hash) add("hash does not match the canonical body");
  if (!HEX64.test(String(cert.acting_hash || ""))) add("acting_hash must be 64-hex");
  else if (actingHash(cert) !== cert.acting_hash) add("acting_hash does not match the acting keys");

  if (cert.version === 1) {
    if (cert.previous_version !== null) add("v1 must have previous_version = null");
    if (cert.previous_hash !== "none" && cert.previous_hash !== null)
      add('v1 must have previous_hash = "none"');
  } else {
    if (cert.previous_version !== cert.version - 1) add("previous_version must be version - 1");
    if (!HEX64.test(String(cert.previous_hash || ""))) add("previous_hash must be 64-hex for v>1");
  }

  if (previous) {
    if (cert.previous_hash !== previous.hash)
      add("previous_hash does not match the hash of the supplied previous version");
    if (cert.version !== previous.version + 1)
      add("version is not previous.version + 1");
  }

  if (cert.lifecycle && cert.lifecycle.state !== undefined && cert.lifecycle.state !== cert.status)
    add("lifecycle.state must equal status");
  const t = cert.time;
  if (t) {
    if (t.anchored === true && !t.ots_proof) add("time.anchored = true requires time.ots_proof");
    // A fresh OTS stamp is a commitment to a calendar server, not a Bitcoin
    // attestation. Claiming anchored on it is an overclaim.
    if (t.anchored === true && t.ots_status !== "complete")
      add('time.anchored = true requires time.ots_status = "complete"');
    // The clock has exactly one owner.
    if (t.anchored === true && t.clock_source !== "okf")
      add('time.anchored = true requires time.clock_source = "okf"');
    if (t.calendar !== undefined) {
      if (!t.calendar || typeof t.calendar !== "object") {
        add("time.calendar must be an object");
      } else {
        for (const k of ["epoch", "cycle", "phase"]) {
          const v = t.calendar[k];
          if (!Number.isInteger(v) || v < 0) add(`time.calendar.${k} must be a non-negative integer`);
        }
      }
    }
  }

  for (const forbidden of ["seed", "mnemonic", "private_key", "nsec", "secret"]) {
    if (cert.genesis && cert.genesis[forbidden] !== undefined) add(`genesis must not carry ${forbidden}`);
    if (cert.identity && cert.identity[forbidden] !== undefined) add(`identity must not carry ${forbidden}`);
  }

  return { ok: errors.length === 0, errors };
}

const SECTION_TITLES: [string, string][] = [
  ["identity", "Identity"],
  ["genesis", "Genesis"],
  ["time", "Time"],
  ["capabilities", "Capabilities"],
  ["memory", "Memory"],
  ["provenance", "Provenance"],
  ["lifecycle", "Lifecycle"],
];

/** Emit SID.md. The stamped hash always reflects the body actually written. */
export function emitSidMd(cert: any, changelog: string[] = cert.changelog || []): string {
  const h = sidHash(cert);
  const ah = actingHash(cert);
  const fm: string[] = ["---", `format: ${FORMAT}`, `id: ${cert.id}`, `version: ${cert.version}`];
  if (cert.version === 1) {
    fm.push("previous_version: null", "previous_hash: none");
  } else {
    fm.push(`previous_version: ${cert.previous_version}`, `previous_hash: ${cert.previous_hash}`);
  }
  fm.push(`hash: ${h}`, `acting_hash: ${ah}`, `status: ${cert.status}`, `born_at: ${cert.born_at}`);
  if (cert.updated) fm.push(`updated: ${cert.updated}`);
  fm.push("---");

  const out: string[] = [fm.join("\n"), ""];
  out.push(`# SID — ${(cert.identity && cert.identity.name) || cert.id}`, "");
  for (const [key, title] of SECTION_TITLES) {
    if (cert[key] === undefined) continue;
    out.push(`## ${title}`, "");
    out.push(`<!-- sid:${key}@1 ${JSON.stringify(cert[key])} -->`, "");
    out.push(summary(key, cert[key]), "");
  }
  if (changelog.length) out.push("## Changelog", "", ...changelog.map((l) => `- ${l}`), "");
  if (cert.appendix !== undefined)
    out.push("## Appendix", "", `<!-- sid:appendix@1 ${JSON.stringify(cert.appendix)} -->`, "");
  return out.join("\n");
}

function summary(key: string, v: any): string {
  switch (key) {
    case "identity":
      return [
        `- name: ${v.name}`,
        `- odu: ${v.odu_primary}/${v.odu_secondary} (link ${v.odu_link})`,
        `- npub: ${v.npub || "—"}`,
        `- principal: ${v.principal || "—"}`,
        `- parent: ${v.parent || "—"}`,
        v.description ? `- ${v.description}` : "",
      ].filter(Boolean).join("\n");
    case "genesis":
      return `- entropy: ${v.entropy_source} · seed ${String(v.seed_hash).slice(0, 12)}… · keygen ${v.keygen}`;
    case "time":
      return `- birth block: ${v.birth_block ?? "—"}${v.anchored ? " (anchored)" : " (unanchored claim)"}`;
    case "capabilities":
      return [
        `- skills: ${(v.skills || []).join(", ") || "—"}`,
        `- permissions: ${(v.permissions || []).join(", ") || "—"}`,
      ].join("\n");
    case "memory":
      return `- locator: ${v.locator || "—"} · root ${v.namespace_root ? String(v.namespace_root).slice(0, 12) + "…" : "—"}`;
    case "provenance":
      return `- trace head: ${v.trace_chain_head ? String(v.trace_chain_head).slice(0, 12) + "…" : "—"} · profile ${v.profile_id || "—"}`;
    case "lifecycle":
      return `- state: ${v.state} · ${(v.history || []).length} transition(s)`;
    default:
      return "";
  }
}

/** Parse SID.md back to the certificate JSON. Lossless for anything emitted above:
 *  sections ride in `<!-- sid:<key>@1 {json} -->` comments. */
export function parseSidMd(md: string): any {
  const m = md.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error("SID.md: missing frontmatter");
  const cert: any = {};
  for (const line of m[1].split("\n")) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const i = line.indexOf(":");
    if (i < 0) continue;
    const k = line.slice(0, i).trim();
    let v: any = line.slice(i + 1).trim();
    if (v === "null") v = null;
    else if (/^-?\d+$/.test(v)) v = parseInt(v, 10);
    cert[k] = v;
  }
  const re = /<!-- sid:([a-z_]+)@1 (\{[\s\S]*?\}) -->/g;
  let mm: RegExpExecArray | null;
  while ((mm = re.exec(md))) {
    try {
      cert[mm[1]] = JSON.parse(mm[2]);
    } catch {
      throw new Error(`SID.md: unparseable ${mm[1]} block`);
    }
  }
  const ch = md.match(/## Changelog\n\n((?:- .*\n?)+)/);
  if (ch) cert.changelog = ch[1].trim().split("\n").map((l) => l.replace(/^- /, ""));
  return cert;
}

/** Unsigned Nostr birth/identity announcement, kind 30401 (parameterized
 *  replaceable, d = sid id). The gatekeeper signs; this only shapes it. */
export function birthEvent(
  cert: any,
  opts: { relays?: string[]; includeMemoryLocator?: boolean } = {}
): { kind: number; content: string; tags: string[][] } {
  const content: any = {
    format: FORMAT,
    id: cert.id,
    version: cert.version,
    hash: cert.hash,
    acting_hash: cert.acting_hash,
    status: cert.status,
    born_at: cert.born_at,
    odu_link: cert.identity ? cert.identity.odu_link : null,
    npub: (cert.identity && cert.identity.npub) || null,
    principal: (cert.identity && cert.identity.principal) || null,
    parent: (cert.identity && cert.identity.parent) || null,
    birth_block: (cert.time && cert.time.birth_block) || null,
    birth_block_hash: (cert.time && cert.time.birth_block_hash) || null,
  };
  if (opts.includeMemoryLocator) content.memory_locator = (cert.memory && cert.memory.locator) || null;

  const tags: string[][] = [
    ["d", cert.id],
    ["format", FORMAT],
    ["v", String(cert.version)],
    ["hash", cert.hash],
    ["status", cert.status],
    ["alt", `SID birth certificate: ${(cert.identity && cert.identity.name) || cert.id} v${cert.version}`],
  ];
  if (opts.relays && opts.relays.length) tags.push(["relays", opts.relays.join(",")]);
  return { kind: BIRTH_EVENT_KIND, content: JSON.stringify(content), tags };
}
