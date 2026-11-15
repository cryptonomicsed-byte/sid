/**
 * sigs.ts — signature suites for sid/0.2.
 *
 *   ed25519   RFC 8032 Ed25519 over the message bytes            (node:crypto)
 *   bip340    BIP-340 Schnorr over sha256(message bytes)         (@noble/curves)
 *
 * Keys are 32 bytes and signatures 64 bytes, hex on the wire. Mirrors
 * implementations/python/sigs.py: the same key and message give the same
 * signature in both (Ed25519 is deterministic; BIP-340 is signed with zero
 * auxiliary randomness).
 */
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "crypto";
import { schnorr } from "@noble/curves/secp256k1";

export const ALGS = ["ed25519", "bip340"] as const;
export type Alg = (typeof ALGS)[number];

const HEX = /^[0-9a-f]*$/;
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const ED_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");

function fromHex(hex: unknown, bytes: number): Buffer | null {
  if (typeof hex !== "string" || hex.length !== bytes * 2 || !HEX.test(hex)) return null;
  return Buffer.from(hex, "hex");
}

function edPublicKey(raw: Buffer) {
  return createPublicKey({ key: Buffer.concat([ED_SPKI, raw]), format: "der", type: "spki" });
}

function edPrivateKey(seed: Buffer) {
  return createPrivateKey({ key: Buffer.concat([ED_PKCS8, seed]), format: "der", type: "pkcs8" });
}

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

export function publicKey(alg: string, secretHex: string): string {
  const secret = fromHex(secretHex, 32);
  if (!secret) throw new Error("secret key must be 64-hex");
  if (alg === "ed25519") {
    const der = createPublicKey(edPrivateKey(secret)).export({ format: "der", type: "spki" }) as Buffer;
    return der.subarray(der.length - 32).toString("hex");
  }
  if (alg === "bip340") return Buffer.from(schnorr.getPublicKey(secret)).toString("hex");
  throw new Error(`unsupported alg ${alg}`);
}

export function sign(alg: string, secretHex: string, message: string): string {
  const secret = fromHex(secretHex, 32);
  if (!secret) throw new Error("secret key must be 64-hex");
  const data = Buffer.from(message, "utf8");
  if (alg === "ed25519") return nodeSign(null, data, edPrivateKey(secret)).toString("hex");
  if (alg === "bip340") {
    return Buffer.from(schnorr.sign(sha256(data), secret, new Uint8Array(32))).toString("hex");
  }
  throw new Error(`unsupported alg ${alg}`);
}

/** False for anything malformed or unsupported — never throws. */
export function verify(alg: unknown, publicHex: unknown, message: string, signatureHex: unknown): boolean {
  const pub = fromHex(publicHex, 32);
  const sig = fromHex(signatureHex, 64);
  if (!pub || !sig) return false;
  const data = Buffer.from(message, "utf8");
  try {
    if (alg === "ed25519") return nodeVerify(null, data, edPublicKey(pub), sig);
    if (alg === "bip340") return schnorr.verify(sig, sha256(data), pub);
  } catch {
    return false;
  }
  return false;
}
