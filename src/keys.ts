/**
 * Key helpers for the fixture driven suite.
 *
 * The chambers verify real ed25519 signatures with node:crypto, so the fixtures
 * never carry a private key: a test mints an ephemeral key pair, signs the
 * canonical statement from the JSON fixture, and hands the chamber a public key
 * in raw 32 byte hex. No network, no ethers, no other dependency.
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

export interface KeyPair {
  /** Raw 32 byte ed25519 public key as lowercase hex. */
  publicKeyHex: string;
  privateKey: KeyObject;
  sign(message: string): string;
}

function rawPublicKeyHex(key: KeyObject): string {
  const spki = key.export({ format: "der", type: "spki" });
  // The last 32 bytes of an ed25519 SPKI DER structure are the raw key.
  return Buffer.from(spki.subarray(spki.length - 32)).toString("hex");
}

export function publicKeyFromHex(hex: string): KeyObject {
  const raw = Buffer.from(hex, "hex");
  if (raw.length !== 32) throw new Error("ed25519 public key must be 32 bytes");
  return createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: raw.toString("base64url"),
    },
    format: "jwk",
  });
}

export function newKeyPair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyHex: rawPublicKeyHex(publicKey),
    privateKey,
    sign(message: string): string {
      return cryptoSign(null, Buffer.from(message, "utf8"), privateKey).toString("hex");
    },
  };
}

export function verifyHex(publicKeyHex: string, message: string, signatureHex: string): boolean {
  let key: KeyObject;
  let sig: Buffer;
  try {
    key = publicKeyFromHex(publicKeyHex);
    sig = Buffer.from(signatureHex, "hex");
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return cryptoVerify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}
