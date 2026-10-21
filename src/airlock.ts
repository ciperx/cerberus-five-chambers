/**
 * Cerberus airlock reference implementation.
 *
 * Five chambers, always in this order:
 *   1. identity   - an ed25519 signed claim binds agent id, chain and key
 *   2. trust      - an allowlisted attestor set produces a score over a window
 *   3. intent     - the declared action, scope, budget and nonce are acceptable
 *   4. soul       - the live agent answers a fresh nonce with its session key
 *   5. session    - a short lived HS256 token is issued and verified
 *
 * Every chamber returns a verdict instead of throwing, so the suite can assert
 * on the refusal code per chamber. Nothing here touches the network and nothing
 * here is timed in wall clock terms: "now" is always injected.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { verifyHex } from "./keys.js";

export const CHAMBERS = ["identity", "trust", "intent", "soul", "session"] as const;
export type Chamber = (typeof CHAMBERS)[number];

export interface Verdict {
  ok: boolean;
  chamber: Chamber;
  code: string;
  reason: string;
}

/** Canonical statement that an identity claim must sign. */
export function identityStatement(agentId: string, chain: string): string {
  return `LAX-IDENTITY/1|agent=${agentId}|chain=${chain}`;
}

/** Canonical statement that a SOUL response must sign. */
export function soulStatement(nonce: string, sessionPublicKeyHex: string): string {
  return `LAX-SOUL/1|nonce=${nonce}|session=${sessionPublicKeyHex}`;
}

const LATIN_DIGITS_AND_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CHAINS = new Set(["base", "solana"]);

// ---------------------------------------------------------------- chamber 1

export interface IdentityClaim {
  agentId: string;
  chain: string;
  publicKeyHex: string;
  statement: string;
  issuedAt: string;
  signature: string;
}

export interface IdentityOptions {
  now: Date;
  maxAgeMs?: number;
  maxSkewMs?: number;
}

export function checkIdentity(claim: Partial<IdentityClaim>, options: IdentityOptions): Verdict {
  const fail = (code: string, reason: string): Verdict => ({ ok: false, chamber: "identity", code, reason });
  const maxAgeMs = options.maxAgeMs ?? 15 * 60_000;
  const maxSkewMs = options.maxSkewMs ?? 60_000;

  if (
    typeof claim.agentId !== "string" ||
    typeof claim.chain !== "string" ||
    typeof claim.publicKeyHex !== "string" ||
    typeof claim.statement !== "string" ||
    typeof claim.issuedAt !== "string" ||
    typeof claim.signature !== "string"
  ) {
    return fail("IDENTITY_MALFORMED", "claim is missing a required field");
  }
  if (!LATIN_DIGITS_AND_ID.test(claim.agentId)) {
    return fail("IDENTITY_MALFORMED", "agent id must be latin lowercase letters, digits or dash, 3 to 64 chars");
  }
  if (!HEX64.test(claim.publicKeyHex)) {
    return fail("IDENTITY_MALFORMED", "public key must be 32 bytes of lowercase hex");
  }
  if (!CHAINS.has(claim.chain)) {
    return fail("IDENTITY_CHAIN", `chain must be one of base or solana, got ${claim.chain}`);
  }
  if (claim.statement !== identityStatement(claim.agentId, claim.chain)) {
    return fail("IDENTITY_STATEMENT", "statement is not the canonical form for this agent id and chain");
  }
  const issuedAt = Date.parse(claim.issuedAt);
  if (Number.isNaN(issuedAt)) {
    return fail("IDENTITY_MALFORMED", "issuedAt is not an ISO 8601 timestamp");
  }
  const age = options.now.getTime() - issuedAt;
  if (age > maxAgeMs) {
    return fail("IDENTITY_STALE", `claim is ${Math.round(age / 1000)}s old, limit is ${Math.round(maxAgeMs / 1000)}s`);
  }
  if (age < -maxSkewMs) {
    return fail("IDENTITY_STALE", "claim is issued in the future beyond the allowed skew");
  }
  if (!verifyHex(claim.publicKeyHex, claim.statement, claim.signature)) {
    return fail("IDENTITY_SIGNATURE", "ed25519 signature does not verify over the statement");
  }
  return { ok: true, chamber: "identity", code: "OK", reason: "claim signed by the presented key" };
}

// ---------------------------------------------------------------- chamber 2

export type AttestationKind = "session" | "review" | "slash";

export interface Attestation {
  attestor: string;
  subject: string;
  kind: AttestationKind;
  score: number;
  issuedAt: string;
}

export interface TrustPolicy {
  attestors: string[];
  minScore: number;
  minSessions: number;
  maxSlashes: number;
  windowDays: number;
  slashPenalty: number;
}

export interface TrustReport {
  score: number;
  sessions: number;
  slashes: number;
  usable: Attestation[];
  ignored: Attestation[];
}

/** Deterministic score: mean attestor score minus a flat penalty per slash. */
export function scoreTrust(
  subject: string,
  attestations: Attestation[],
  policy: TrustPolicy,
  now: Date,
): TrustReport {
  const allowed = new Set(policy.attestors);
  const cutoff = now.getTime() - policy.windowDays * 86_400_000;
  const usable: Attestation[] = [];
  const ignored: Attestation[] = [];

  for (const entry of attestations) {
    const age = Date.parse(entry.issuedAt);
    const inWindow = !Number.isNaN(age) && age >= cutoff && age <= now.getTime();
    if (entry.subject !== subject || !allowed.has(entry.attestor) || !inWindow) {
      ignored.push(entry);
      continue;
    }
    usable.push(entry);
  }

  // One vote per attestor: keep the newest attestation that attestor filed.
  const newest = new Map<string, Attestation>();
  for (const entry of usable) {
    const current = newest.get(entry.attestor);
    if (current === undefined || Date.parse(entry.issuedAt) > Date.parse(current.issuedAt)) {
      newest.set(entry.attestor, entry);
    }
  }
  const votes = [...newest.values()];
  const positives = votes.filter((v) => v.kind !== "slash");
  const slashes = votes.filter((v) => v.kind === "slash");
  const mean = positives.length === 0 ? 0 : positives.reduce((sum, v) => sum + v.score, 0) / positives.length;
  const score = Math.max(0, Math.round((mean - slashes.length * policy.slashPenalty) * 100) / 100);
  const sessions = positives.filter((v) => v.kind === "session").length;

  return { score, sessions, slashes: slashes.length, usable: votes, ignored };
}

export function checkTrust(
  subject: string,
  attestations: Attestation[],
  policy: TrustPolicy,
  now: Date,
): Verdict & { report?: TrustReport } {
  const fail = (code: string, reason: string, report: TrustReport): Verdict & { report: TrustReport } => ({
    ok: false,
    chamber: "trust",
    code,
    reason,
    report,
  });
  const report = scoreTrust(subject, attestations, policy, now);
  if (report.usable.length === 0) {
    return fail("TRUST_NO_ATTESTATIONS", "no attestation from an allowlisted attestor inside the window", report);
  }
  if (report.sessions < policy.minSessions) {
    return fail("TRUST_TOO_FEW_SESSIONS", `only ${report.sessions} attested sessions, need ${policy.minSessions}`, report);
  }
  if (report.slashes > policy.maxSlashes) {
    return fail("TRUST_SLASHED", `${report.slashes} slashes, limit is ${policy.maxSlashes}`, report);
  }
  if (report.score < policy.minScore) {
    return fail("TRUST_SCORE_LOW", `score ${report.score} is under the floor ${policy.minScore}`, report);
  }
  return { ok: true, chamber: "trust", code: "OK", reason: `score ${report.score} over ${report.sessions} sessions`, report };
}

// ---------------------------------------------------------------- chamber 3

export interface Intent {
  action: string;
  resource: string;
  budgetUsdc: number;
  nonce: string;
  issuedAt: string;
}

export interface IntentPolicy {
  /** action -> allowed resource prefixes */
  scopes: Record<string, string[]>;
  maxBudgetUsdc: number;
  ttlMs: number;
  /** Mutable set of nonces already spent by this airlock. */
  spent: Set<string>;
}

export function checkIntent(intent: Partial<Intent>, policy: IntentPolicy, now: Date): Verdict {
  const fail = (code: string, reason: string): Verdict => ({ ok: false, chamber: "intent", code, reason });

  if (
    typeof intent.action !== "string" ||
    typeof intent.resource !== "string" ||
    typeof intent.budgetUsdc !== "number" ||
    typeof intent.nonce !== "string" ||
    typeof intent.issuedAt !== "string"
  ) {
    return fail("INTENT_MALFORMED", "intent is missing a required field");
  }
  if (!/^[0-9a-f]{16,64}$/.test(intent.nonce)) {
    return fail("INTENT_MALFORMED", "nonce must be 8 to 32 bytes of lowercase hex");
  }
  const prefixes = policy.scopes[intent.action];
  if (prefixes === undefined) {
    return fail("INTENT_ACTION", `action ${intent.action} is not in the allowlist`);
  }
  const resource = intent.resource;
  if (!prefixes.some((prefix) => resource === prefix || resource.startsWith(prefix))) {
    return fail("INTENT_SCOPE", `resource ${resource} is outside the scope of ${intent.action}`);
  }
  if (!Number.isFinite(intent.budgetUsdc) || intent.budgetUsdc <= 0) {
    return fail("INTENT_BUDGET", "budget must be a positive finite number");
  }
  if (intent.budgetUsdc > policy.maxBudgetUsdc) {
    return fail("INTENT_BUDGET", `budget ${intent.budgetUsdc} exceeds the cap ${policy.maxBudgetUsdc}`);
  }
  const issuedAt = Date.parse(intent.issuedAt);
  if (Number.isNaN(issuedAt)) {
    return fail("INTENT_MALFORMED", "issuedAt is not an ISO 8601 timestamp");
  }
  if (now.getTime() - issuedAt > policy.ttlMs) {
    return fail("INTENT_STALE", "intent is older than its time to live");
  }
  if (policy.spent.has(intent.nonce)) {
    return fail("INTENT_REPLAY", `nonce ${intent.nonce.slice(0, 12)} was already spent`);
  }
  policy.spent.add(intent.nonce);
  return { ok: true, chamber: "intent", code: "OK", reason: `action ${intent.action} declared inside scope` };
}

// ---------------------------------------------------------------- chamber 4

export interface SoulChallenge {
  nonce: string;
  issuedAt: string;
}

export interface SoulResponse {
  nonce: string;
  sessionPublicKeyHex: string;
  signature: string;
}

export interface SoulOptions {
  now: Date;
  ttlMs?: number;
  identityPublicKeyHex: string;
}

export function checkSoul(
  challenge: Partial<SoulChallenge>,
  response: Partial<SoulResponse>,
  options: SoulOptions,
): Verdict {
  const fail = (code: string, reason: string): Verdict => ({ ok: false, chamber: "soul", code, reason });
  const ttlMs = options.ttlMs ?? 60_000;

  if (
    typeof challenge.nonce !== "string" ||
    typeof challenge.issuedAt !== "string" ||
    typeof response.nonce !== "string" ||
    typeof response.sessionPublicKeyHex !== "string" ||
    typeof response.signature !== "string"
  ) {
    return fail("SOUL_MALFORMED", "challenge or response is missing a required field");
  }
  const issuedAt = Date.parse(challenge.issuedAt);
  if (Number.isNaN(issuedAt)) {
    return fail("SOUL_MALFORMED", "challenge issuedAt is not an ISO 8601 timestamp");
  }
  if (options.now.getTime() - issuedAt > ttlMs) {
    return fail("SOUL_STALE", "challenge expired before it was answered");
  }
  if (response.nonce !== challenge.nonce) {
    return fail("SOUL_NONCE", "response nonce does not match the outstanding challenge");
  }
  if (!HEX64.test(response.sessionPublicKeyHex)) {
    return fail("SOUL_MALFORMED", "session public key must be 32 bytes of lowercase hex");
  }
  if (response.sessionPublicKeyHex === options.identityPublicKeyHex) {
    return fail("SOUL_KEY_REUSE", "session key must not be the long lived identity key");
  }
  if (!verifyHex(options.identityPublicKeyHex, soulStatement(challenge.nonce, response.sessionPublicKeyHex), response.signature)) {
    return fail("SOUL_SIGNATURE", "identity key did not sign nonce and session key");
  }
  return { ok: true, chamber: "soul", code: "OK", reason: "live agent answered the nonce with a session key" };
}

// ---------------------------------------------------------------- chamber 5

export interface SessionClaims {
  sub: string;
  sid: string;
  aud: string;
  iat: number;
  exp: number;
}

export interface SessionOptions {
  secret: string;
  audience: string;
  now: Date;
  maxTtlSeconds?: number;
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function hmac(secret: string, data: string): string {
  return createHmac("sha256", secret).update(data).digest("base64url");
}

export function issueSessionToken(claims: SessionClaims, secret: string): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify(claims));
  const body = `${header}.${payload}`;
  return `${body}.${hmac(secret, body)}`;
}

export function checkSession(token: string, options: SessionOptions): Verdict & { claims?: SessionClaims } {
  const fail = (code: string, reason: string): Verdict => ({ ok: false, chamber: "session", code, reason });
  const maxTtl = options.maxTtlSeconds ?? 900;

  if (typeof token !== "string") return fail("SESSION_MALFORMED", "token is not a string");
  const parts = token.split(".");
  if (parts.length !== 3) return fail("SESSION_MALFORMED", "token must have three dot separated segments");
  const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];

  let header: { alg?: string; typ?: string };
  let claims: SessionClaims;
  try {
    header = JSON.parse(Buffer.from(rawHeader, "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(rawPayload, "base64url").toString("utf8"));
  } catch {
    return fail("SESSION_MALFORMED", "header or payload is not base64url encoded JSON");
  }
  if (header.alg !== "HS256") {
    return fail("SESSION_ALG", `algorithm ${String(header.alg)} is not accepted, only HS256`);
  }
  const expected = hmac(options.secret, `${rawHeader}.${rawPayload}`);
  const left = Buffer.from(expected);
  const right = Buffer.from(rawSignature);
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    return fail("SESSION_SIGNATURE", "signature does not match header and payload");
  }
  if (
    typeof claims.sub !== "string" ||
    typeof claims.sid !== "string" ||
    typeof claims.aud !== "string" ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number"
  ) {
    return fail("SESSION_MALFORMED", "claims are missing sub, sid, aud, iat or exp");
  }
  if (claims.aud !== options.audience) {
    return fail("SESSION_AUDIENCE", `token audience ${claims.aud} is not ${options.audience}`);
  }
  if (claims.exp <= claims.iat) {
    return fail("SESSION_TTL", "exp must be after iat");
  }
  if (claims.exp - claims.iat > maxTtl) {
    return fail("SESSION_TTL", `ttl ${claims.exp - claims.iat}s exceeds the ceiling ${maxTtl}s`);
  }
  if (claims.exp * 1000 <= options.now.getTime()) {
    return fail("SESSION_EXPIRED", "token is expired");
  }
  if (claims.iat * 1000 > options.now.getTime() + 60_000) {
    return fail("SESSION_TTL", "token was issued in the future");
  }
  return { ok: true, chamber: "session", code: "OK", reason: `session ${claims.sid} valid until ${claims.exp}`, claims };
}

// ---------------------------------------------------------------- airlock

export interface AdmitRequest {
  claim: IdentityClaim;
  attestations: Attestation[];
  intent: Intent;
  challenge: SoulChallenge;
  response: SoulResponse;
  sessionClaims: SessionClaims;
}

export interface StageRecord {
  chamber: Chamber;
  ok: boolean;
  code: string;
  reason: string;
}

export interface AdmitResult {
  admitted: boolean;
  refusedAt: Chamber | null;
  transcript: StageRecord[];
  token?: string;
  trust?: TrustReport;
}

export interface AirlockConfig {
  identity: { maxAgeMs?: number; maxSkewMs?: number };
  trust: TrustPolicy;
  intent: IntentPolicy;
  soul: { ttlMs?: number };
  session: { secret: string; audience: string; maxTtlSeconds?: number };
}

/**
 * Runs the five chambers in a fixed order and stops at the first refusal, so a
 * caller can never obtain a session token without passing identity, trust,
 * intent and the SOUL handshake first.
 */
export class Airlock {
  constructor(private readonly config: AirlockConfig) {}

  admit(request: AdmitRequest, now: Date): AdmitResult {
    const transcript: StageRecord[] = [];
    const stage = (verdict: Verdict): StageRecord => {
      const record: StageRecord = {
        chamber: verdict.chamber,
        ok: verdict.ok,
        code: verdict.code,
        reason: verdict.reason,
      };
      transcript.push(record);
      return record;
    };

    const identity = checkIdentity(request.claim, { now, ...this.config.identity });
    if (!stage(identity).ok) {
      return { admitted: false, refusedAt: "identity", transcript };
    }

    const trust = checkTrust(request.claim.agentId, request.attestations, this.config.trust, now);
    if (!stage(trust).ok) {
      return { admitted: false, refusedAt: "trust", transcript };
    }

    const intent = checkIntent(request.intent, this.config.intent, now);
    if (!stage(intent).ok) {
      return { admitted: false, refusedAt: "intent", transcript };
    }

    const soul = checkSoul(request.challenge, request.response, {
      now,
      identityPublicKeyHex: request.claim.publicKeyHex,
      ...this.config.soul,
    });
    if (!stage(soul).ok) {
      return { admitted: false, refusedAt: "soul", transcript };
    }

    const token = issueSessionToken(request.sessionClaims, this.config.session.secret);
    const session = checkSession(token, {
      secret: this.config.session.secret,
      audience: this.config.session.audience,
      now,
      ...(this.config.session.maxTtlSeconds === undefined
        ? {}
        : { maxTtlSeconds: this.config.session.maxTtlSeconds }),
    });
    if (!stage(session).ok) {
      return { admitted: false, refusedAt: "session", transcript };
    }

    const result: AdmitResult = { admitted: true, refusedAt: null, transcript, token };
    if (trust.report !== undefined) result.trust = trust.report;
    return result;
  }
}
