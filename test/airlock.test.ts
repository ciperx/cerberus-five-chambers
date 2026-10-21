/**
 * Fixture driven suite for the five Cerberus chambers.
 *
 * Every case comes from fixtures/*.json, every signature is a real ed25519
 * signature over the canonical statement, and the clock is always injected, so
 * the suite has no network, no sleep and no wall clock dependency.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  Airlock,
  checkIdentity,
  checkIntent,
  checkSession,
  checkSoul,
  checkTrust,
  identityStatement,
  issueSessionToken,
  soulStatement,
  type AdmitRequest,
} from "../src/airlock.js";
import { newKeyPair } from "../src/keys.js";

function fixture<T = any>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url), "utf8")) as T;
}

const iso = (ms: number): string => new Date(ms).toISOString();

// ---------------------------------------------------------------- chamber 1

const identityFixture = fixture("identity");

function identityClaim() {
  const statement = identityStatement(identityFixture.agentId, identityFixture.chain);
  const keys = newKeyPair();
  return {
    keys,
    claim: {
      agentId: identityFixture.agentId as string,
      chain: identityFixture.chain as string,
      publicKeyHex: keys.publicKeyHex,
      statement,
      issuedAt: identityFixture.issuedAt as string,
      signature: keys.sign(statement),
    },
  };
}

for (const testCase of identityFixture.cases) {
  test(testCase.name, () => {
    const now = new Date(identityFixture.now as string);
    const { keys, claim } = identityClaim();
    const target: Record<string, unknown> = { ...claim };

    switch (testCase.variant) {
      case "foreign_signature":
        target.signature = newKeyPair().sign(claim.statement);
        break;
      case "foreign_statement":
        target.statement = identityStatement("someone-else-99", claim.chain);
        break;
      case "stale":
        target.issuedAt = iso(now.getTime() - 16 * 60_000);
        break;
      case "unknown_chain":
        target.chain = "ethereum";
        target.statement = identityStatement(claim.agentId, "ethereum");
        break;
      case "bad_agent_id":
        target.agentId = "OZMA Ranger";
        target.statement = identityStatement("OZMA Ranger", claim.chain);
        break;
      case "missing_signature":
        delete target.signature;
        break;
      default:
        break;
    }

    const verdict = checkIdentity(target as never, { now });
    assert.equal(verdict.code, testCase.expect, verdict.reason);
    assert.equal(verdict.chamber, "identity");
    if (testCase.expect !== "OK") assert.equal(verdict.ok, false);
    // the presented key is still the signer of the good case
    assert.equal(claim.publicKeyHex, keys.publicKeyHex);
  });
}

// ---------------------------------------------------------------- chamber 2

const trustFixture = fixture("trust");

function trustCase(variant?: string) {
  const base = trustFixture.attestations as any[];
  const copy = base.map((entry) => ({ ...entry }));
  if (variant === "low_score") for (const entry of copy) entry.score = 40;
  if (variant === "few_sessions") for (const entry of copy) entry.kind = "review";
  if (variant === "slashed") {
    copy.push({
      attestor: "lax-node-1",
      subject: trustFixture.subject,
      kind: "slash",
      score: 0,
      issuedAt: "2026-10-20T12:00:00.000Z",
    });
    copy[2].kind = "session";
  }
  if (variant === "foreign_attestors") for (const entry of copy) entry.attestor = "random-stranger";
  if (variant === "stale_attestations") {
    for (const entry of copy) entry.issuedAt = "2026-01-01T00:00:00.000Z";
  }
  return copy;
}

for (const testCase of trustFixture.cases) {
  test(testCase.name, () => {
    const now = new Date(trustFixture.now as string);
    const verdict = checkTrust(
      trustFixture.subject,
      trustCase(testCase.variant),
      trustFixture.policy,
      now,
    );
    assert.equal(verdict.code, testCase.expect, verdict.reason);
    assert.equal(verdict.chamber, "trust");
    assert.ok(verdict.report !== undefined);
  });
}

test("B7 one vote per attestor counts the newest filing", () => {
  const now = new Date(trustFixture.now as string);
  const attestations = trustCase().concat([
    {
      attestor: "lax-node-1",
      subject: trustFixture.subject,
      kind: "slash",
      score: 0,
      issuedAt: "2026-10-21T06:00:00.000Z",
    },
    {
      attestor: "kognai-ceo",
      subject: trustFixture.subject,
      kind: "session",
      score: 85,
      issuedAt: "2026-10-21T07:00:00.000Z",
    },
  ]);
  const verdict = checkTrust(trustFixture.subject, attestations, trustFixture.policy, now);
  assert.equal(verdict.report?.slashes, 1);
  assert.equal(verdict.code, "TRUST_SLASHED");
});

// ---------------------------------------------------------------- chamber 3

const intentFixture = fixture("intent");

function intentPolicy() {
  return { ...intentFixture.policy, spent: new Set<string>() };
}

function intentCase(variant?: string) {
  const base = { ...intentFixture.intent } as Record<string, unknown>;
  const now = new Date(intentFixture.now as string);
  if (variant === "unknown_action") base.action = "transfer.funds";
  if (variant === "out_of_scope") base.resource = "https://lax.kognai.ai/registry/agents";
  if (variant === "over_budget") base.budgetUsdc = 51;
  if (variant === "zero_budget") base.budgetUsdc = 0;
  if (variant === "stale") base.issuedAt = iso(now.getTime() - 10 * 60_000);
  return base as never;
}

for (const testCase of intentFixture.cases) {
  test(testCase.name, () => {
    const now = new Date(intentFixture.now as string);
    const policy = intentPolicy();
    if (testCase.variant === "replay") {
      assert.equal(checkIntent(intentCase(), policy, now).code, "OK");
    }
    const verdict = checkIntent(intentCase(testCase.variant), policy, now);
    assert.equal(verdict.code, testCase.expect, verdict.reason);
    assert.equal(verdict.chamber, "intent");
  });
}

test("C8 a spent nonce stays spent for the life of the policy", () => {
  const now = new Date(intentFixture.now as string);
  const policy = intentPolicy();
  const intent = intentCase();
  assert.equal(checkIntent(intent, policy, now).code, "OK");
  assert.equal(policy.spent.size, 1);
  assert.equal(checkIntent(intent, policy, now).code, "INTENT_REPLAY");
});

// ---------------------------------------------------------------- chamber 4

const soulFixture = fixture("soul");

function soulPair() {
  const identityKeys = newKeyPair();
  const sessionKeys = newKeyPair();
  const challenge = {
    nonce: soulFixture.challenge.nonce as string,
    issuedAt: soulFixture.challenge.issuedAt as string,
  };
  const response = {
    nonce: challenge.nonce,
    sessionPublicKeyHex: sessionKeys.publicKeyHex,
    signature: identityKeys.sign(soulStatement(challenge.nonce, sessionKeys.publicKeyHex)),
  };
  return { identityKeys, sessionKeys, challenge, response };
}

for (const testCase of soulFixture.cases) {
  test(testCase.name, () => {
    const now = new Date(soulFixture.now as string);
    const { identityKeys, sessionKeys, challenge, response } = soulPair();
    const target: Record<string, unknown> = { ...response };
    const challengeTarget: Record<string, unknown> = { ...challenge };

    switch (testCase.variant) {
      case "wrong_nonce":
        target.nonce = "0000000000000000";
        break;
      case "wrong_signature": {
        const other = newKeyPair();
        target.signature = identityKeys.sign(soulStatement(challenge.nonce, other.publicKeyHex));
        break;
      }
      case "key_reuse":
        target.sessionPublicKeyHex = identityKeys.publicKeyHex;
        target.signature = identityKeys.sign(soulStatement(challenge.nonce, identityKeys.publicKeyHex));
        break;
      case "stale":
        challengeTarget.issuedAt = iso(now.getTime() - 120_000);
        break;
      case "missing_signature":
        delete target.signature;
        break;
      default:
        break;
    }

    const verdict = checkSoul(challengeTarget as never, target as never, {
      now,
      ttlMs: soulFixture.ttlMs,
      identityPublicKeyHex: identityKeys.publicKeyHex,
    });
    assert.equal(verdict.code, testCase.expect, verdict.reason);
    assert.equal(verdict.chamber, "soul");
    assert.equal(sessionKeys.publicKeyHex.length, 64);
  });
}

// ---------------------------------------------------------------- chamber 5

const sessionFixture = fixture("session");

function sessionClaims(overrides: Record<string, unknown> = {}) {
  const now = new Date(sessionFixture.now as string).getTime();
  const iat = Math.floor(now / 1000) + sessionFixture.claims.iatOffsetSeconds;
  return {
    sub: sessionFixture.claims.sub as string,
    sid: sessionFixture.claims.sid as string,
    aud: sessionFixture.claims.aud as string,
    iat,
    exp: iat + (sessionFixture.claims.ttlSeconds as number),
    ...overrides,
  } as never;
}

function sessionOptions() {
  return {
    secret: sessionFixture.secret as string,
    audience: sessionFixture.audience as string,
    now: new Date(sessionFixture.now as string),
    maxTtlSeconds: sessionFixture.maxTtlSeconds as number,
  };
}

for (const testCase of sessionFixture.cases) {
  test(testCase.name, () => {
    const secret = sessionFixture.secret as string;
    let token = issueSessionToken(sessionClaims(), secret);

    switch (testCase.variant) {
      case "tampered": {
        const [header, payload, signature] = token.split(".") as [string, string, string];
        const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
        claims.sid = "sess-hijacked";
        token = `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${signature}`;
        break;
      }
      case "expired": {
        const now = new Date(sessionFixture.now as string).getTime();
        const iat = Math.floor(now / 1000) - 3600;
        token = issueSessionToken(sessionClaims({ iat, exp: iat + 300 }), secret);
        break;
      }
      case "wrong_audience":
        token = issueSessionToken(sessionClaims({ aud: "another-service" }), secret);
        break;
      case "alg_none": {
        const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
        const payload = Buffer.from(JSON.stringify(sessionClaims())).toString("base64url");
        token = `${header}.${payload}.`;
        break;
      }
      case "long_ttl": {
        const claims = sessionClaims() as { iat: number };
        token = issueSessionToken(sessionClaims({ exp: claims.iat + 3600 }), secret);
        break;
      }
      case "malformed":
        token = "not-a-token";
        break;
      default:
        break;
    }

    const verdict = checkSession(token, sessionOptions());
    assert.equal(verdict.code, testCase.expect, verdict.reason);
    assert.equal(verdict.chamber, "session");
  });
}

test("E8 a token is not valid under a different secret", () => {
  const token = issueSessionToken(sessionClaims(), sessionFixture.secret as string);
  const verdict = checkSession(token, { ...sessionOptions(), secret: "rotated-secret" });
  assert.equal(verdict.code, "SESSION_SIGNATURE");
});

// ---------------------------------------------------------------- airlock

const airlockFixture = fixture("airlock");

function airlockConfig() {
  return {
    identity: {},
    trust: airlockFixture.trust,
    intent: {
      ...airlockFixture.intent,
      scopes: intentFixture.policy.scopes,
      ttlMs: intentFixture.policy.ttlMs,
      maxBudgetUsdc: intentFixture.policy.maxBudgetUsdc,
      spent: new Set<string>(),
    },
    soul: {},
    session: {
      secret: airlockFixture.secret as string,
      audience: airlockFixture.audience as string,
      maxTtlSeconds: 900,
    },
  };
}

function admitRequest(): AdmitRequest {
  const now = new Date(airlockFixture.now as string).getTime();
  const statement = identityStatement(airlockFixture.agentId as string, "base");
  const identityKeys = newKeyPair();
  const sessionKeys = newKeyPair();
  const nonce = "5b1f9d3c7a2e6408";
  const iat = Math.floor(now / 1000) + airlockFixture.session.iatOffsetSeconds;

  return {
    claim: {
      agentId: airlockFixture.agentId as string,
      chain: "base",
      publicKeyHex: identityKeys.publicKeyHex,
      statement,
      issuedAt: iso(now - 60_000),
      signature: identityKeys.sign(statement),
    },
    attestations: [
      { attestor: "lax-node-1", subject: airlockFixture.agentId, kind: "session", score: 90, issuedAt: iso(now - 3_600_000) },
      { attestor: "lax-node-2", subject: airlockFixture.agentId, kind: "session", score: 88, issuedAt: iso(now - 7_200_000) },
      { attestor: "kognai-ceo", subject: airlockFixture.agentId, kind: "review", score: 92, issuedAt: iso(now - 86_400_000) },
    ],
    intent: {
      action: airlockFixture.intent.action as string,
      resource: airlockFixture.intent.resource as string,
      budgetUsdc: airlockFixture.intent.budgetUsdc as number,
      nonce: airlockFixture.intent.nonce as string,
      issuedAt: iso(now + airlockFixture.intent.issuedAtOffsetSeconds * 1000),
    },
    challenge: { nonce, issuedAt: iso(now - 1_000) },
    response: {
      nonce,
      sessionPublicKeyHex: sessionKeys.publicKeyHex,
      signature: identityKeys.sign(soulStatement(nonce, sessionKeys.publicKeyHex)),
    },
    sessionClaims: {
      sub: airlockFixture.session.sub as string,
      sid: airlockFixture.session.sid as string,
      aud: airlockFixture.audience as string,
      iat,
      exp: iat + airlockFixture.session.ttlSeconds,
    },
  };
}

test("F1 a clean request passes all five chambers and gets a token", () => {
  const now = new Date(airlockFixture.now as string);
  const result = new Airlock(airlockConfig()).admit(admitRequest(), now);

  assert.equal(result.admitted, true);
  assert.equal(result.refusedAt, null);
  assert.deepEqual(
    result.transcript.map((stage) => stage.chamber),
    ["identity", "trust", "intent", "soul", "session"],
  );
  assert.ok(result.transcript.every((stage) => stage.ok));
  assert.equal(typeof result.token, "string");
  assert.equal(
    checkSession(result.token as string, {
      secret: airlockFixture.secret as string,
      audience: airlockFixture.audience as string,
      now,
    }).code,
    "OK",
  );
  assert.equal(result.trust?.sessions, 2);
});

test("F2 a bad identity stops the airlock before trust runs", () => {
  const now = new Date(airlockFixture.now as string);
  const request = admitRequest();
  request.claim.signature = newKeyPair().sign(request.claim.statement);
  const result = new Airlock(airlockConfig()).admit(request, now);

  assert.equal(result.admitted, false);
  assert.equal(result.refusedAt, "identity");
  assert.equal(result.transcript.length, 1);
  assert.equal(result.transcript[0]?.code, "IDENTITY_SIGNATURE");
  assert.equal(result.token, undefined);
});

test("F3 a thin trust record stops the airlock at chamber two", () => {
  const now = new Date(airlockFixture.now as string);
  const request = admitRequest();
  request.attestations = request.attestations.slice(0, 1);
  const result = new Airlock(airlockConfig()).admit(request, now);

  assert.equal(result.refusedAt, "trust");
  assert.equal(result.transcript.length, 2);
  assert.equal(result.transcript[1]?.code, "TRUST_TOO_FEW_SESSIONS");
});

test("F4 an unanswered SOUL nonce stops the airlock at chamber four", () => {
  const now = new Date(airlockFixture.now as string);
  const request = admitRequest();
  request.response = { ...request.response, nonce: "ffffffffffffffff" };
  const result = new Airlock(airlockConfig()).admit(request, now);

  assert.equal(result.refusedAt, "soul");
  assert.equal(result.transcript.length, 4);
  assert.equal(result.transcript[3]?.code, "SOUL_NONCE");
});

test("F5 a session token beyond the ttl ceiling is refused at chamber five", () => {
  const now = new Date(airlockFixture.now as string);
  const request = admitRequest();
  request.sessionClaims = { ...request.sessionClaims, exp: request.sessionClaims.iat + 3600 };
  const result = new Airlock(airlockConfig()).admit(request, now);

  assert.equal(result.refusedAt, "session");
  assert.equal(result.transcript.length, 5);
  assert.equal(result.transcript[4]?.code, "SESSION_TTL");
});

test("F6 the airlock spends the nonce so the same request cannot be replayed", () => {
  const now = new Date(airlockFixture.now as string);
  const airlock = new Airlock(airlockConfig());
  assert.equal(airlock.admit(admitRequest(), now).admitted, true);
  const replay = airlock.admit(admitRequest(), now);
  assert.equal(replay.refusedAt, "intent");
  assert.equal(replay.transcript.at(-1)?.code, "INTENT_REPLAY");
});
