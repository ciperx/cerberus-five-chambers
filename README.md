# Cerberus five chambers

A deterministic reference implementation of the Cerberus airlock plus a fixture
driven `node:test` suite that drives the five chambers in order:

1. `identity` - an ed25519 signed claim binds agent id, chain and public key
2. `trust` - an allowlisted attestor set produces a score inside a time window
3. `intent` - declared action, resource scope, budget and nonce are acceptable
4. `soul` - the live agent answers a fresh nonce with a session key
5. `session` - a short lived HS256 token is issued and then verified

The suite never touches the network, never sleeps and never reads the wall
clock: `now` is injected into every chamber, and each fixture carries its own
timestamps. Signatures are real ed25519 signatures from `node:crypto`, minted
per test from an ephemeral key pair, so no private key is ever stored in the
repository.

## Run

```
npm ci
npm test
npm run typecheck
```

Node 20 or newer. Two dev dependencies (`tsx`, `typescript`), no runtime
dependency, no install script.

## What the suite covers

42 cases, at least one refusing case per chamber:

- identity: 7 cases. A signature from a foreign key, a statement naming another
  agent, a claim older than 15 minutes, an unknown chain, a malformed agent id
  and a missing signature are all refused. The canonical statement is
  `LAX-IDENTITY/1|agent=<agentId>|chain=<chain>`, so a signature cannot be moved
  to another agent or chain.
- trust: 7 cases. One vote per attestor, newest filing wins, only allowlisted
  attestors inside the window count, a floor on the score, a floor on attested
  sessions and a ceiling on slashes. A slash penalty of 25 points per slash is
  applied after the mean of the positive votes.
- intent: 8 cases. Unknown action, resource outside the action scope, budget
  above the cap, zero budget, replayed nonce and an intent past its time to live
  are refused. The nonce is spent inside the policy, so a second admission with
  the same nonce is a replay even when everything else is valid.
- soul: 6 cases. Wrong nonce, a signature over a different session key, reuse of
  the long lived identity key as the session key, a stale challenge and a
  missing signature are refused.
- session: 8 cases. A tampered payload fails the signature, an expired token is
  refused, a token for another audience is refused, an `alg: none` header is
  refused before any signature check, a ttl above the ceiling is refused and a
  rotated secret invalidates every token.
- airlock order: 6 cases. A clean request produces five passing stages and a
  token that verifies; a broken identity stops at stage one; a thin trust record
  stops at stage two; an unanswered nonce stops at stage four; a ttl above the
  ceiling stops at stage five; the second admission with the same nonce is
  refused at stage three.

The transcript length assertions are the point of the order tests: a caller can
never reach the session chamber, and therefore never receive a token, without
passing identity, trust, intent and the SOUL handshake first.

## Layout

```
src/airlock.ts        chambers, airlock, verdict codes
src/keys.ts           ed25519 helpers, raw public key hex
fixtures/*.json       one file per chamber plus the full airlock request
test/airlock.test.ts  the fixture driven suite
```

## Refusal codes

`IDENTITY_MALFORMED`, `IDENTITY_CHAIN`, `IDENTITY_STATEMENT`,
`IDENTITY_STALE`, `IDENTITY_SIGNATURE`, `TRUST_NO_ATTESTATIONS`,
`TRUST_TOO_FEW_SESSIONS`, `TRUST_SLASHED`, `TRUST_SCORE_LOW`,
`INTENT_MALFORMED`, `INTENT_ACTION`, `INTENT_SCOPE`, `INTENT_BUDGET`,
`INTENT_STALE`, `INTENT_REPLAY`, `SOUL_MALFORMED`, `SOUL_STALE`,
`SOUL_NONCE`, `SOUL_KEY_REUSE`, `SOUL_SIGNATURE`, `SESSION_MALFORMED`,
`SESSION_ALG`, `SESSION_SIGNATURE`, `SESSION_AUDIENCE`, `SESSION_TTL`,
`SESSION_EXPIRED`.

## Using it against the real airlock

`Airlock` takes one config object and one `AdmitRequest`, so the same tests run
against a different chamber implementation by swapping the imports: the fixtures
are data, the assertions are on codes, and every chamber function has the same
shape `(input, options) -> Verdict`. If Kognai's chamber functions use different
signatures, only `src/airlock.ts` needs adapting; `test/airlock.test.ts` and the
fixtures stay as they are.

## License

MIT.
