import assert from "node:assert/strict";
import { test } from "node:test";
import { sessionPolicy, sessionExpiry, sessionState, cleanupCandidates, cookieMaxAge } from "../dist/auth/policy.js";

const hour = 3600000, day = 24 * hour;
const now = Date.parse("2026-01-31T00:00:00Z");
const at = value => new Date(value).toISOString();
const session = {
  createdAt: at(now - 29 * day), firstLoginAt: null, lastRenewedAt: null,
  expiresAt: at(now + hour), revokedAt: null, transport: "native",
};
const latest = {createdAt: at(now - hour), expiresAt: at(now + day)};

test("session policy rejects invalid values instead of silently using defaults", () => {
  assert.deepEqual(sessionPolicy(), {idleTimeoutSeconds: 2592000, absoluteLifetimeSeconds: 0});
  for (const idleTimeoutSeconds of [0, 3599, 31536001, -1, 3600.5, "3600", null, NaN, Infinity]) {
    assert.throws(() => sessionPolicy({idleTimeoutSeconds}), /auth.session.idle_timeout_seconds/);
  }
  for (const absoluteLifetimeSeconds of [1, 3599, 31536001, -1, "off", null, NaN]) {
    assert.throws(() => sessionPolicy({absoluteLifetimeSeconds}), /auth.session.absolute_lifetime_seconds/);
  }
  for (const value of [null, [], true, {idle_timeout_seconds: 3600}, {unknown: 1}]) {
    assert.throws(() => sessionPolicy(value), /auth.session/);
  }
  assert.equal(sessionPolicy({idleTimeoutSeconds: 3600, absoluteLifetimeSeconds: 3600}).idleTimeoutSeconds, 3600);
  assert.equal(sessionPolicy({idleTimeoutSeconds: 31536000, absoluteLifetimeSeconds: 31536000}).absoluteLifetimeSeconds, 31536000);
});

test("legacy Q1 uses latest normal issuance, preserves first login and stored expiry", () => {
  const policy = sessionPolicy({idleTimeoutSeconds: 3600});
  assert.equal(sessionState(session, latest, policy, now - 1).expired, false);
  assert.equal(sessionState(session, latest, policy, now).expired, true);
  assert.equal(sessionState(session, latest, policy, now - 1).firstLoginAt, Date.parse(session.createdAt));
  assert.equal(sessionState(session, {...latest, expiresAt: at(now - 2)}, policy, now - 1).expired, true);
  assert.equal(sessionState(session, undefined, policy, now - 1).expired, true);
});

test("pure session decisions produce the same output with identical inputs and no ambient clock", () => {
  const policy = sessionPolicy({absoluteLifetimeSeconds: 60 * 86400});
  const input = Object.freeze({...session, firstLoginAt: session.createdAt, lastRenewedAt: latest.createdAt});
  const credential = Object.freeze({...latest});
  const original = Date.now;
  try {
    Date.now = () => { throw new Error("Ambient clock was read."); };
    assert.deepEqual(sessionState(input, credential, policy, now), sessionState(input, credential, policy, now));
    assert.deepEqual(cleanupCandidates(policy, now), cleanupCandidates(policy, now));
    assert.equal(sessionExpiry(policy, now - 59 * day, now), now + day);
    assert.equal(cookieMaxAge(policy, now - 59 * day, now), 86400);
    assert.equal(cookieMaxAge(sessionPolicy(), now, now), 34560000);
  } finally { Date.now = original; }
  assert.deepEqual(input, {...session, firstLoginAt: session.createdAt, lastRenewedAt: latest.createdAt});
});
