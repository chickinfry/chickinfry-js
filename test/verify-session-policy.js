import assert from "node:assert/strict";
import { test } from "node:test";
import { sessionPolicy, sessionExpiry, sessionState, cleanupCandidates, cookieMaxAge } from "../dist/auth/policy.js";
import { authOperations, invokeAuth, browserRequest } from "../dist/auth/index.js";

const hour = 3600000, day = 24 * hour;
const now = Date.parse("2026-01-31T00:00:00Z");
const at = value => new Date(value).toISOString();
const session = {
  createdAt: at(now - 29 * day), firstLoginAt: null, lastRenewedAt: null,
  expiresAt: at(now + hour), revokedAt: null, transport: "native",
};
const latest = {createdAt: at(now - hour), expiresAt: at(now + day)};

test("canonical browser auth is token-free and removed names reject without fallback", async () => {
  const user = {id: "user", email: "user@example.test", sessionId: "session", expiresAt: at(now + hour)};
  const result = {...user, credential: "C".repeat(43), cookieMaxAge: 3600};
  const calls = [];
  const auth = {
    async signup(...args) { calls.push(["signup", ...args]); return result; },
    async signin(...args) { calls.push(["signin", ...args]); return result; },
    async signinIdentity(...args) { calls.push(["identity", ...args]); return result; },
    async session(...args) { calls.push(["session", ...args]); return user; },
    async logout(...args) { calls.push(["logout", ...args]); },
  };
  const request = new Request("https://api.example.test/auth.session", {method: "POST"});
  const input = {email: user.email, password: "correct horse battery staple", provider: "company", credential: "proof"};
  const expected = {id: user.id, email: user.email, session_id: user.sessionId, expires_at: user.expiresAt};
  for (const name of ["signup", "signin", "identity", "session", "logout"]) {
    const context = {credential: "P".repeat(43), cookieName: "__Host-chik_session_test", headers: new Headers()};
    const wire = await invokeAuth(auth, "auth." + name, input, request, context);
    assert.deepEqual(wire, name === "logout" ? {status: "ok"} : expected);
    assert.ok(calls.at(-1).includes("browser"));
    if (["signup", "signin", "identity"].includes(name)) {
      assert.match(context.headers.get("set-cookie"), /; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600$/);
      assert.equal(calls.at(-1).at(-1), context.credential);
    } else if (name === "logout") assert.match(context.headers.get("set-cookie"), /Max-Age=0$/);
    else assert.equal(context.headers.has("set-cookie"), false);
    const count = calls.length;
    for (const browser of [undefined, {...context, headers: new Headers()}]) {
      await assert.rejects(invokeAuth(auth, "auth.browser_" + name, input, request, browser), {
        code: "auth_operation_removed", status: 400, message: `auth.browser_${name} was removed; use auth.${name}.`,
      });
      assert.equal(browser?.headers.has("set-cookie") ?? false, false);
    }
    assert.equal(calls.length, count);
  }
  assert.equal(authOperations.some(operation => operation.startsWith("auth.browser_")), false);
  await assert.rejects(invokeAuth(auth, "auth.refresh", {refresh_token: "R".repeat(43)}, request,
    {credential: "", cookieName: "test", headers: new Headers()}), {code: "invalid_input", status: 400});
});

test("native auth.session exposes token-free session expiry", async () => {
  const user = {id: "user", email: "user@example.test", sessionId: "session", expiresAt: at(now + hour)};
  const request = new Request("https://api.example.test/auth.session", {headers: {authorization: "Bearer " + "A".repeat(43)}});
  assert.deepEqual(await invokeAuth({async session() { return user; }}, "auth.session", {}, request),
    {id: user.id, email: user.email, session_id: user.sessionId, expires_at: user.expiresAt});
});

test("browser credential mixing rejects before authentication but unrelated cookies preserve bearer", () => {
  const project = "01234567-89ab-4cde-8fab-0123456789ab";
  const cookie = `__Host-chik_session_${project}`;
  const request = headers => new Request("https://api.example.test/auth.session", {method: "POST", headers});
  const origins = new Set(["https://web.example.test"]);
  for (const authorization of ["Bearer " + "A".repeat(43), "", "invalid"]) {
    for (const credential of ["B".repeat(43), "", "invalid"]) {
      for (const marker of [undefined, "1"]) {
        const headers = {authorization, cookie: `${cookie}=${credential}`};
        if (marker) headers["x-chik-browser"] = marker;
        assert.throws(() => browserRequest(request(headers), project, origins), {code: "invalid_input", status: 400});
      }
    }
    assert.throws(() => browserRequest(request({authorization, "x-chik-browser": "1"}), project, origins),
      {code: "invalid_input", status: 400});
    const unrelated = request({authorization, cookie: "analytics=value"});
    assert.equal(browserRequest(unrelated, project, origins), undefined);
    assert.equal(unrelated.headers.get("authorization"), authorization);
    assert.equal(unrelated.headers.get("cookie"), "analytics=value");
  }
});

test("other projects' session cookies preserve bearer while this project's cookie rejects mixing", () => {
  const project = "01234567-89ab-4cde-8fab-0123456789ab";
  const otherProject = "11234567-89ab-4cde-8fab-0123456789ab";
  const origins = new Set();
  const request = headers => new Request("https://api.example.test/auth.session", {method: "POST", headers});
  const cookie = projectId => `__Host-chik_session_${projectId}=${"B".repeat(43)}`;
  const authorization = "Bearer " + "A".repeat(43);
  const unrelated = request({authorization, cookie: cookie(otherProject)});
  assert.equal(browserRequest(unrelated, project, origins), undefined);
  assert.throws(() => browserRequest(request({authorization, cookie: cookie(project)}), project, origins),
    {code: "invalid_input", status: 400});
});

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
