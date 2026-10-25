import assert from "node:assert/strict";
import net from "node:net";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { Auth, AuthError } from "../dist/auth/runtime.js";
import { hashToken } from "../dist/auth/crypto.js";
import { createDatabase } from "../dist/auth/private/database.js";
import { createPostgresPort, cleanupBudgetMillis } from "../dist/postgres.js";

const url = process.env.CHIK_TEST_DATABASE_URL;
const port = createPostgresPort(url), other = createPostgresPort(url);
const db = createDatabase(port);
const clock = Date.parse("2029-01-01T00:00:00Z"), now = () => clock;
const expired = "2020-01-01T00:00:00.000Z";
const password = "correct horse battery staple";
const rejects = (work, code) => assert.rejects(work, error => error instanceof AuthError && error.code === code);
const startingAt = (runtime, id) => {
  runtime.cleanupStart = () => id;
  return runtime;
};
const observe = (base, before, after) => ({
  async query(sql, args) {
    await before?.(sql, args);
    const result = await base.query(sql, args);
    await after?.(sql, args, result);
    return result;
  },
  transaction(work) { return base.transaction(tx => work(observe(tx, before, after))); },
});
const tasks = [];
let closes = 0;
const context = (before, after) => ({
  waitUntil(work) { tasks.push(work); },
  createPort(signal) {
    const base = createPostgresPort(url, signal);
    return {...observe(base, before, after), async close() { closes++; await base.close(); }};
  },
});
const drain = async () => { await Promise.all(tasks.splice(0)); };
const logs = [], originalLog = console.error;
console.error = (...args) => logs.push(args);
// TCP proxy that delays only the first data chunk in each direction: slows connection setup, leaves later queries untouched.
const delayProxy = perDirectionMillis => new Promise(resolve => {
  const target = new URL(url);
  const sockets = new Set();
  const server = net.createServer(client => {
    const upstream = net.connect({host: target.hostname, port: Number(target.port)});
    for (const [from, to] of [[client, upstream], [upstream, client]]) {
      let opened = false, queued = [], timer;
      const flush = () => { opened = true; for (const chunk of queued.splice(0)) if (!to.destroyed) to.write(chunk); };
      from.on("data", chunk => {
        if (opened) { if (!to.destroyed) to.write(chunk); return; }
        queued.push(chunk);
        if (!timer) timer = setTimeout(flush, perDirectionMillis);
      });
      from.on("close", () => to.destroy());
    }
    for (const socket of [client, upstream]) { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); }
  });
  server.on("error", () => {});
  server.listen(0, "127.0.0.1", () => {
    const proxied = new URL(url);
    proxied.port = String(server.address().port);
    resolve({url: proxied.toString(), async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise(done => server.close(() => done()));
    }});
  });
});
const through = target => ({waitUntil(work) { tasks.push(work); }, createPort(signal) { return createPostgresPort(target, signal); }});

try {
  const auth = new Auth(port, [], now);
  const email = `cleanup-${randomUUID()}@example.test`;
  const owner = await auth.signup(email, password);
  const doomed = await auth.signin(email, password);
  await db.appAuthSessions.update({id: doomed.sessionId}, {expiresAt: expired});
  const doomedRefresh = (await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.eq(doomed.sessionId)}))[0];
  await db.appAuthRefreshTokens.update({id: doomedRefresh.id}, {expiresAt: expired});
  await rejects(auth.session(doomed.accessToken), "invalid_token");
  await rejects(auth.refresh(doomed.refreshToken), "session_revoked");
  assert.ok(await db.appAuthRefreshTokens.findById({id: doomedRefresh.id}));
  await db.appAuthRateLimits.insert({action: "signin", keyHash: hashToken("expired-limit@example.test"), attemptCount: 10, expiresAt: expired});
  await rejects(auth.signin("expired-limit@example.test", password), "invalid_credentials");
  assert.equal((await db.appAuthRateLimits.findById({action: "signin", keyHash: hashToken("expired-limit@example.test")})).attemptCount, 1);

  for (let i = 0; i < 32; i++) {
    const session = await db.appAuthSessions.insert({userId: owner.userId, tokenHash: hashToken(randomUUID()), userSessionVersion: 0, expiresAt: expired});
    await db.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(randomUUID()), expiresAt: expired});
    await db.appAuthRateLimits.insert({action: "cleanup", keyHash: hashToken(randomUUID()), attemptCount: 1, expiresAt: expired});
    await db.appAuthInvites.insert({email: `expired-${i}@example.test`, codeHash: hashToken(randomUUID()), issuedBy: owner.userId, expiresAt: expired});
  }
  const started = Promise.withResolvers(), release = Promise.withResolvers();
  let rounds = 0, deleted = 0;
  const delayed = context(async sql => {
    started.resolve();
    await release.promise;
    rounds++;
    await delay(100);
  }, async (sql, args, rows) => { if (sql.startsWith("delete")) deleted += rows.length; });
  const requestPort = createPostgresPort(url);
  const begin = performance.now();
  const tokens = await new Auth(requestPort, [], now, {}, {}, delayed).signin(email, password);
  const responseMillis = performance.now() - begin;
  await started.promise;
  assert.equal(rounds, 0, "authentication response must complete even while cleanup is blocked");
  await requestPort.close();
  const cleanupStart = performance.now();
  release.resolve();
  await drain();
  const cleanupMillis = performance.now() - cleanupStart;
  assert.equal(closes, 1);
  assert.ok(rounds <= 23 && deleted <= 8, "one cleanup pass must not process the entire backlog");
  assert.ok(cleanupMillis >= 1000 && responseMillis < cleanupMillis);
  assert.equal((await auth.session(tokens.accessToken)).id, owner.userId);
  assert.ok((await db.appAuthInvites.findMany({where: c => c.expiresAt.eq(expired)})).length > 0);
  console.log(JSON.stringify({risk: "backlog-delay", responseMillis: +responseMillis.toFixed(1), cleanupMillis: +cleanupMillis.toFixed(1), ormQueries: rounds, deleted}));

  // Remove the earlier artificial backlog so separate retention and race checks are not obscured by its candidate ordering.
  for (const row of await db.appAuthRefreshTokens.findMany({where: c => c.expiresAt.eq(expired)})) await db.appAuthRefreshTokens.delete({id: row.id});
  for (const row of await db.appAuthSessions.findMany({where: c => c.expiresAt.eq(expired)})) await db.appAuthSessions.delete({id: row.id});
  for (const row of await db.appAuthRateLimits.findMany({where: c => c.expiresAt.eq(expired)})) await db.appAuthRateLimits.delete({action: row.action, keyHash: row.keyHash});
  for (const row of await db.appAuthInvites.findMany({where: c => c.expiresAt.eq(expired)})) await db.appAuthInvites.delete({id: row.id});

  // An expired access token paired with a live refresh token is preserved regardless of parent lock acquisition order.
  for (const refreshFirst of [true, false]) {
    const live = await auth.signin(email, password);
    const cutoff = new Date(clock - 1).toISOString();
    await db.appAuthSessions.update({id: live.sessionId}, {expiresAt: cutoff});
    // Keep this legacy family eligible while testing both parent lock acquisition orders.
    await db.appAuthSessions.update({id: live.sessionId}, {expiresAt: "2010-01-01T00:00:00.000Z", firstLoginAt: null, lastRenewedAt: null});
    const locked = Promise.withResolvers(), attempted = Promise.withResolvers();
    const winner = observe(port, undefined, async (sql, args, rows) => {
      if (sql.startsWith('update "public"."app_auth_sessions"') && rows[0]?.id === live.sessionId) {
        locked.resolve();
        await attempted.promise;
      }
    });
    const loser = observe(other, async (sql, args) => {
      if (sql.startsWith('update "public"."app_auth_sessions"') && args.includes(live.sessionId)) attempted.resolve();
    });
    const cleanup = (base) => ({waitUntil(work) { tasks.push(work); }, createPort() {
      return {...base, async close() { closes++; }};
    }});
    let refreshed;
    if (refreshFirst) {
      const refreshing = new Auth(winner, [], now).refresh(live.refreshToken);
      await locked.promise;
      await startingAt(new Auth(other, [], now, {}, {}, cleanup(loser)), live.sessionId).signin(email, password);
      refreshed = await refreshing;
    } else {
      await startingAt(new Auth(other, [], now, {}, {}, cleanup(winner)), live.sessionId).signup(`race-${randomUUID()}@example.test`, password);
      await locked.promise;
      refreshed = await new Auth(loser, [], now).refresh(live.refreshToken);
    }
    await drain();
    await new Auth(port, [], now, {}, {}, context()).signup(`retention-${randomUUID()}@example.test`, password);
    await drain();
    assert.equal((await auth.session(refreshed.accessToken)).sessionId, live.sessionId);
    const children = await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.eq(live.sessionId)});
    assert.equal(children.length, 2);
    assert.equal(children.filter(row => row.consumedAt !== null).length, 1);
    await rejects(auth.refresh(live.refreshToken), "session_revoked");
    await rejects(auth.session(refreshed.accessToken), "invalid_token");
  }
  assert.deepEqual(logs, []);

  const gate = Promise.withResolvers();
  const detached = context(() => gate.promise);
  const provider = {id: "cleanup", async verify() { return {subject: "employee", verifiedEmail: `identity-${randomUUID()}@example.test`}; }};
  const flow = new Auth(port, [provider], now, {}, {}, detached);
  const signup = await flow.signup(`flow-${randomUUID()}@example.test`, password);
  const identity = await flow.signinIdentity(provider.id, "fixture");
  const refreshed = await flow.refresh(signup.refreshToken);
  const hooks = {async inviteManaging() {}};
  const invites = new Auth(port, [], now, hooks, {signup: "invite-only", projectId: randomUUID()}, detached);
  const issued = await invites.inviteIssue(owner.accessToken, randomUUID(), "flow-invite@example.test");
  assert.ok((await invites.inviteList(owner.accessToken, "")).items.some(row => row.id === issued.id));
  assert.equal((await invites.inviteRevoke(owner.accessToken, issued.id)).status, "revoked");
  assert.equal((await auth.session(identity.accessToken)).id, identity.userId);
  assert.equal((await auth.session(refreshed.accessToken)).sessionId, signup.sessionId);
  const scheduled = tasks.length;
  await rejects(invites.signup("missing-invite@example.test", password), "invite_required");
  await rejects(flow.refresh("x".repeat(43)), "invalid_token");
  assert.equal(tasks.length, scheduled);
  gate.resolve();
  await drain();

  // A rejected signup creates no port, and factory or close failures never change the committed result.
  for (const failure of ["schedule", "create", "close"]) {
    let created = 0;
    const failing = {
      waitUntil(work) { if (failure === "schedule") throw new Error("private schedule detail"); tasks.push(work); },
      createPort(signal) {
        created++;
        if (failure === "create") throw new Error("private factory detail");
        const base = createPostgresPort(url, signal);
        return {...base, async close() { await base.close(); throw new Error("private close detail"); }};
      },
    };
    const result = await new Auth(port, [], now, {}, {}, failing).signup(`failure-${failure}-${randomUUID()}@example.test`, password);
    await drain();
    assert.equal(created, failure === "schedule" ? 0 : 1);
    assert.equal((await auth.session(result.accessToken)).id, result.userId);
  }

  // Verify that aborting a real DB lock wait leaves no uncommitted deletion behind.
  const blocked = await db.appAuthSessions.insert({userId: owner.userId, tokenHash: hashToken(randomUUID()), userSessionVersion: 0, expiresAt: "2000-01-01T00:00:00.000Z"});
  const holding = Promise.withResolvers(), unlock = Promise.withResolvers();
  const lock = other.transaction(async tx => {
    await createDatabase(tx).appAuthSessions.update({id: blocked.id}, {expiresAt: blocked.expiresAt});
    holding.resolve();
    await unlock.promise;
  });
  await holding.promise;
  let cleanupSignal;
  const bounded = context();
  const budget = {...bounded, createPort(signal) { cleanupSignal = signal; return bounded.createPort(signal); }};
  const deadlineStart = performance.now();
  const unaffected = await startingAt(new Auth(port, [], now, {}, {}, budget), blocked.id).signup(`deadline-${randomUUID()}@example.test`, password);
  try {
    await drain();
    const deadlineMillis = performance.now() - deadlineStart;
    assert.ok(cleanupSignal.aborted);
    assert.ok(deadlineMillis < 6500);
    assert.ok(await db.appAuthSessions.findById({id: blocked.id}));
    assert.equal((await auth.session(unaffected.accessToken)).id, unaffected.userId);
    console.log(JSON.stringify({risk: "locked-cleanup-deadline", deadlineMillis: +deadlineMillis.toFixed(1)}));
  } finally { unlock.resolve(); await lock; }

  // Connection setup beyond the old 1s cap still completes cleanup when it fits the cleanup budget; longer delays are still recorded as failures.
  const expiredPair = async () => {
    const session = await db.appAuthSessions.insert({userId: owner.userId, tokenHash: hashToken(randomUUID()), userSessionVersion: 0, expiresAt: "2002-01-01T00:00:00.000Z"});
    const refresh = await db.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(randomUUID()), expiresAt: "2002-01-01T00:00:00.000Z"});
    return {session, refresh};
  };
  const slow = await delayProxy(600);
  const slowRows = await expiredPair();
  const warnings = logs.length;
  const slowStart = performance.now();
  await startingAt(new Auth(port, [], now, {}, {}, through(slow.url)), slowRows.session.id).signin(email, password);
  await drain();
  const slowMillis = performance.now() - slowStart;
  assert.ok(!await db.appAuthRefreshTokens.findById({id: slowRows.refresh.id}), "a slow connection must not leave expired rows behind");
  assert.ok(!await db.appAuthSessions.findById({id: slowRows.session.id}));
  assert.equal(logs.length, warnings);
  assert.ok(slowMillis > 1_000 && slowMillis < cleanupBudgetMillis, "connection setup must exceed the old cap yet finish within the overall budget");
  console.log(JSON.stringify({risk: "slow-connect-cleanup", slowMillis: +slowMillis.toFixed(1)}));
  await slow.close();

  const stuck = await delayProxy(3_000);
  const stuckRows = await expiredPair();
  const stuckStart = performance.now();
  await new Auth(port, [], now, {}, {}, through(stuck.url)).signin(email, password);
  await drain();
  const stuckMillis = performance.now() - stuckStart;
  assert.ok(await db.appAuthRefreshTokens.findById({id: stuckRows.refresh.id}), "a delay beyond the budget must leave expired rows in place");
  assert.ok(stuckMillis >= cleanupBudgetMillis - 100 && stuckMillis < 8_000);
  assert.deepEqual(logs.at(-1), ["Authentication cleanup failed (session)."]);
  assert.equal(logs.length, warnings + 1);
  console.log(JSON.stringify({risk: "over-budget-connect", stuckMillis: +stuckMillis.toFixed(1)}));
  await stuck.close();
  assert.ok(logs.flat().every(value => !String(value).includes("private")));
  console.log("Authentication cleanup: detached response, bounded backlog, both parent-lock orders, consumed refresh retention, no-context expiry, rejected scheduling, port failures, deadline rollback and connection-budget alignment passed.");
} finally {
  await drain();
  console.error = originalLog;
  await other.close();
  await port.close();
}
