import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { Auth, AuthError, invokeAuth } from "../dist/auth/index.js";
import { createDatabase } from "../dist/auth/private/database.js";
import { createPostgresPort } from "../dist/postgres.js";
import { hashToken, randomToken } from "../dist/auth/crypto.js";

const url = process.env.CHIK_TEST_DATABASE_URL;
const day = 86400000;
const start = Date.parse("2026-01-01T00:00:00Z");
const password = "correct horse battery staple";
const rejected = promise => assert.rejects(promise, error => error instanceof AuthError && error.status === 401);

test("rolling sessions through PostgreSQL", {skip: !url}, async t => {
  const port = createPostgresPort(url);
  t.after(() => port.close());
  const db = createDatabase(port);
  let clock = start;
  const now = () => clock;
  const provider = {id: "rolling", async verify(subject) {
    return {subject, verifiedEmail: `${subject}@example.test`};
  }};
  const auth = (session = {}, base = port, cleanup) => new Auth(base, [provider], now, {}, {session}, cleanup);
  const login = (runtime = auth(), transport = "native") => runtime.signinIdentity("rolling", randomUUID(), "", transport);

  const tasks = [], selections = [];
  const cleanup = {
    waitUntil(work) { tasks.push(work); },
    createPort(signal) {
      const base = createPostgresPort(url, signal);
      return {
        async query(sql, args) {
          const rows = await base.query(sql, args);
          if (sql.startsWith("select") && sql.includes('from "public"."app_auth_sessions"')) selections.push(rows.map(row => row.id));
          return rows;
        },
        transaction(work) { return base.transaction(work); },
        close() { return base.close(); },
      };
    },
  };
  const cleanupPass = async (runtime, origin) => {
    if (origin !== undefined) runtime.cleanupStart = () => origin;
    selections.length = 0;
    await login(runtime);
    await Promise.all(tasks.splice(0));
    assert.ok(selections.length >= 1 && selections.length <= 2, "A cleanup pass must use at most two session queries.");
    const selected = selections.flat();
    assert.ok(selected.length <= 2, "Wrapping must share the same session batch budget.");
    assert.equal(new Set(selected).size, selected.length, "Wrapping must not repeat a candidate.");
    return selected;
  };

  await t.test("CLEANUP-GROW(a): expanded idle delays selection but never revives stored expiry", async () => {
    clock = start;
    const first = await login(auth({idleTimeoutSeconds: 3600}));
    // Rejected refresh commits revocation, so use a twin to leave the cleanup subject untouched.
    const probe = await login(auth({idleTimeoutSeconds: 3600}));
    const refresh = (await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(first.sessionId)}))[0];
    assert.equal(Date.parse(refresh.expiresAt), start + 3600000);
    const runtime = auth({idleTimeoutSeconds: 31536000}, port, cleanup);
    clock = start + 3600001;
    assert.ok(!(await cleanupPass(runtime)).includes(first.sessionId));
    assert.equal((await db.appAuthSessions.findById({id: first.sessionId})).revokedAt, null);
    await rejected(auth({idleTimeoutSeconds: 31536000}).refresh(probe.refreshToken));
    clock = start + 31536000000 - 1;
    assert.ok(!(await cleanupPass(runtime)).includes(first.sessionId));
    assert.ok(await db.appAuthRefreshTokens.findById({id: refresh.id}));
    clock++;
    assert.ok((await cleanupPass(runtime)).includes(first.sessionId), "Expanded idle must eventually select the expired family.");
    assert.equal(await db.appAuthSessions.findById({id: first.sessionId}), undefined);
    assert.equal(await db.appAuthRefreshTokens.findById({id: refresh.id}), undefined);
  });

  await t.test("CLEANUP-GROW(b): keyset skips live legacy candidates and wraps within one batch", async () => {
    clock = start;
    const generated = [], randomRuntime = auth({}, port, cleanup);
    const generate = randomRuntime.cleanupStart.bind(randomRuntime);
    randomRuntime.cleanupStart = () => { const value = generate(); generated.push(value); return value; };
    await cleanupPass(randomRuntime);
    await cleanupPass(randomRuntime);
    assert.equal(generated.length, 2, "Each pass must use a fresh generated start.");
    for (const value of generated) assert.match(value, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(generated[0], generated[1]);

    for (const release of ["renewal", "expiry"]) {
      clock = start;
      const owner = await login();
      const userSessionVersion = (await db.appAuthUsers.findById({id: owner.userId})).sessionVersion;
      const active = [];
      const suffix = release === "renewal" ? "1" : "2";
      // Legacy access expiry can precede a newer, still-valid refresh issuance.
      for (let i = 0; i < 2; i++) {
        const current = randomToken();
        const session = await db.appAuthSessions.insert({id: `00000000-0000-4000-8000-0000000000${suffix}${i}`,
          userId: owner.userId, userSessionVersion, tokenHash: hashToken(randomToken()),
          createdAt: new Date(clock - 3 * 3600000).toISOString(),
          expiresAt: new Date(clock - 2 * 3600000 + i * 1000).toISOString()});
        const refresh = await db.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(current),
          createdAt: new Date(clock - 1800000).toISOString(), expiresAt: new Date(clock + day).toISOString()});
        active.push({session, refresh, current});
      }
      const dead = await db.appAuthSessions.insert({id: `ffffffff-ffff-4fff-bfff-00000000000${suffix}`,
        userId: owner.userId, userSessionVersion, tokenHash: hashToken(randomToken()),
        createdAt: new Date(clock - 3 * 3600000).toISOString(), firstLoginAt: new Date(clock - 3 * 3600000).toISOString(),
        lastRenewedAt: new Date(clock - 2 * 3600000).toISOString(), expiresAt: new Date(clock - 3600000).toISOString()});
      const expired = await db.appAuthRefreshTokens.insert({sessionId: dead.id, tokenHash: hashToken(randomToken()),
        createdAt: dead.createdAt, expiresAt: new Date(clock - 1).toISOString()});
      const ids = active.map(({session}) => session.id);
      assert.ok((await cleanupPass(auth({}, port, cleanup), ids[0])).every(id => !ids.includes(id) && id !== dead.id));
      const runtime = auth({idleTimeoutSeconds: 3600}, port, cleanup);
      for (let repeat = 0; repeat < 2; repeat++) {
        assert.deepEqual(await cleanupPass(runtime, ids[0]), ids, "The same start and candidates must select the same full live batch.");
        assert.equal(selections.length, 1, "A full first range must not query the wrapped range.");
        assert.ok(await db.appAuthSessions.findById({id: dead.id}));
      }
      assert.deepEqual(await cleanupPass(runtime, dead.id), [dead.id, ids[0]], "A later start must reach the dead family and fill from the front.");
      assert.equal(selections.length, 2);
      assert.equal(await db.appAuthSessions.findById({id: dead.id}), undefined);
      assert.equal(await db.appAuthRefreshTokens.findById({id: expired.id}), undefined);
      for (const {session, refresh} of active) {
        assert.equal((await db.appAuthSessions.findById({id: session.id})).revokedAt, null);
        assert.equal((await db.appAuthRefreshTokens.findById({id: refresh.id})).consumedAt, null);
      }
      if (release === "renewal") {
        const renewing = auth({idleTimeoutSeconds: 3600});
        for (const {session, current} of active) {
          const rotated = await renewing.refresh(current);
          const again = await renewing.refresh(rotated.refreshToken);
          assert.equal(again.sessionId, session.id);
        }
        assert.ok((await cleanupPass(runtime, ids[0])).every(id => !ids.includes(id)));
      } else {
        clock = start + 1800000 - 1;
        assert.deepEqual(await cleanupPass(runtime, ids[0]), ids, "Live legacy families survive 1ms before the shortened idle boundary.");
        clock++;
        assert.deepEqual(await cleanupPass(runtime, ids[0]), ids, "The shortened idle boundary makes the live families eligible for deletion.");
        for (const {session, refresh} of active) {
          assert.equal(await db.appAuthSessions.findById({id: session.id}), undefined);
          assert.equal(await db.appAuthRefreshTokens.findById({id: refresh.id}), undefined);
        }
      }
    }
  });

  await t.test("A-05: default idle expiry rolls on successful rotation", async () => {
    clock = start;
    const runtime = auth();
    const first = await login(runtime);
    assert.equal(Date.parse(first.refreshExpiresAt), start + 30 * day);
    clock += 29 * day;
    const second = await runtime.refresh(first.refreshToken);
    assert.equal(Date.parse(second.refreshExpiresAt), start + 59 * day);
    clock = start + 31 * day;
    const third = await runtime.refresh(second.refreshToken);
    assert.equal(Date.parse(third.refreshExpiresAt), start + 61 * day);
    assert.equal(third.sessionId, first.sessionId);
    assert.equal(third.userId, first.userId);
    const row = await db.appAuthSessions.findById({id: first.sessionId});
    assert.equal(Date.parse(row.firstLoginAt), start);
    assert.equal(Date.parse(row.lastRenewedAt), clock);
    await rejected(runtime.refresh(first.refreshToken));
    await rejected(runtime.session(third.accessToken));
    await rejected(runtime.refresh(third.refreshToken));
  });

  await t.test("A-06: idle boundary rejects and commits revocation without access renewal", async () => {
    for (const offset of [-1000, 0, 1000]) {
      clock = start;
      const runtime = auth();
      const first = await login(runtime);
      clock += 600000;
      await runtime.session(first.accessToken);
      assert.equal((await db.appAuthSessions.findById({id: first.sessionId})).lastRenewedAt, new Date(start).toISOString());
      clock = start + 30 * day + offset;
      if (offset < 0) await runtime.refresh(first.refreshToken);
      else {
        await rejected(runtime.refresh(first.refreshToken));
        const row = await db.appAuthSessions.findById({id: first.sessionId});
        assert.ok(row.revokedAt);
        assert.equal(Date.parse(row.lastRenewedAt), start);
      }
    }
  });

  await t.test("A-07: rotations preserve the 60-day cap including a still-live access credential", async () => {
    for (const offset of [-1000, 0, 1000]) {
      clock = start;
      const runtime = auth({absoluteLifetimeSeconds: 60 * 86400});
      let tokens = await login(runtime);
      for (const days of [29, 58]) {
        clock = start + days * day;
        tokens = await runtime.refresh(tokens.refreshToken);
      }
      assert.equal(Date.parse(tokens.refreshExpiresAt), start + 60 * day);
      clock = start + 60 * day + offset;
      if (offset < 0) {
        tokens = await runtime.refresh(tokens.refreshToken);
        clock += 1000;
        assert.ok(Date.parse(tokens.expiresAt) > clock);
        await rejected(runtime.session(tokens.accessToken));
      } else await rejected(runtime.refresh(tokens.refreshToken));
      assert.ok((await db.appAuthSessions.findById({id: tokens.sessionId})).revokedAt);
    }
  });

  await t.test("SESS-1: legacy latest issuance, stored expiry and live transition", async () => {
    for (const variant of ["recent", "idle", "stored", "absolute"]) {
      clock = start;
      const first = await login();
      const refresh = (await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(first.sessionId)}))[0];
      await db.appAuthSessions.update({id: first.sessionId}, {createdAt: new Date(start - 5 * day).toISOString(), firstLoginAt: null, lastRenewedAt: null});
      await db.appAuthRefreshTokens.update({id: refresh.id}, {
        createdAt: new Date(start - (variant === "idle" ? 7200000 : 1800000)).toISOString(),
        expiresAt: new Date(start + (variant === "stored" ? -1 : day)).toISOString(),
      });
      const runtime = auth({idleTimeoutSeconds: 3600, absoluteLifetimeSeconds: variant === "absolute" ? 86400 : 0});
      if (variant === "recent") {
        const next = await runtime.refresh(first.refreshToken);
        assert.equal(Date.parse(next.refreshExpiresAt), start + 3600000);
        const row = await db.appAuthSessions.findById({id: first.sessionId});
        assert.equal(Date.parse(row.firstLoginAt), start - 5 * day);
        assert.equal(Date.parse(row.lastRenewedAt), start);
      } else await rejected(runtime.refresh(first.refreshToken));
    }
  });

  await t.test("current policy takes effect on access, refresh and browser without reviving expired families", async () => {
    for (const transport of ["native", "browser"]) {
      for (const absolute of [false, true]) {
        clock = start;
        const first = await login(auth(), transport);
        clock += 3600000;
        const runtime = auth(absolute ? {absoluteLifetimeSeconds: 3600} : {idleTimeoutSeconds: 3600});
        await rejected(runtime.session(transport === "browser" ? first.credential : first.accessToken, transport));
        assert.ok((await db.appAuthSessions.findById({id: first.sessionId})).revokedAt);
      }
      clock = start;
      const runtime = auth({idleTimeoutSeconds: 3600});
      const first = await login(runtime, transport);
      clock += 3600000;
      if (transport === "browser") await rejected(auth().session(first.credential, transport));
      else await rejected(auth().refresh(first.refreshToken));
    }
  });

  await t.test("rotation racing replay and user invalidation never leaves usable credentials", async () => {
    const other = createPostgresPort(url);
    try {
      clock = start;
      const first = await login();
      const results = await Promise.allSettled([auth().refresh(first.refreshToken), auth({}, other).refresh(first.refreshToken)]);
      assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
      const rotated = results.find(result => result.status === "fulfilled").value;
      await rejected(auth().session(rotated.accessToken));
      await rejected(auth().refresh(rotated.refreshToken));
      for (const mode of ["disable", "version"]) {
        const tokens = await login();
        const user = await db.appAuthUsers.findById({id: tokens.userId});
        const change = mode === "disable" ? {disabledAt: new Date(clock).toISOString()} : {sessionVersion: user.sessionVersion + 1};
        await db.appAuthUsers.update({id: tokens.userId}, change);
        await rejected(auth().session(tokens.accessToken));
        await rejected(auth().refresh(tokens.refreshToken));
      }
    } finally { await other.close(); }
  });

  await t.test("expiry is checked after waiting for the session lock", async () => {
    clock = start;
    const first = await login(auth({idleTimeoutSeconds: 3600}));
    const other = createPostgresPort(url);
    const held = Promise.withResolvers(), release = Promise.withResolvers(), attempted = Promise.withResolvers();
    const holding = other.transaction(async tx => {
      await createDatabase(tx).appAuthSessions.update({id: first.sessionId}, {revokedAt: null});
      held.resolve();
      await release.promise;
    });
    const observe = base => ({
      async query(sql, args) { if (sql.startsWith('update "public"."app_auth_sessions"')) attempted.resolve(); return base.query(sql, args); },
      transaction(work) { return base.transaction(tx => work(observe(tx))); },
    });
    try {
      await held.promise;
      clock = start + 3599999;
      const pending = rejected(auth({idleTimeoutSeconds: 3600}, observe(port)).refresh(first.refreshToken));
      await attempted.promise;
      clock++;
      release.resolve();
      await holding;
      await pending;
      assert.equal(Date.parse((await db.appAuthSessions.findById({id: first.sessionId})).lastRenewedAt), start);
    } finally { release.resolve(); await holding; await other.close(); }
  });

  await t.test("F-08: browser activity rolls only DB expiry and auth responses own cookies", async () => {
    clock = start;
    const runtime = auth({idleTimeoutSeconds: 3600});
    const request = new Request("https://api.example.test/auth.browser_identity", {method: "POST"});
    const context = {credential: "", cookieName: `__Host-chik_session_${randomUUID()}`, headers: new Headers()};
    const first = await invokeAuth(runtime, "auth.browser_identity", {provider: "rolling", credential: randomUUID()}, request, context);
    const cookie = context.headers.get("set-cookie");
    assert.match(cookie, /; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=34560000$/);
    assert.ok(!cookie.includes("Domain="));
    context.credential = cookie.slice(cookie.indexOf("=") + 1, cookie.indexOf(";"));
    assert.ok(!JSON.stringify(first).includes(context.credential));
    for (const seconds of [600, 1200, 1801, 2400, 3000, 3601]) {
      clock = start + seconds * 1000;
      context.headers = new Headers();
      const current = await invokeAuth(runtime, "auth.browser_session", {}, request, context);
      assert.equal(Date.parse(current.expires_at), clock + 3600000);
      assert.equal(context.headers.has("set-cookie"), false);
      assert.equal(Date.parse((await db.appAuthSessions.findById({id: first.session_id})).firstLoginAt), start);
    }
    clock += 3600000;
    await rejected(invokeAuth(runtime, "auth.browser_session", {}, request, context));
    assert.equal(context.headers.has("set-cookie"), false);
    const replacement = await invokeAuth(runtime, "auth.browser_identity", {provider: "rolling", credential: randomUUID()}, request, context);
    assert.notEqual(replacement.session_id, first.session_id);
    assert.notEqual(context.headers.get("set-cookie"), cookie);
    await rejected(runtime.session(context.credential, "browser"));
    context.credential = context.headers.get("set-cookie").split(";", 1)[0].split("=")[1];
    context.headers = new Headers();
    await invokeAuth(runtime, "auth.browser_logout", {}, request, context);
    assert.match(context.headers.get("set-cookie"), /Max-Age=0$/);
  });

  await t.test("browser cap and independent idle expiry boundaries", async () => {
    for (const offset of [-1000, 0, 1000]) {
      clock = start;
      const runtime = auth({idleTimeoutSeconds: 3600, absoluteLifetimeSeconds: 7200});
      const first = await login(runtime, "browser");
      assert.equal(first.cookieMaxAge, 7200);
      clock += 3600000 + offset;
      if (offset < 0) {
        const current = await runtime.session(first.credential, "browser");
        assert.equal(Date.parse(current.expiresAt), clock + 3600000);
      } else await rejected(runtime.session(first.credential, "browser"));
    }
    clock = start;
    const runtime = auth({absoluteLifetimeSeconds: 3600});
    const first = await login(runtime, "browser");
    clock += 3599000;
    assert.equal(Date.parse((await runtime.session(first.credential, "browser")).expiresAt), start + 3600000);
    clock++;
    await runtime.session(first.credential, "browser");
    clock = start + 3600000;
    await rejected(runtime.session(first.credential, "browser"));
  });

  await t.test("login and refresh record access expiry atomically with refresh insertion", async () => {
    clock = start;
    const writes = [];
    let transaction = 0, fail = false, failSession = false;
    const observe = (base, id = 0) => ({
      async query(sql, args) {
        if (fail && sql.startsWith('insert into "public"."app_auth_refresh_tokens"')) throw new Error("Fixture insertion failure.");
        if (failSession && sql.startsWith('insert into "public"."app_auth_sessions"')) throw new Error("Fixture session failure.");
        const rows = await base.query(sql, args);
        if (/^(insert|update)/.test(sql)) writes.push({sql, rows, transaction: id});
        return rows;
      },
      transaction(work) { return base.transaction(tx => work(observe(tx, ++transaction))); },
    });
    const runtime = auth({}, observe(port));
    const first = await runtime.signup(`atomic-${randomUUID()}@example.test`, password);
    const verify = () => {
      const refresh = writes.findLast(entry => entry.sql.startsWith('insert into "public"."app_auth_refresh_tokens"'));
      const session = writes.findLast(entry => entry.rows[0]?.id === first.sessionId);
      assert.ok(refresh.transaction > 0);
      assert.equal(refresh.transaction, session.transaction);
      assert.equal(Date.parse(session.rows[0].expires_at), clock + 900000);
    };
    verify();
    clock += 600000;
    await runtime.refresh(first.refreshToken);
    verify();
    const live = await login(runtime);
    const before = await db.appAuthSessions.findById({id: live.sessionId});
    const old = (await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(live.sessionId)}))[0];
    clock += 600000;
    fail = true;
    await assert.rejects(runtime.refresh(live.refreshToken), /Fixture insertion failure/);
    assert.deepEqual(await db.appAuthSessions.findById({id: live.sessionId}), before);
    assert.equal((await db.appAuthRefreshTokens.findById({id: old.id})).consumedAt, null);
    fail = false;
    await runtime.refresh(live.refreshToken);
    const previous = await login(runtime, "browser");
    failSession = true;
    await assert.rejects(runtime.signinIdentity("rolling", randomUUID(), "", "browser", previous.credential), /Fixture session failure/);
    failSession = false;
    assert.equal((await db.appAuthSessions.findById({id: previous.sessionId})).revokedAt, null);
    await runtime.session(previous.credential, "browser");
    const replacement = await runtime.signinIdentity("rolling", randomUUID(), "", "browser", previous.credential);
    assert.notEqual(replacement.credential, previous.credential);
    await rejected(runtime.session(previous.credential, "browser"));
  });

  await t.test("F-05: cleanup progresses past retained credentials and old legacy parents", async () => {
    clock = start + 90 * day;
    const owner = await login();
    const userSessionVersion = (await db.appAuthUsers.findById({id: owner.userId})).sessionVersion;
    const active = [];
    for (let i = 0; i < 4; i++) {
      const access = randomToken(), old = randomToken(), current = randomToken();
      const session = await db.appAuthSessions.insert({userId: owner.userId, userSessionVersion, tokenHash: hashToken(access),
        createdAt: new Date(clock - 40 * day).toISOString(), firstLoginAt: new Date(clock - 40 * day).toISOString(),
        lastRenewedAt: new Date(clock).toISOString(), expiresAt: new Date(clock + 900000).toISOString()});
      const retained = await db.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(old),
        createdAt: new Date(clock - 40 * day).toISOString(), consumedAt: new Date(clock).toISOString(), expiresAt: new Date(clock - 10 * day).toISOString()});
      await db.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(current),
        createdAt: new Date(clock).toISOString(), expiresAt: new Date(clock + 30 * day).toISOString()});
      active.push({session, retained, old, access, current});
    }
    const dead = await db.appAuthSessions.insert({userId: owner.userId, userSessionVersion, tokenHash: hashToken(randomToken()),
      createdAt: new Date(clock - 7 * day).toISOString(), expiresAt: new Date(clock + 100 * day).toISOString()});
    await db.appAuthRefreshTokens.insert({sessionId: dead.id, tokenHash: hashToken(randomToken()),
      createdAt: dead.createdAt, expiresAt: new Date(clock).toISOString()});
    const selectedLive = await db.appAuthSessions.insert({userId: owner.userId, userSessionVersion, tokenHash: hashToken(randomToken()),
      createdAt: new Date(clock - 8 * day).toISOString(), expiresAt: new Date(clock + 90 * day).toISOString()});
    const latestLive = await db.appAuthRefreshTokens.insert({sessionId: selectedLive.id, tokenHash: hashToken(randomToken()),
      createdAt: new Date(clock - 1800000).toISOString(), expiresAt: new Date(clock + day).toISOString()});
    const tasks = [], passes = [];
    const context = {
      waitUntil(work) { tasks.push(work); },
      createPort(signal) {
        const base = createPostgresPort(url, signal);
        const pass = {deletions: 0};
        passes.push(pass);
        const observe = tx => ({
          async query(sql, args) { const rows = await tx.query(sql, args); if (sql.startsWith("delete")) pass.deletions += rows.length; return rows; },
          transaction(work) { return tx.transaction(inner => work(observe(inner))); },
        });
        return {...observe(base), close: () => base.close()};
      },
    };
    const runtime = auth({}, port, context);
    runtime.cleanupStart = () => dead.id;
    let credentials = owner;
    for (let i = 0; i < 40 && await db.appAuthSessions.findById({id: dead.id}); i++) {
      credentials = await runtime.refresh(credentials.refreshToken);
      await Promise.all(tasks.splice(0));
    }
    assert.equal(await db.appAuthSessions.findById({id: dead.id}), undefined, "Seven-day legacy candidate was starved.");
    assert.ok(passes.some(pass => pass.deletions > 0));
    assert.ok(passes.every(pass => pass.deletions <= 8));
    assert.ok(await db.appAuthSessions.findById({id: selectedLive.id}), "Selection alone must not delete a live legacy family.");
    assert.ok(await db.appAuthRefreshTokens.findById({id: latestLive.id}));
    for (const {session, retained} of active) {
      assert.ok(await db.appAuthSessions.findById({id: session.id}));
      assert.ok(await db.appAuthRefreshTokens.findById({id: retained.id}));
    }
    await rejected(auth().refresh(active[0].old));
    await rejected(auth().session(active[0].access));
    await rejected(auth().refresh(active[0].current));
  });
});
