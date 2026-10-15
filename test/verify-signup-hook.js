import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { Auth, AuthError } from "../dist/auth/runtime.js";
import { createPostgresPort } from "../dist/postgres.js";
import { createDatabase } from "../dist/auth/private/database.js";

const failed = work => assert.rejects(work, error => error instanceof AuthError
  && error.code === "user_creation_failed" && error.status === 500);
const expired = work => assert.rejects(work, {message: "The transaction is no longer active."});
const user = {email: "private-signup@example.test"};

function fixture(t, creating, query = async () => []) {
  const calls = [], logs = [];
  t.mock.method(console, "error", message => logs.push(JSON.parse(message)));
  const port = {
    async query(sql, parameters) {
      calls.push({sql, parameters});
      if (sql.startsWith("select current_setting")) return [{lock_timeout: "7s", statement_timeout: "9s"}];
      return query(sql, parameters);
    },
    transaction() { throw new Error("Unexpected transaction."); },
  };
  const auth = new Auth(port, [], Date.now, {creating});
  return {run: () => auth.creating(port, user), calls, logs};
}

test("signup hook deadline invalidates queued and retained statements", async t => {
  t.mock.timers.enable({apis: ["setTimeout"]});
  const entered = Promise.withResolvers(), release = Promise.withResolvers();
  let lease, queued;
  const {run, calls, logs} = fixture(t, async tx => {
    lease = tx;
    const first = tx.query("first", []);
    queued = expired(tx.query("queued", []));
    await first;
  }, async sql => {
    if (sql === "first") { entered.resolve(); await release.promise; }
    return [];
  });
  const rejection = failed(run());
  await entered.promise;
  t.mock.timers.tick(5_000);
  await rejection;
  await expired(lease.query("late", []));
  release.resolve();
  await queued;
  assert.deepEqual(calls.filter(call => ["first", "queued", "late"].includes(call.sql)).map(call => call.sql), ["first"]);
  assert.equal(logs.length, 1);
  assert.deepEqual(Object.keys(logs[0]).sort(), ["cause", "elapsedMillis"]);
  assert.equal(logs[0].cause, "signup_hook_timeout");
  assert.equal(JSON.stringify(logs).includes(user.email), false);
});

test("successful signup hook restores existing limits and closes its handle", async t => {
  let lease, clock = 0;
  t.mock.method(performance, "now", () => clock);
  const {run, calls, logs} = fixture(t, async tx => {
    lease = tx;
    clock = 4_000;
    await tx.query("hook write", []);
  });
  await run();
  assert.ok(calls.some(call => call.sql.includes("'1000ms'")));
  assert.deepEqual(calls.at(-1), {
    sql: "select set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)", parameters: ["7s", "9s"],
  });
  await expired(lease.query("late", []));
  assert.deepEqual(logs, []);
});

test("elapsed time rejects a hook even when the event loop delays the timer", async t => {
  let clock = 0;
  t.mock.method(performance, "now", () => clock);
  const {run, logs} = fixture(t, async () => { clock = 5_001; });
  await failed(run());
  assert.deepEqual(logs, [{cause: "signup_hook_timeout", elapsedMillis: 5_001}]);
});

test("SQL timeout fails signup even when the hook catches its query error", async t => {
  const {run, logs} = fixture(t, async tx => {
    await tx.query("blocked", []).catch(() => {});
  }, async sql => {
    if (sql === "blocked") throw Object.assign(new Error("Private query details"), {code: "57014"});
    return [];
  });
  await failed(run());
  assert.equal(logs.length, 1);
  assert.equal(logs[0].cause, "signup_hook_timeout");
});

const url = process.env.CHIK_TEST_DATABASE_URL;

test("signup hook deadlines isolate PostgreSQL transactions and reused connections", {skip: !url}, async t => {
  const port = createPostgresPort(url), other = createPostgresPort(url);
  const db = createDatabase(port);
  const table = `signup_hook_${randomUUID().replaceAll("-", "")}`;
  await port.query(`create table "${table}" (id uuid primary key)`, []);
  t.after(async () => {
    try { await port.query(`drop table "${table}"`, []); }
    finally { await port.close(); await other.close(); }
  });
  const logs = [];
  t.mock.method(console, "error", message => logs.push(message));
  const provider = {id: "deadline", async verify(subject) {
    return {subject, verifiedEmail: `${subject}@example.test`};
  }};
  const normal = new Auth(port, [provider]), parallel = new Auth(other, [provider]);
  const signup = (auth, subject = randomUUID()) => auth.signinIdentity("deadline", subject);
  const absent = async subject => {
    assert.equal((await db.appAuthUsers.findMany({where: c => c.email.equals(`${subject}@example.test`)})).length, 0);
    assert.equal((await port.query(`select id from "${table}" where id = $1`, [subject])).length, 0);
  };

  await t.test("six-second hook rolls back writes while another email succeeds", async () => {
    const subject = randomUUID(), entered = Promise.withResolvers(), finished = Promise.withResolvers();
    const slow = new Auth(port, [provider], Date.now, {async creating(tx) {
      entered.resolve(performance.now());
      await tx.query(`insert into "${table}" values ($1)`, [subject]);
      await delay(6_000);
      try {
        await expired(tx.query(`insert into "${table}" values ($1)`, [randomUUID()]));
        finished.resolve();
      } catch (error) { finished.reject(error); }
    }});
    const rejection = failed(slow.signup(`${subject}@example.test`, randomUUID())).then(() => performance.now());
    const started = await entered.promise;
    const concurrentStarted = performance.now();
    const concurrent = await parallel.signup(`${randomUUID()}@example.test`, randomUUID());
    assert.ok(performance.now() - concurrentStarted < 5_000);
    assert.equal((await parallel.session(concurrent.accessToken)).id, concurrent.userId);
    const elapsed = (await rejection) - started;
    assert.ok(elapsed >= 4_500 && elapsed < 8_000);
    await absent(subject);
    const email = `${randomUUID()}@example.test`, password = randomUUID();
    const continued = await normal.signup(email, password);
    assert.equal((await normal.session(continued.accessToken)).id, continued.userId);
    await finished.promise;
    await absent(subject);
    assert.equal((await port.query(`select id from "${table}"`, [])).length, 0);
    const signedIn = await normal.signin(email, password);
    assert.equal(signedIn.userId, continued.userId);
    assert.equal((await normal.session(signedIn.accessToken)).id, continued.userId);
    const record = JSON.parse(logs.at(-1));
    assert.deepEqual(Object.keys(record).sort(), ["cause", "elapsedMillis"]);
    assert.equal(record.cause, "signup_hook_timeout");
    assert.ok(record.elapsedMillis >= 4_990 && record.elapsedMillis < 6_000);
    assert.equal(logs.join("\n").includes("@example.test"), false);
  });

  await t.test("four-second hook commits and restores limits before session issuance", async () => {
    const subject = randomUUID();
    await port.query("set lock_timeout = '7s'; set statement_timeout = '9s'", []);
    let settings;
    const observed = {
      query: (sql, args) => port.query(sql, args),
      transaction: work => port.transaction(tx => work({
        transaction: tx.transaction,
        async query(sql, args) {
          if (sql.startsWith('insert into "public"."app_auth_sessions"')) {
            [settings] = await tx.query("select current_setting('lock_timeout') as lock_timeout, current_setting('statement_timeout') as statement_timeout", []);
          }
          return tx.query(sql, args);
        },
      })),
    };
    const runtime = new Auth(observed, [provider], Date.now, {async creating(tx) {
      await delay(4_000);
      await tx.query(`insert into "${table}" values ($1)`, [subject]);
    }});
    const result = await runtime.signup(`${subject}@example.test`, randomUUID());
    assert.equal((await runtime.session(result.accessToken)).id, result.userId);
    assert.deepEqual(settings, {lock_timeout: "7s", statement_timeout: "9s"});
    assert.equal((await port.query(`select id from "${table}" where id = $1`, [subject])).length, 1);
  });

  await t.test("late SQL and lock waits use the remaining hook budget", async () => {
    for (const locked of [false, true]) {
      const subject = randomUUID(), release = Promise.withResolvers(), ready = Promise.withResolvers();
      const held = locked ? other.transaction(async tx => {
        await tx.query(`lock table "${table}" in access exclusive mode`, []);
        ready.resolve();
        await release.promise;
      }) : Promise.resolve();
      if (locked) await ready.promise;
      const runtime = new Auth(port, [provider], Date.now, {async creating(tx) {
        if (!locked) await tx.query(`insert into "${table}" values ($1)`, [subject]);
        await delay(4_000);
        await tx.query(locked ? `insert into "${table}" values ($1)` : "select pg_sleep(6)", locked ? [subject] : []);
      }});
      const started = performance.now();
      try { await failed(signup(runtime, subject)); }
      finally { release.resolve(); await held; }
      assert.ok(performance.now() - started < 6_000);
      await absent(subject);
      const result = await signup(normal);
      assert.equal((await normal.session(result.accessToken)).id, result.userId);
    }
  });
});
