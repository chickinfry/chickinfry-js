import assert from "node:assert/strict";
import test from "node:test";
import { Auth, AuthError } from "@chickinfry/chickinfry/auth";
import { randomBytes, randomUUID } from "node:crypto";
import { defineTable, Repository } from "@chickinfry/chickinfry";
import pg from "pg";
import { createPostgresPort } from "@chickinfry/chickinfry/postgres";
import { createDatabase } from "../dist/auth/private/database.js";

const runtime = () => import("@chickinfry/chickinfry/auth/runtime");
const noIO = {query() { throw new Error("Unexpected I/O"); }, transaction() { throw new Error("Unexpected I/O"); }};
const request = () => new Request("https://example.test/service.read", {method: "POST"});

function dollarBoundary(tag, command) {
  const outer = `$${tag}$`, inner = "$nested$";
  return ["select", outer, inner, `${outer};`, `${command};`, "--", inner].join(" ");
}

const dollarTags = ["\u00e9", "\ud55c", "tag\u0080", String.fromCodePoint(0x1f680)];

test("runtime rejects anonymous protected calls before entering language code", async () => {
  const {invokeRuntime} = await runtime();
  const auth = new Auth(noIO);
  let calls = 0;
  const invocation = {protected: true, async invoke() { calls++; }};
  await assert.rejects(invokeRuntime(auth, "service.read", {}, request(), invocation),
    error => error instanceof AuthError && error.code === "unauthenticated" && error.status === 401);
  assert.equal(calls, 0);
  const result = await invokeRuntime(auth, "service.read", {}, request(), {
    protected: false, async invoke(session) { calls++; return session; },
  });
  assert.equal(result, null);
  assert.equal(calls, 1);
});

test("runtime rejects malformed credentials even for public operations", async () => {
  const {invokeRuntime} = await runtime();
  const incoming = request();
  incoming.headers.set("authorization", "invalid");
  let called = false;
  await assert.rejects(invokeRuntime(new Auth(noIO), "service.read", {}, incoming, {
    protected: false, async invoke() { called = true; },
  }), error => error instanceof AuthError && error.code === "invalid_token");
  assert.equal(called, false);
});

test("lease adapters deny transaction control without sending it to the host", async () => {
  const {createLeasePort} = await runtime();
  const port = createLeasePort({async exec() { throw new Error("Host received forbidden SQL"); }});
  for (const sql of ["begin", "COMMIT", "rollback", "end", "abort", "start transaction", "savepoint x",
    "release savepoint x", "prepare transaction 'x'", "/* comment */ commit", "select 1; -- comment\n rollback",
    "/* outer /* inner */ end */ begin", "select 1;commit and chain",
    "select 1 as label$tag$; commit; -- $tag$", "select 1 as \u00e9$tag$; rollback; -- $tag$"]) {
    await assert.rejects(async () => port.query(sql, []), /Transaction control belongs to the host/);
  }
  await assert.rejects(async () => port.transaction(async () => {}), /Nested transactions/);
});

test("host transaction ports expire after their owner commits or rolls back", async () => {
  const {createHostPort} = await runtime();
  const host = {async exec(sql) {
    return sql.includes(" as transaction_state") ? [{transaction_state: "stable"}] : [{value: 1}];
  }, async transaction(work) { return work(this); }};
  const port = createHostPort(host);
  let retained;
  await port.transaction(async tx => {
    retained = tx;
    assert.deepEqual(await tx.query("select '; commit' as text, $$; rollback$$ as quoted", []), [{value: 1}]);
  });
  await assert.rejects(async () => retained.query("select 1", []), /no longer active/);
  await assert.rejects(port.transaction(async tx => { retained = tx; throw new Error("failed"); }), /failed/);
  await assert.rejects(async () => retained.query("select 1", []), /no longer active/);
});

test("lease adapters reject control hidden by non-ASCII dollar quoting", async () => {
  const {createLeasePort} = await runtime();
  const port = createLeasePort({async exec() { throw new Error("Host received forbidden SQL"); }});
  for (const tag of dollarTags) {
    for (const command of ["commit", "rollback"]) {
      await assert.rejects(port.query(dollarBoundary(tag, command), []), /Transaction control belongs to the host/);
    }
  }
  for (const sql of ["select $1broken$", "select $unterminated$value", 'select U&"escaped"', "select '\\'",
    `select $${String.fromCharCode(0xd800)}$value$${String.fromCharCode(0xd800)}$`]) {
    await assert.rejects(port.query(sql, []), /Transaction control belongs to the host/);
  }
});

test("lease adapters reject transaction settings while preserving hook timeouts", async () => {
  const {createLeasePort} = await runtime();
  const forbidden = createLeasePort({async exec() { throw new Error("Host received forbidden SQL"); }});
  const settings = ["transaction_isolation", "transaction_read_only", "transaction_deferrable"];
  for (const sql of ["set transaction read only", "set session characteristics as transaction read only",
    "set /* comment */ session /* comment */ characteristics as transaction read only", "reset all"]) {
    await assert.rejects(forbidden.query(sql, []), /Transaction control belongs to the host/);
  }
  for (const key of settings.flatMap(name => [name, `default_${name}`])) {
    for (const sql of [`set ${key} = default`, `set local "${key}" = default`, `reset "${key}"`,
      `select pg_catalog.set_config('${key}', 'on', true)`, `select set_config($$${key}$$, 'on', true)`,
      "select set_config($1, $2, true)"]) {
      await assert.rejects(forbidden.query(sql, [key, "on"]), /Transaction control belongs to the host/);
    }
  }
  await assert.rejects(forbidden.query("select set_config('transaction_' || 'read_only', 'on', true)", []),
    /Transaction control belongs to the host/);
  const allowed = createLeasePort({async exec() { return []; }});
  await allowed.query("set local lock_timeout = '100ms'; set local statement_timeout = '100ms'", []);
  await allowed.query("select set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)", ["1s", "1s"]);
  await allowed.query("select set_config($1, $2, true)", ["lock_timeout", "1s"]);
  await allowed.query("set local application_name = 'lease-test'", []);
});

const url = process.env.CHIK_TEST_RUNTIME_DATABASE_URL ?? process.env.CHIK_TEST_DATABASE_URL;

test("host leases preserve PostgreSQL authentication, email, cleanup, and signup atomicity", {skip: !url}, async t => {
  const {createHostPort, invokeRuntime} = await runtime();
  const tableName = `auth_hook_${randomUUID().replaceAll("-", "")}`;
  const hookTable = defineTable({name: tableName, primaryKey: ["id"], columns: {id: "id"}});
  const admin = createPostgresPort(url);
  t.after(async () => { await admin.query(`drop table "${tableName}"`, []); await admin.close(); });
  await admin.query(`create table "${tableName}" (id uuid primary key references app_auth_users(id))`, []);
  const db = createDatabase(admin);
  const rows = new Repository(admin, hookTable);
  const password = randomBytes(32).toString("base64url");
  const open = mode => {
    if (mode === "pg") return createPostgresPort(url);
    const client = new pg.Client({connectionString: url, types: {getTypeParser(oid, format) {
      return oid === 1082 || oid === 1184 ? value => value : pg.types.getTypeParser(oid, format);
    }}});
    const connected = client.connect();
    const lease = {async exec(sql, parameters) {
      await connected;
      const result = await client.query(sql, parameters);
      return (Array.isArray(result) ? result.at(-1) : result).rows;
    }};
    const host = {...lease, async transaction(work) {
      await lease.exec("begin", []);
      let result;
      try { result = await work(lease); }
      catch (error) { await lease.exec("rollback", []); await lease.exec("discard all", []); throw error; }
      const committed = await client.query("commit");
      assert.equal(committed.command, "COMMIT");
      await lease.exec("discard all", []);
      return result;
    }};
    const port = mode === "raw" ? {query: lease.exec,
      transaction: work => host.transaction(() => work({query: lease.exec,
        transaction() { throw new Error("Nested transactions are not supported."); }})),
    } : createHostPort(host);
    return Object.assign(port, {
      async replaceTransaction() {
        await lease.exec("commit", []);
        await lease.exec("begin", []);
      },
      async close() { await connected; await client.end(); },
    });
  };
  const rejected = (work, code, status) => assert.rejects(work,
    error => error instanceof AuthError && error.code === code && error.status === status);
  const normalize = result => Object.fromEntries(Object.entries(result).map(([key, value]) => [key,
    /token$/.test(key) ? typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value)
      : key === "id" || key === "attempt" || /_id$/.test(key) ? typeof value === "string" && /^[0-9a-f-]{36}$/.test(value)
        : key === "email" ? value.endsWith("@example.test") : value]));
  async function scenario(mode, verification) {
    const port = open(mode);
    const pending = [], mail = [], hookEvents = [], results = [];
    const settle = async () => { while (pending.length) await Promise.all(pending.splice(0)); };
    const email = `${randomUUID()}@example.test`;
    let clock = Date.parse("2031-01-01T12:00:00Z"), userId;
    const cleanup = {waitUntil(work) { pending.push(work); }, createPort() { return open(mode); }};
    const options = verification ? {email: {verification: "required"},
      migrationState: {verificationRequiredSince: Promise.resolve("2000-01-01T00:00:00Z")},
      emailLinkBase: "https://example.test", mailer: {async send(message) { mail.push(message); }}} : {};
    const auth = new Auth(port, [], () => clock, {
      async creating(tx, user) {
        userId = user.id;
        assert.ok(await createDatabase(tx).appAuthUsers.findById({id: user.id}));
        assert.equal(await db.appAuthUsers.findById({id: user.id}), null);
        await new Repository(tx, hookTable).insert({id: user.id});
        await tx.query("set local lock_timeout = '3s'; set local statement_timeout = '4s'", []);
        hookEvents.push("creating");
      },
      async committed(user) {
        assert.ok(await rows.findById({id: user.id}));
        hookEvents.push("committed");
      },
    }, options, cleanup);
    const call = async (operation, input = {}, access) => {
      const incoming = request();
      if (access) incoming.headers.set("authorization", `Bearer ${access}`);
      const result = mode === "pg"
        ? await (await import("../dist/auth/router.js")).invokeAuth(auth, operation, input, incoming)
        : await invokeRuntime(auth, operation, input, incoming, {protected: true,
          async invoke() { throw new Error("Auth operation entered language code"); }});
      await settle();
      results.push(normalize(result));
      return result;
    };
    try {
      const signup = await call("auth.signup", {email, password});
      if (verification) {
        assert.equal(signup.accepted, true);
        assert.match(signup.attempt, /^[0-9a-f-]{36}$/);
        assert.deepEqual(hookEvents, []);
        assert.equal((await db.appAuthUsers.findMany({where: c => c.email.eq(email)})).length, 0);
        await rejected(call("auth.signin", {email, password}), "invalid_credentials", 401);
        const code = /\b([0-9]{3}) ([0-9]{3})\b/.exec(mail.at(-1).text);
        assert.ok(code);
        const confirmation = {attempt: signup.attempt, code: code[1] + code[2]};
        await call("auth.verify_email", confirmation);
        await rejected(call("auth.verify_email", confirmation), "invalid_code", 400);
      }
      assert.deepEqual(hookEvents, ["creating", "committed"]);
      const signedIn = await call("auth.signin", {email, password});
      const session = await call("auth.session", {}, signedIn.access_token);
      assert.equal(session.email_verified, verification);
      let languageCalls = 0;
      const business = await invokeRuntime(auth, "service.read", {}, new Request(request(), {
        headers: {authorization: `Bearer ${signedIn.access_token}`},
      }), {protected: true, async invoke(value) { languageCalls++; return value; }});
      assert.equal(languageCalls, 1);
      assert.ok(business.id === userId && business.sessionId === signedIn.session_id);
      assert.equal(Object.keys(business).some(key => /token|password|credential/i.test(key)), false);
      const refreshed = await call("auth.refresh", {refresh_token: signedIn.refresh_token});
      await call("auth.logout", {}, refreshed.access_token);
      await rejected(call("auth.session", {}, refreshed.access_token), "invalid_token", 401);
      if (verification) {
        await call("auth.request_password_reset", {email});
        const reset = new URLSearchParams(new URL(mail.at(-1).text.match(/https:\/\/\S+/)[0]).hash.slice(1)).get("token");
        const active = await call("auth.signin", {email, password});
        await call("auth.reset_password", {token: reset, password});
        await rejected(call("auth.session", {}, active.access_token), "invalid_token", 401);
        await rejected(call("auth.reset_password", {token: reset, password}), "invalid_token", 400);
      }
      const user = await db.appAuthUsers.findById({id: userId});
      results.push({verified: user.emailVerifiedAt !== null, version: user.sessionVersion,
        hooks: hookEvents, businessRows: (await rows.findMany({where: c => c.id.eq(userId)})).length});
      clock += 32 * 24 * 60 * 60_000;
      await call("auth.signin", {email, password});
      for (let i = 0; i < 8; i++) {
        const sessions = await db.appAuthSessions.findMany({where: c => c.userId.eq(userId)});
        if (sessions.length === 1) break;
        await call("auth.signin", {email, password});
      }
      const sessions = await db.appAuthSessions.findMany({where: c => c.userId.eq(userId)});
      assert.equal(sessions.some(row => row.revokedAt !== null || Date.parse(row.expiresAt) <= clock), false);
      const refreshes = await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.isIn(sessions.map(row => row.id))});
      results.push({sessions: sessions.map(row => ({transport: row.transport, version: row.userSessionVersion,
        expiresAt: row.expiresAt, firstLoginAt: row.firstLoginAt, lastRenewedAt: row.lastRenewedAt, revokedAt: row.revokedAt})),
        refreshes: refreshes.map(row => ({expiresAt: row.expiresAt, consumedAt: row.consumedAt})),
        actionRows: (await db.appAuthActionTokens.findMany({where: c => c.userId.eq(userId)})).length});
      return results;
    } finally { await settle(); await port.close(); }
  }
  await t.test("host rejects a replaced transaction before returning to its owner", async () => {
    const port = open("host");
    let retained;
    try {
      await assert.rejects(port.transaction(async tx => {
        retained = tx;
        await port.replaceTransaction();
      }), /Transaction state changed/);
      await assert.rejects(async () => retained.query("select 1", []), /no longer active/);
    } finally { await port.close(); }
  });
  const changes = [["read_only", "on"], ["isolation", "read uncommitted"], ["deferrable", "on"]]
    .flatMap(([name, value]) => [[`transaction_${name}`, value], [`default_transaction_${name}`, value]]);
  const settings = tx => tx.query(`select pg_catalog.pg_backend_pid()::pg_catalog.text as backend,
    pg_catalog.current_setting('default_transaction_read_only') as read_only,
    pg_catalog.current_setting('default_transaction_isolation') as isolation,
    pg_catalog.current_setting('default_transaction_deferrable') as deferrable,
    pg_catalog.current_setting('transaction_read_only') as current_read_only,
    pg_catalog.current_setting('transaction_isolation') as current_isolation,
    pg_catalog.current_setting('transaction_deferrable') as current_deferrable`, []);
  for (const [setting, value] of changes) {
    const command = `do $body$ begin perform pg_catalog.set_config('${setting}', '${value}', ${!setting.startsWith("default_")}); end; $body$`;
    await t.test(`host transaction preserves state after indirect ${setting} changes`, async () => {
      const port = open("host");
      try {
        const before = await port.transaction(settings);
        if (setting.startsWith("default_")) await port.transaction(tx => tx.query(command, []));
        else await assert.rejects(port.transaction(tx => tx.query(command, [])), error => (!setting.endsWith("read_only") && error.code === "25001") || /Transaction state changed/.test(error.message));
        assert.deepEqual(await port.transaction(settings), before);
      } finally { await port.close(); }
    });
    for (const mode of ["pg", "host"]) {
      await t.test(`${mode} signup preserves state after indirect ${setting} changes`, async () => {
        const port = open(mode), email = `${randomUUID()}@example.test`;
        let committed = false, failedUser, retained;
        const auth = new Auth(port, [], Date.now, {async creating(tx, user) {
          retained = tx;
          failedUser = user.id;
          await new Repository(tx, hookTable).insert({id: user.id});
          await tx.query(command, []);
        }, async committed() { committed = true; }});
        try {
          const before = await port.transaction(settings);
          if (setting.startsWith("default_")) {
            const result = await auth.signup(email, password);
            assert.equal(result.userId, failedUser);
            assert.equal(committed, true);
          } else {
            await rejected(auth.signup(email, password), "user_creation_failed", 500);
            assert.equal((await db.appAuthUsers.findMany({where: c => c.email.eq(email)})).length, 0);
            assert.equal(await rows.findById({id: failedUser}), null);
            assert.equal((await db.appAuthSessions.findMany({where: c => c.userId.eq(failedUser)})).length, 0);
            assert.equal(committed, false);
          }
          assert.deepEqual(await port.transaction(settings), before);
          await assert.rejects(async () => retained.query("select 1", []), /no longer active/);
        } finally { await port.close(); }
      });
    }
  }
  await t.test("state checks do not invoke user types or functions after a search path change", async () => {
    const port = open("host");
    const schema = `auth_state_${randomUUID().replaceAll("-", "")}`;
    try {
      await port.query(`create schema "${schema}"`, []);
      await port.query(`create sequence "${schema}".calls`, []);
      await port.query(`create function "${schema}".checked(pg_catalog.text) returns pg_catalog.bool
        language plpgsql as $$ begin perform pg_catalog.nextval('"${schema}".calls'); return true; end $$`, []);
      await port.query(`create domain "${schema}".text as pg_catalog.text check ("${schema}".checked(value))`, []);
      await port.query(`create function "${schema}".pg_backend_pid() returns pg_catalog.int4
        language sql as $$ select pg_catalog.pg_backend_pid() where "${schema}".checked('called') $$`, []);
      await port.query(`create function "${schema}".transaction_timestamp() returns pg_catalog.timestamptz
        language sql as $$ select pg_catalog.transaction_timestamp() where "${schema}".checked('called') $$`, []);
      await port.query(`create function "${schema}".current_setting(pg_catalog.text) returns pg_catalog.text
        language sql as $$ select pg_catalog.current_setting($1) where "${schema}".checked('called') $$`, []);
      await port.query(`create function "${schema}".json_build_array(variadic pg_catalog.text[]) returns pg_catalog.json
        language sql as $$ select '[]'::pg_catalog.json where "${schema}".checked('called') $$`, []);
      await port.transaction(async tx => {
        await tx.query(`set local search_path to "${schema}", pg_catalog, public`, []);
      });
      const [row] = await port.query(`select is_called from "${schema}".calls`, []);
      assert.equal(row.is_called, false);
    } finally {
      await port.query(`drop schema "${schema}" cascade`, []);
      await port.close();
    }
  });
  for (const mode of ["pg", "host", "raw"]) {
    for (const [setting, value] of changes.filter(([name]) => name.startsWith("default_"))) {
      await t.test(`${mode} resets masked ${setting} before reusing its connection`, async () => {
        const port = open(mode), email = `${randomUUID()}@example.test`;
        let committed = false;
        try {
          const before = await port.transaction(settings);
          const baseline = before[0][setting.slice("default_transaction_".length)];
          const auth = new Auth(port, [], Date.now, {async creating(tx) {
            await tx.query(`do $hook$ begin
              perform pg_catalog.set_config('${setting}', '${value}', false);
              perform pg_catalog.set_config('${setting}', '${baseline}', true);
            end $hook$`, []);
          }, async committed() { committed = true; }});
          await auth.signup(email, password);
          assert.equal(committed, true);
          assert.deepEqual(await port.transaction(settings), before);
        } finally { await port.close(); }
      });
    }
    await t.test(`${mode} hook helpers never resolve user functions through the search path`, async () => {
      const port = open(mode), schema = `hook_helpers_${randomUUID().replaceAll("-", "")}`;
      const path = `${schema}, public, pg_catalog`;
      try {
        await admin.query(`create schema ${schema}`, []);
        await admin.query(`create sequence ${schema}.marker`, []);
        await admin.query(`create function ${schema}.set_config(pg_catalog.text, pg_catalog.text, pg_catalog.bool)
          returns pg_catalog.text language plpgsql as $function$ begin
          perform pg_catalog.nextval('${schema}.marker');
          return pg_catalog.set_config($1, $2, $3); end $function$`, []);
        await admin.query(`create function ${schema}.current_setting(pg_catalog.text)
          returns pg_catalog.text language plpgsql as $function$ begin
          perform pg_catalog.nextval('${schema}.marker');
          return pg_catalog.current_setting($1); end $function$`, []);
        await port.query("select pg_catalog.set_config('search_path', $1, false)", [path]);
        const auth = new Auth(port, [], Date.now, {async creating(tx) {
          await tx.query("select pg_catalog.set_config('search_path', $1, false)", [path]);
        }});
        await port.transaction(tx => auth.creating(tx, {id: randomUUID(), email: "helper@example.test"}));
        const [row] = await port.query(`select is_called from ${schema}.marker`, []);
        assert.equal(row.is_called, false);
        const [state] = await port.query("select pg_catalog.current_setting('search_path') as path", []);
        assert.equal(state.path.includes(schema), false);
      } finally {
        await admin.query(`drop schema ${schema} cascade`, []);
        await port.close();
      }
    });
  }
  for (const verification of [false, true]) {
    const expected = await scenario("pg", verification);
    const actual = await scenario("host", verification);
    assert.deepEqual(actual, expected);
  }
  const boundaryCommands = dollarTags.flatMap(tag => [dollarBoundary(tag, "commit"), dollarBoundary(tag, "rollback")]);
  for (const command of [undefined, "begin", "commit", "rollback", ...boundaryCommands]) {
    const port = open("host"), email = `${randomUUID()}@example.test`;
    let committed = false, retained, failedUser;
    const auth = new Auth(port, [], Date.now, {async creating(tx, user) {
      retained = tx;
      failedUser = user.id;
      await new Repository(tx, hookTable).insert({id: user.id});
      if (command) await tx.query(command, []);
      throw new Error("Business write failed");
    }, async committed() { committed = true; }});
    try {
      await rejected(auth.signup(email, password), "user_creation_failed", 500);
      assert.equal((await db.appAuthUsers.findMany({where: c => c.email.eq(email)})).length, 0);
      assert.equal(await rows.findById({id: failedUser}), null);
      assert.equal((await db.appAuthSessions.findMany({where: c => c.userId.eq(failedUser)})).length, 0);
      assert.equal(committed, false);
      await assert.rejects(async () => retained.query("select 1", []), /no longer active/);
    } finally { await port.close(); }
  }
  const normal = open("host");
  try {
    await normal.transaction(async tx => {
      await tx.query("create function pg_temp.auth_hook_constant() returns integer language sql as $$select 1$$", []);
      await tx.query("do $$begin perform pg_temp.auth_hook_constant(); end$$", []);
      await tx.query("create procedure pg_temp.auth_hook_noop() language plpgsql as $$begin perform 1; end$$", []);
      await tx.query("call pg_temp.auth_hook_noop()", []);
    });
  } finally { await normal.close(); }
  const quoting = open("host");
  try {
    for (const tag of dollarTags) {
      const delimiter = `$${tag}$`, value = "$nested$";
      const [row] = await quoting.query(["select", delimiter, value, delimiter, "as quoted"].join(" "), []);
      assert.ok(row.quoted.trim() === value);
    }
  } finally { await quoting.close(); }
});
