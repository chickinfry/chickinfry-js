import assert from "node:assert/strict";
import { test } from "node:test";
import dns from "node:dns";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import pg from "pg";
import { createPostgresPort, cleanupBudgetMillis } from "../dist/postgres.js";
import { Auth } from "../dist/auth/runtime.js";

const localURL = "postgresql://user:private@127.0.0.1:5432/customer?sslmode=disable";

async function within(work, milliseconds) {
  let timer;
  try {
    return await Promise.race([work, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("Database work did not settle within its deadline.")), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

// The corpus lives in the CLI repo. It reaches us either through the JS CI
// layout (CLI pinned under .ci-work/cli, see cli-generator.ref) or through
// the CLI repo's own CI, which nests this checkout and keeps the corpus at
// its workspace root.
function postgresUrlCorpus() {
  const relative = "adapters/database/postgresql/testdata/urls.json";
  for (let dir = new URL("..", import.meta.url); ; dir = new URL("../", dir)) {
    for (const candidate of [new URL(`.ci-work/cli/${relative}`, dir), new URL(relative, dir)]) {
      if (existsSync(candidate)) return candidate;
    }
    if (dir.pathname === "/") break;
  }
  return null;
}

// The publish job has no CLI checkout, so the corpus test skips there; CI sets
// CHIK_REQUIRE_URL_CORPUS=1 so a missing corpus fails instead of skipping.
const urlCorpus = process.env.CHIK_POSTGRES_URL_CORPUS ?? postgresUrlCorpus();
const urlCorpusRequired = process.env.CHIK_REQUIRE_URL_CORPUS === "1";

test("Workers cancellation settles before connect and after close without uncaught exceptions", async t => {
  const fixture = `
    import assert from "node:assert/strict";
    import { createRequire } from "node:module";
    Object.defineProperty(globalThis, "navigator", {value:{userAgent:"Cloudflare-Workers"}, configurable:true});
    const require = createRequire(import.meta.url);
    const pg = require("pg"), {CloudflareSocket} = require("pg-cloudflare");
    assert.equal(require("pg/package.json").version, "8.23.0");
    assert.equal(require("pg-cloudflare/package.json").version, "1.4.0");
    const {createPostgresPort} = await import("./dist/postgres.js");
    let networkConnections = 0, socketClosures = 0;
    const uncaught = [], streams = [];
    process.on("uncaughtException", error => {
      process.exitCode = 1;
      uncaught.push({name:error.name, message:error.message});
      console.error(JSON.stringify({scenario, uncaught:uncaught.at(-1)}));
    });
    CloudflareSocket.prototype.connect = function () {
      networkConnections++;
      throw new Error("Network is forbidden in the lifecycle fixture.");
    };
    const end = pg.Client.prototype.end;
    pg.Client.prototype.end = function (...args) {
      streams.push(this.connection.stream);
      return end.apply(this, args);
    };
    const controller = new AbortController(), reason = new Error("Database work was cancelled.");
    const scenario = process.argv[1];
    if (scenario === "pre-aborted") {
      const base = "postgresql://fixture:fixture@database.example.test/customer?sslmode=verify-full";
      assert.throws(() => createPostgresPort(base+"&channel_binding=require"), {
        message:"The deployment runtime does not support PostgreSQL channel binding. Remove channel_binding=require and run chik update database (or chik add database for a new project); connections use sslmode=verify-full.",
      });
      for (const binding of ["prefer", "disable"]) await createPostgresPort(base+"&channel_binding="+binding).close();
    }
    if (scenario === "pre-aborted") controller.abort(reason);
    const port = createPostgresPort("postgresql://fixture:fixture@database.example.test/customer?sslmode=require", controller.signal, true);
    if (scenario === "already-closed") {
      await port.close();
      await assert.rejects(port.query("select 1", []), {message:"The database connection is closed."});
    }
    controller.abort(reason);
    await assert.rejects(port.query("select 1", []), error => error === reason);
    await Promise.all([port.close(), port.close()]);
    if (scenario === "late-open") {
      const stream = streams.at(-1);
      stream._cfSocket = {close() {
        socketClosures++;
        stream._cfSocket = null;
        stream.emit("close");
      }};
      stream.writable = true;
      stream.emit("connect");
      assert.doesNotThrow(() => { stream.destroy(); stream.destroy(); });
      assert.equal(socketClosures, 1);
      assert.equal(stream.writable, false);
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(uncaught, []);
    assert.equal(networkConnections, 0);
    assert.ok(streams.length > 0 && streams.every(stream => stream instanceof CloudflareSocket));
    console.log(JSON.stringify({scenario, querySettled:true, closeSettled:true, uncaughtExceptions:uncaught.length, networkConnections, socketClosures}));
  `;
  for (const scenario of ["pre-aborted", "lazy-abort", "already-closed", "late-open"]) {
    await t.test(scenario, () => {
      const output = execFileSync(process.execPath, ["--conditions=workerd", "--input-type=module", "-e", fixture, scenario],
        {cwd:new URL("..", import.meta.url), timeout:2_000, encoding:"utf8"});
      assert.deepEqual(JSON.parse(output), {scenario, querySettled:true, closeSettled:true, uncaughtExceptions:0, networkConnections:0,
        socketClosures:scenario === "late-open" ? 1 : 0});
      console.log(output.trim());
    });
  }
});

async function postgresPeer(t, fatal = false) {
  const clients = [], sockets = new Set(), startup = Promise.withResolvers();
  const connect = pg.Client.prototype.connect;
  t.mock.method(pg.Client.prototype, "connect", function (...args) {
    clients.push(this);
    return connect.apply(this, args);
  });
  const server = net.createServer({allowHalfOpen:true}, socket => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.once("data", () => {
      startup.resolve();
      if (fatal) {
        const fields = Buffer.from("SFATAL\0VFATAL\0C28P01\0MFixture authentication rejected\0\0");
        const header = Buffer.alloc(5);
        header[0] = 69;
        header.writeInt32BE(fields.length + 4, 1);
        socket.write(Buffer.concat([header, fields]));
      }
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    for (const client of clients) client.connection.stream.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  return {url:localURL.replace(":5432", `:${server.address().port}`), startup:startup.promise, clients};
}

test("startup abort settles connect, query and close without reconnecting", async t => {
  const peer = await postgresPeer(t), controller = new AbortController();
  const port = createPostgresPort(peer.url, controller.signal);
  const query = assert.rejects(port.query("select 1", []));
  await within(peer.startup, 1_000);
  const started = performance.now();
  controller.abort();
  await within(Promise.all([query, port.close()]), 1_000);
  await assert.rejects(port.query("select 2", []));
  assert.equal(peer.clients.length, 1);
  assert.equal(peer.clients[0].connection.stream.destroyed, true);
  console.log(JSON.stringify({scenario:"startup-abort",settled:true,milliseconds:performance.now()-started}));
});

test("abort forces a graceful close already waiting on an authentication-error half-open peer", async t => {
  const peer = await postgresPeer(t, true), controller = new AbortController();
  const port = createPostgresPort(peer.url, controller.signal);
  await within(assert.rejects(port.query("select 1", []), {code:"28P01"}), 1_000);
  let closed = false;
  const closing = port.close().then(() => { closed = true; });
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(closed, false);
  const started = performance.now();
  controller.abort();
  await within(closing, 1_000);
  assert.equal(peer.clients.length, 1);
  assert.equal(peer.clients[0].connection.stream.destroyed, true);
  console.log(JSON.stringify({scenario:"fatal-half-open-abort",settled:true,milliseconds:performance.now()-started}));
});

test("normal close forces a half-open peer within the cleanup deadline without an abort signal", async t => {
  const peer = await postgresPeer(t, true), port = createPostgresPort(peer.url);
  await within(assert.rejects(port.query("select 1", []), {code:"28P01"}), 1_000);
  const started = performance.now();
  await within(port.close(), cleanupBudgetMillis + 1_000);
  assert.equal(peer.clients[0].connection.stream.destroyed, true);
  console.log(JSON.stringify({scenario:"fatal-half-open-close",settled:true,milliseconds:performance.now()-started}));
});

test("startup abort and driver connect timeout settle in both timer orders", async t => {
  for (const abortFirst of [true, false]) {
    await t.test(abortFirst ? "abort-first" : "timeout-first", async t => {
      const peer = await postgresPeer(t), controller = new AbortController();
      let timer;
      if (abortFirst) timer = setTimeout(() => controller.abort(), cleanupBudgetMillis);
      const port = createPostgresPort(peer.url, controller.signal);
      const query = assert.rejects(port.query("select 1", []));
      await within(peer.startup, 1_000);
      if (!abortFirst) timer = setTimeout(() => controller.abort(), cleanupBudgetMillis);
      try {
        await within(query.then(() => port.close()), cleanupBudgetMillis + 1_000);
        assert.equal(peer.clients.length, 1);
        assert.equal(peer.clients[0].connection.stream.destroyed, true);
        console.log(JSON.stringify({scenario:abortFirst ? "abort-first-timeout" : "timeout-first-abort",settled:true}));
      } finally { clearTimeout(timer); }
    });
  }
});

test("revalidation retains native identity and checks revoked, expired, disabled and browser sessions", async () => {
  const sessionId = "22222222-2222-4222-8222-222222222222", userId = "11111111-1111-4111-8111-111111111111";
  const session = {id:sessionId, user_id:userId, token_hash:"a".repeat(64), transport:"native", user_session_version:1,
    created_at:"2029-01-01T00:00:00Z", expires_at:"2029-01-02T00:00:00Z", revoked_at:null,
    first_login_at:null, last_renewed_at:null};
  const user = {id:userId, email:"fixture@example.test", session_version:1, created_at:"2029-01-01T00:00:00Z",
    disabled_at:null, password_hash:null};
  const refresh = {id:"33333333-3333-4333-8333-333333333333", session_id:sessionId, token_hash:"b".repeat(64),
    created_at:session.created_at, expires_at:"2029-01-31T00:00:00Z", consumed_at:null};
  const port = {async query(sql) {
    return [sql.includes('"app_auth_sessions"') ? session : sql.includes('"app_auth_refresh_tokens"') ? refresh : user];
  }, async transaction(work) { return work(port); }};
  const auth = new Auth(port, [], () => Date.parse("2029-01-01T12:00:00Z"));
  assert.equal((await auth.revalidateSession(sessionId, userId)).id, userId);
  await assert.rejects(auth.session(sessionId), {code:"invalid_token"});
  await assert.rejects(auth.revalidateSession(sessionId, "33333333-3333-4333-8333-333333333333"), {code:"invalid_token"});
  for (const patch of [{transport:"browser"}, {revoked_at:session.created_at}, {expires_at:session.created_at},
    {user_session_version:0}]) {
    const original = {...session};
    Object.assign(session, patch);
    await assert.rejects(auth.revalidateSession(sessionId, userId), {code:"invalid_token"});
    Object.assign(session, original);
  }
  user.disabled_at = session.created_at;
  await assert.rejects(auth.revalidateSession(sessionId, userId), {code:"invalid_token"});
});

test("shared URL corpus preserves host, port, database and case-insensitive schemes", {
  skip: !urlCorpus && !urlCorpusRequired && "the CLI URL corpus is not checked out",
}, async t => {
  if (!urlCorpus) throw new Error("Set CHIK_POSTGRES_URL_CORPUS to the CLI checkout's adapters/database/postgresql/testdata/urls.json");
  const cases = JSON.parse(readFileSync(urlCorpus,"utf8"));
  const Client = pg.Client;
  let target;
  t.mock.method(pg,"Client",function (config) {
    target = {host:config.host,port:config.port,database:config.database};
    return new Client(config);
  });
  for (const c of cases.filter(c => /^(?:host-|scheme-)/.test(c.name))) {
    if (!c.valid) {
      assert.throws(() => createPostgresPort(c.url),{message:c.error ?? "A complete, permitted PostgreSQL URL is required."},c.name);
      continue;
    }
    const port = createPostgresPort(c.url);
    assert.deepEqual(target,c.target,c.name);
    await port.close();
  }
});

test("URL overrides, private destinations and IPv6 fail before a connection", () => {
  for (const host of ["127.0.0.1", "2130706433", "0x7f000001", "10.0.0.1", "100.64.0.1", "169.254.169.254",
    "[::1]", "[::ffff:127.0.0.1]", "[fc00::1]", "[2001:db8::1]", "localhost", "database.internal", "private.local"]) {
    assert.throws(() => createPostgresPort(localURL.replace("127.0.0.1", host), undefined, true),
      {message: /^(?:2130706433|0x7f000001)$/.test(host)
        ? "Unsupported PostgreSQL host. Use an ASCII hostname, a standard dotted-decimal IPv4 address, or a bracketed IPv6 address."
        : "A complete, permitted PostgreSQL URL is required."});
  }
  for (const path of ["/wrong/../target", "/wrong/%2e%2e/target", "/wrong/.%2E/target", "/./target"]) {
    assert.throws(() => createPostgresPort(localURL.replace("/customer?",path+"?")),
      {message:"A complete, permitted PostgreSQL URL is required."});
  }
  for (const host of ["db.test,other.test", "db%2etest", "db%25test"]) {
    assert.throws(() => createPostgresPort(localURL.replace("127.0.0.1",host)),
      {message:"Unsupported PostgreSQL host. Use an ASCII hostname, a standard dotted-decimal IPv4 address, or a bracketed IPv6 address."});
  }
  for (const query of ["host=127.0.0.1", "port=5432", "user=owner", "password=private", "sslcert=/tmp/key",
    "sslrootcert=/tmp/ca", "options=-c+search_path=public", "sslmode=require&sslmode=disable", "sslmode=invalid"]) {
    const name = new URLSearchParams(query).keys().next().value;
    assert.throws(() => createPostgresPort(localURL.replace("sslmode=disable", query)),
      {message:name === "sslmode" ? "A complete, permitted PostgreSQL URL is required." : "Unsupported PostgreSQL connection option. Only sslmode and channel_binding are allowed."});
  }
  for (const key of ["disposable", "%64isposable"]) {
    assert.throws(() => createPostgresPort(localURL+"&"+key+"=ignored"), error => {
      assert.equal(error.message, "Unsupported PostgreSQL connection option. Only sslmode and channel_binding are allowed.");
      assert.doesNotMatch(error.message, /disposable/);
      return true;
    });
  }
  assert.throws(() => createPostgresPort(localURL+"&channel_binding=unknown"), {message:'Invalid PostgreSQL connection option "channel_binding".'});
  assert.throws(() => createPostgresPort(localURL+"&channel_binding=require&channel_binding=disable"), {message:'Invalid PostgreSQL connection option "channel_binding".'});
  assert.throws(() => createPostgresPort(localURL+"&https%3A%2F%2Fprivate=ignored"), {message:"Unsupported PostgreSQL connection option. Only sslmode and channel_binding are allowed."});
});

test("Neon default and pooled URL options preserve channel binding without exposing credentials", async () => {
  for (const endpoint of ["ep-fixture", "ep-fixture-pooler"]) {
    for (const binding of ["require", "prefer", "disable"]) {
      await createPostgresPort(`postgresql://role:fixture-secret@${endpoint}.us-east-1.aws.neon.tech/customer?sslmode=require&channel_binding=${binding}`).close();
    }
  }
  assert.throws(() => createPostgresPort(localURL+"&channel_binding=require"), {message:"channel_binding=require needs TLS. Use sslmode=verify-full."});
});

test("Node TLS negotiates required PLUS and rejects a SCRAM server without PLUS", {
  skip: !process.env.CHIK_TEST_DATABASE_CA,
}, () => {
  const fixture = `
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import net from "node:net";
    import tls from "node:tls";
    import pg from "pg";
    import {createPostgresPort} from "./dist/postgres.js";
    const original = new URL(process.env.CHIK_TEST_DATABASE_URL);
    const sockets = new Set(), mechanisms = [], clients = [];
    const connect = pg.Client.prototype.connect;
    pg.Client.prototype.connect = function (...args) {
      clients.push(this);
      const send = this.connection.sendSASLInitialResponseMessage.bind(this.connection);
      this.connection.sendSASLInitialResponseMessage = (mechanism, ...args) => {
        mechanisms.push(mechanism); return send(mechanism, ...args);
      };
      return connect.apply(this, args);
    };
    const cert = fs.readFileSync(process.env.CHIK_TEST_DATABASE_CA), key = fs.readFileSync(process.env.CHIK_TEST_DATABASE_KEY);
    const proxy = net.createServer(socket => {
      sockets.add(socket); socket.on("error", () => {});
      socket.once("data", request => {
        assert.equal(request.readInt32BE(4), 80877103);
        socket.write("S");
        const secure = new tls.TLSSocket(socket, {isServer:true, secureContext:tls.createSecureContext({cert,key})});
        const upstream = net.connect({host:original.hostname, port:Number(original.port)});
        sockets.add(secure); sockets.add(upstream);
        secure.on("error", () => upstream.destroy()); upstream.on("error", () => secure.destroy());
        secure.on("close", () => upstream.destroy()); upstream.on("close", () => secure.destroy());
        secure.pipe(upstream).pipe(secure);
      });
    });
    await new Promise(resolve => proxy.listen(0, "127.0.0.1", resolve));
    try {
      for (const [binding, expected] of [["require","SCRAM-SHA-256-PLUS"],["prefer","SCRAM-SHA-256-PLUS"],["disable","SCRAM-SHA-256"]]) {
        const url = new URL(original); url.searchParams.set("sslmode", "verify-full"); url.searchParams.set("channel_binding", binding);
        const port = createPostgresPort(url.toString());
        try { await port.query("select 1", []); assert.equal(mechanisms.at(-1), expected); }
        finally { await port.close(); }
      }
      const url = new URL(original); url.port = String(proxy.address().port); url.searchParams.set("sslmode", "verify-full");
      url.searchParams.set("channel_binding", "require");
      const required = createPostgresPort(url.toString()), sent = mechanisms.length;
      try {
        await assert.rejects(required.query("select 1", []), {message:"Could not complete channel_binding=require authentication. Check that the server offers SCRAM-SHA-256-PLUS over TLS."});
        assert.equal(mechanisms.length, sent);
        await assert.rejects(required.query("select 1", []), /closed/);
      } finally { await required.close(); }
      url.searchParams.set("channel_binding", "prefer");
      const preferred = createPostgresPort(url.toString());
      try { await preferred.query("select 1", []); assert.equal(mechanisms.at(-1), "SCRAM-SHA-256"); }
      finally { await preferred.close(); }
      assert.equal(clients.length, 5);
      console.log(JSON.stringify({NodeTLS:"passed", require:"SCRAM-SHA-256-PLUS", noPlus:"rejected-before-response", prefer:"fallback-allowed", connections:clients.length}));
      for (const mode of ["plus-without-proof", "plus-early-ready", "invalid-server-signature"]) {
        let initial = 0, responses = 0, queries = 0;
        const auth = (code, data = Buffer.alloc(0)) => {
          const packet = Buffer.alloc(9+data.length); packet[0] = 82;
          packet.writeUInt32BE(8+data.length,1); packet.writeUInt32BE(code,5); data.copy(packet,9); return packet;
        };
        const ready = Buffer.from([90,0,0,0,5,73]);
        const attacker = net.createServer(socket => {
          sockets.add(socket); socket.on("error", () => {});
          socket.once("data", request => {
            assert.equal(request.readInt32BE(4),80877103); socket.write("S");
            const secure = new tls.TLSSocket(socket,{isServer:true,secureContext:tls.createSecureContext({cert,key})});
            sockets.add(secure); secure.on("error", () => {});
            secure.once("data", () => {
              secure.write(auth(10,Buffer.from("SCRAM-SHA-256-PLUS\\0SCRAM-SHA-256\\0\\0")));
              let buffered = Buffer.alloc(0);
              secure.on("data", chunk => {
                buffered = Buffer.concat([buffered,chunk]);
                while (buffered.length >= 5 && buffered.length >= 1+buffered.readUInt32BE(1)) {
                  const length = 1+buffered.readUInt32BE(1), packet = buffered.subarray(0,length);
                  buffered = buffered.subarray(length);
                  if (packet[0] === 112 && initial === 0) {
                    initial++;
                    if (mode === "invalid-server-signature") {
                      const nonce = /r=([^,]+)/.exec(packet.toString())?.[1];
                      secure.write(auth(11,Buffer.from("r="+nonce+"fixtureServer,s=Zml4dHVyZQ==,i=4096")));
                    } else secure.write(mode === "plus-early-ready" ? ready : Buffer.concat([auth(0),ready]));
                  } else if (packet[0] === 112) {
                    responses++;
                    secure.write(Buffer.concat([auth(12,Buffer.from("v="+Buffer.alloc(32).toString("base64"))),auth(0),ready]));
                  } else if (packet[0] === 81) {
                    queries++;
                    secure.write(Buffer.concat([Buffer.from([67,0,0,0,13]),Buffer.from("SELECT 1\\0"),ready]));
                  }
                }
              });
            });
          });
        });
        await new Promise(resolve => attacker.listen(0,"127.0.0.1",resolve));
        const attackURL = new URL(original); attackURL.port = String(attacker.address().port);
        attackURL.searchParams.set("sslmode","verify-full"); attackURL.searchParams.set("channel_binding","require");
        const port = createPostgresPort(attackURL.toString());
        let accepted = false;
        try { await port.query("select 1",[]); accepted = true; } catch {}
        finally { await port.close(); }
        await new Promise(resolve => attacker.close(resolve));
        console.log(JSON.stringify({mode,accepted,initialSASLResponses:initial,saslResponses:responses,queries}));
        assert.equal(accepted,false); assert.equal(queries,0); assert.equal(initial,1);
        assert.equal(responses,mode === "invalid-server-signature" ? 1 : 0);
      }
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => proxy.close(resolve));
    }
  `;
  const output = execFileSync(process.execPath, ["--input-type=module", "-e", fixture], {cwd:new URL("..", import.meta.url),
    env:{...process.env, NODE_EXTRA_CA_CERTS:process.env.CHIK_TEST_DATABASE_CA}, timeout:10_000, encoding:"utf8"});
  console.log(output.trim());
});

test("one lazy connection serializes queries around a transaction and closes once", async t => {
  let connects = 0, closes = 0;
  const queries = [];
  t.mock.method(pg.Client.prototype, "connect", function (callback) { connects++; callback(); });
  t.mock.method(pg.Client.prototype, "query", async sql => { queries.push(sql); return {command: sql.toUpperCase(), rows: [{id: 1}]}; });
  t.mock.method(pg.Client.prototype, "end", async () => { closes++; });
  const port = createPostgresPort(localURL);
  assert.equal(connects, 0);
  await Promise.all([port.query("first", []), port.transaction(async tx => {
    await tx.query("inside", []);
    await assert.rejects(async () => tx.transaction(async () => {}), /Nested transactions/);
  }), port.query("after", [])]);
  assert.equal(connects, 1);
  assert.deepEqual(queries, ["first", "begin", "inside", "commit", "after"]);
  await Promise.all([port.close(), port.close()]);
  assert.equal(closes, 1);
  await assert.rejects(port.query("late", []), /closed/);
});

test("a failed commit query keeps its unknown outcome and closes the connection", async t => {
  const cause = new Error("Connection lost during commit.");
  let closes = 0;
  t.mock.method(pg.Client.prototype, "connect", callback => callback());
  t.mock.method(pg.Client.prototype, "query", async sql => {
    if (sql === "commit") throw cause;
    return {rows: []};
  });
  t.mock.method(pg.Client.prototype, "end", async () => { closes++; });
  const port = createPostgresPort(localURL);
  try {
    await assert.rejects(port.transaction(async () => "ok"), error => {
      assert.equal(error.message, "Transaction commit outcome is unknown.");
      assert.equal(error.cause, cause);
      return true;
    });
    await assert.rejects(port.query("select 1", []), /closed/);
  } finally { await port.close(); }
  assert.equal(closes, 1);
});

test("a failed connect cannot allocate a replacement connection", async t => {
  let connects = 0;
  t.mock.method(pg.Client.prototype, "connect", callback => { connects++; callback(new Error("failed")); });
  t.mock.method(pg.Client.prototype, "end", async () => {});
  const port = createPostgresPort(localURL);
  try {
    await assert.rejects(port.query("first", []), /failed/);
    await assert.rejects(port.query("retry", []), /failed/);
    assert.equal(connects, 1);
  } finally { await port.close(); }
});

test("abort and close share one termination", async t => {
  let closes = 0;
  t.mock.method(pg.Client.prototype, "end", async () => { closes++; });
  const controller = new AbortController();
  const port = createPostgresPort(localURL, controller.signal);
  controller.abort();
  await Promise.all([port.close(), port.close()]);
  assert.equal(closes, 1);
});

test("DNS resolving to private IPv4 or IPv6 never reaches the target socket", async t => {
  for (const [address, family] of [["127.0.0.1", 4], ["::1", 6], ["::ffff:127.0.0.1", 6]]) {
    const lookup = t.mock.method(dns, "lookup", (_host, _options, callback) => {
      callback(null, [{address, family}]);
    });
    let accepted = 0;
    const server = net.createServer(socket => { accepted++; socket.destroy(); });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const port = createPostgresPort(`postgresql://user:private@database.example.test:${server.address().port}/customer`, undefined, true);
    try {
      await assert.rejects(port.query("select 1", []), /blocked|invalid|ENETUNREACH/);
      assert.equal(accepted, 0);
    } finally {
      await port.close();
      await new Promise(resolve => server.close(resolve));
      lookup.mock.restore();
    }
  }
});

test("PostgreSQL uses one backend across concurrent ORM queries and transaction rollback", {
  skip: !process.env.CHIK_TEST_DATABASE_URL,
}, async () => {
  const port = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL);
  try {
    const pids = await Promise.all(Array.from({length: 8}, () => port.query("select pg_backend_pid() as pid", [])));
    assert.equal(new Set(pids.map(rows => rows[0].pid)).size, 1);
    const pid = pids[0][0].pid;
    let expired;
    await assert.rejects(port.transaction(async tx => {
      expired = tx;
      assert.equal((await tx.query("select pg_backend_pid() as pid", []))[0].pid, pid);
      await tx.query("select 1/0", []);
    }), {code: "22012"});
    await assert.rejects(expired.query("select 1", []), /no longer active/);
    assert.equal((await port.query("select pg_backend_pid() as pid", []))[0].pid, pid);
  } finally { await port.close(); }
});

test("PostgreSQL rejects a rolled-back commit and still commits a healthy transaction", {
  skip: !process.env.CHIK_TEST_DATABASE_URL,
}, async () => {
  const port = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL);
  try {
    await port.query("create temporary table commit_check (id integer primary key)", []);
    await assert.rejects(port.transaction(async tx => {
      await tx.query("insert into commit_check values (1)", []);
      await assert.rejects(tx.query("insert into commit_check values (1)", []), {code: "23505"});
      return "ok";
    }), error => {
      assert.equal(error.message, "Transaction commit failed.");
      assert.equal(error.code, undefined);
      return true;
    });
    assert.deepEqual(await port.query("select id from commit_check", []), []);
    assert.equal(await port.transaction(async tx => {
      await tx.query("insert into commit_check values (2)", []);
      return "ok";
    }), "ok");
    assert.deepEqual(await port.query("select id from commit_check", []), [{id: 2}]);
  } finally { await port.close(); }
});

test("TLS failure has no plaintext fallback and abort closes a real query", {
  skip: !process.env.CHIK_TEST_DATABASE_URL,
}, async () => {
  const verified = new URL(process.env.CHIK_TEST_DATABASE_URL);
  verified.searchParams.set("sslmode", "verify-full");
  const secure = createPostgresPort(verified.toString());
  try { await assert.rejects(secure.query("select 1", []), /SSL|certificate/); }
  finally { await secure.close(); }
  const controller = new AbortController();
  const port = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL, controller.signal);
  await port.query("select 1", []);
  const started = Date.now();
  const timer = setTimeout(() => controller.abort(), 100);
  try {
    await assert.rejects(port.query("select pg_sleep(30)", []));
    await port.close();
    assert.ok(Date.now() - started < 2_000);
    await assert.rejects(port.query("select 1", []));
  } finally { clearTimeout(timer); await port.close(); }
});
