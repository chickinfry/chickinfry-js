import {strict as assert} from "node:assert";
import {randomBytes, randomUUID} from "node:crypto";
import {mkdir, mkdtemp, readFile, readdir, writeFile, stat, chmod, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {spawn} from "node:child_process";
import {test} from "node:test";
import {createServer} from "node:http";
import {HTTP, BrowserHTTP, OperationError} from "../src/http.js";
import type {TransportOptions} from "../src/http.js";

const origin = "https://api.example.com";
const scopeKey = Symbol.for("chickinfry.store.scope.v1");
const scoped = (screen = "screen-a", extra: TransportOptions = {}): TransportOptions => {
  const options = {...extra};
  Reflect.set(options, scopeKey, {appId: "test-app", projectId: "test-project", origin, screen});
  return options;
};
const credential = () => ({access_token: randomBytes(32).toString("base64url"),
  refresh_token: randomBytes(32).toString("base64url"), user_id: randomUUID(), session_id: randomUUID(),
  expires_at: new Date(Date.now() + 900_000).toISOString(),
  refresh_expires_at: new Date(Date.now() + 86_400_000).toISOString()});
const unavailable = (error: unknown) => error instanceof OperationError &&
  error.code === "device_storage_unavailable" && error.status === 0;
const originalFetch = globalThis.fetch;
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => {resolve = done;});
  return {promise, resolve};
};

async function child(phase: string, dir: string, flags: string[] = []): Promise<void> {
  const process = spawn(globalThis.process.execPath, [...flags, fileURLToPath(import.meta.url), phase, dir], {
    env: {HOME: /^(default-|bearer-|late-disabled)/.test(phase) ? join(dir, "home") : globalThis.process.env.HOME!,
      XDG_STATE_HOME: join(dir, "state"), PATH: dirname(globalThis.process.execPath),
      TMPDIR: tmpdir(), LANG: "en_US.UTF-8"}, stdio: ["ignore", "pipe", "pipe"],
  });
  process.stdout.resume();
  process.stderr.resume();
  const code = await new Promise<number | null>((resolve, reject) => {
    process.once("error", reject); process.once("exit", resolve);
  });
  assert.ok(code === 0, `Process phase ${phase} failed.`);
}

if (process.argv[2]) {
  const requestedPhase = process.argv[2], phase = requestedPhase.replace(/^default-/, ""), dir = process.argv[3];
  try {
    const session = JSON.parse(await readFile(join(dir, "server.json"), "utf8"));
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      const authorization = new Headers(init?.headers).get("authorization");
      if (operation === "/auth.signin") return Response.json(session);
      if (operation === "/auth.logout") return Response.json({status: "ok"});
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt: session.attempt});
      if (operation === "/auth.send_verification_email") {
        const input = JSON.parse(String(init?.body));
        return Response.json({accepted: input.attempt === session.attempt});
      }
      return authorization === "Bearer " + session.access_token ? Response.json({ok: true}) :
        Response.json({error: "unauthenticated"}, {status: 401});
    };
    const transport = phase === "bearer-string" ? new HTTP(origin, session.access_token) :
      phase === "bearer-options" ? new HTTP(origin, {token: session.access_token, persist: {dir: join(dir, "ignored")}}) :
      new HTTP(origin, requestedPhase.startsWith("default-") ? scoped() : phase === "late-disabled" ? {persist: false} : {persist: {dir: join(dir, "device")}});
    if (phase.startsWith("bearer-") || phase === "late-disabled") {
      Reflect.set(transport, scopeKey, Reflect.get(scoped(), scopeKey));
      if (phase === "late-disabled") {
        await transport.invoke("auth.signup", {email: "test@example.com"});
        const value = await transport.invoke("auth.send_verification_email", {}) as {accepted: boolean};
        if (!value.accepted) throw new Error("Disabled device lost its current attempt.");
      } else {await transport.invoke("auth.signin", {}); await transport.invoke("notes.list", {});}
    }
    if (phase === "load-failure") await assert.rejects(transport.invoke("auth.signin", {}), unavailable);
    if (phase === "signin") await transport.invoke("auth.signin", {});
    if (phase === "signup") await transport.invoke("auth.signup", {email: "test@example.com"});
    if (phase === "resend") {
      const value = await transport.invoke("auth.send_verification_email", {}) as {accepted: boolean};
      if (!value.accepted) throw new Error("Signup screen was not restored.");
    }
    if (phase === "restore") await transport.invoke("notes.list", {});
    if (phase === "logout") await transport.invoke("auth.logout", {});
    if (phase === "empty") {
      let rejected = false;
      try { await transport.invoke("notes.list", {}); }
      catch (error) { rejected = error instanceof OperationError && error.status === 401; }
      if (!rejected) throw new Error("A signed-out session was restored.");
    }
  } catch { process.exitCode = 1; }
} else {
  test("restores a session and signup screen across processes, then deletes them on logout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-process-"));
    try {
      await writeFile(join(dir, "server.json"), JSON.stringify({...credential(), attempt: randomUUID()}), {mode: 0o600});
      for (const phase of ["signin", "restore", "signup", "resend", "logout", "empty"]) await child(phase, dir);
      for (const phase of ["default-signin", "default-restore", "default-logout", "default-empty"]) await child(phase, dir);
      const deviceDir = join(dir, "device");
      if (process.platform !== "win32") {
        assert.ok(((await stat(deviceDir)).mode & 0o777) === 0o700);
        for (const name of await readdir(deviceDir)) assert.ok(((await stat(join(deviceDir, name))).mode & 0o777) === 0o600);
      }
      const files = await readdir(deviceDir);
      assert.ok(!files.some(name => name.endsWith(".tmp")));
      const text = await readFile(join(deviceDir, files.find(name => name.endsWith(".json"))!), "utf8");
      const issued = JSON.parse(await readFile(join(dir, "server.json"), "utf8"));
      assert.ok(!text.includes(issued.access_token) && !text.includes(issued.refresh_token) &&
        !text.includes(issued.attempt) && !text.includes("test@example.com"));
    } finally { await rm(dir, {recursive: true}); }
  });

  test("accepts transport options without changing explicit bearer or custom store ownership", async () => {
    const access = credential().access_token;
    let authorization: string | null = null;
    globalThis.fetch = async (_url, init) => {
      authorization = new Headers(init?.headers).get("authorization");
      return Response.json({ok: true});
    };
    try {
      await new HTTP(origin, {token: access, persist: false}).invoke("notes.list", {});
      assert.ok(authorization === "Bearer " + access);
      await new HTTP(origin, {persist: false}).invoke("notes.list", {});
      assert.ok(authorization === null);
      assert.throws(() => new BrowserHTTP(origin, {persist: {dir: "device"}}), unavailable);
      assert.throws(() => new HTTP(origin, {persist: {dir: ""}}), unavailable);
      assert.throws(() => new HTTP(origin, {[scopeKey]: {}} as never), unavailable);
    } finally { globalThis.fetch = originalFetch; }
  });

  test("preserves corrupt records and newer versions instead of restoring an empty session", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-corrupt-"));
    globalThis.fetch = async () => Response.json(credential());
    try {
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      for (const [text, code] of [["{", "device_storage_corrupt"],
        [JSON.stringify({version: 2}), "device_storage_version_unsupported"]]) {
        await writeFile(file, text, {mode: 0o600});
        await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("notes.list", {}),
          error => error instanceof OperationError && error.code === code);
        assert.ok((await readFile(file, "utf8")) === text);
      }
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("refuses unsafe existing file permissions before sending an authentication request", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-permissions-"));
    let calls = 0;
    globalThis.fetch = async () => { calls++; return Response.json(credential()); };
    try {
      await chmod(dir, 0o777);
      await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {}), unavailable);
      const nested = join(dir, "private"); await mkdir(nested, {mode: 0o700});
      await assert.rejects(new HTTP(origin, {persist: {dir: nested}}).invoke("auth.signin", {}), unavailable);
      assert.ok(calls === 0);
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  test("restores only the current browser screen without storing credentials", async () => {
    const values = new Map<string, string>();
    const storage = {getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value); }};
    Object.defineProperty(globalThis, "localStorage", {value: storage, configurable: true});
    const attempts = [randomUUID(), randomUUID()];
    let signup = 0;
    const sent: boolean[] = [];
    globalThis.fetch = async (url, init) => {
      if (new URL(String(url)).pathname === "/auth.signup") return Response.json({accepted: true, attempt: attempts[signup++]});
      const input = JSON.parse(String(init?.body));
      sent.push(input.attempt === attempts[sent.length]);
      assert.ok(!new Headers(init?.headers).has("authorization"));
      return Response.json({accepted: true});
    };
    try {
      await new BrowserHTTP(origin, scoped("a")).invoke("auth.signup", {email: "a@example.com", password: randomUUID()});
      await new BrowserHTTP(origin, scoped("b")).invoke("auth.signup", {email: "b@example.com", password: randomUUID()});
      await new BrowserHTTP(origin, scoped("a")).invoke("auth.send_verification_email", {});
      await new BrowserHTTP(origin, scoped("b")).invoke("auth.send_verification_email", {});
      assert.ok(sent.length === 2 && sent.every(Boolean));
      const text = [...values.values()].join("");
      assert.ok(!/password|refreshToken|accessToken|cookie/i.test(text));
    } finally { globalThis.fetch = originalFetch; Reflect.deleteProperty(globalThis, "localStorage"); }
  });

  test("does not install a verification response arriving after logout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-late-"));
    const started = deferred<void>(), response = deferred<Response>();
    const attempt = randomUUID();
    globalThis.fetch = async url => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt});
      if (operation === "/auth.verify_email") { started.resolve(); return response.promise; }
      return Response.json({status: "ok"});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signup", {email: "a@example.com"});
      const pending = client.invoke("auth.verify_email", {});
      await started.promise;
      await new HTTP(origin, {persist: {dir}}).invoke("auth.logout", {});
      response.resolve(Response.json(credential()));
      await pending;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("retries only local writes when another screen saves an attempt during verification", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-verify-"));
    const started = deferred<void>(), response = deferred<Response>();
    const firstAttempt = randomUUID(), secondAttempt = randomUUID();
    let verifies = 0, preserved = false;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname, input = JSON.parse(String(init?.body));
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt: input.email === "a@example.com" ? firstAttempt : secondAttempt});
      if (operation === "/auth.verify_email") { verifies++; started.resolve(); return response.promise; }
      preserved = input.attempt === secondAttempt; return Response.json({accepted: true});
    };
    try {
      const first = new HTTP(origin, scoped("a", {persist: {dir}}));
      await first.invoke("auth.signup", {email: "a@example.com"});
      const pending = first.invoke("auth.verify_email", {});
      await started.promise;
      await new HTTP(origin, scoped("b", {persist: {dir}})).invoke("auth.signup", {email: "b@example.com"});
      response.resolve(Response.json(credential())); await pending;
      await new HTTP(origin, scoped("b", {persist: {dir}})).invoke("auth.send_verification_email", {});
      assert.ok(verifies === 1 && preserved);
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("drops an E1 memory session for one call when another process changes the auth generation", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-memory-"));
    const sessions = [credential(), credential(), credential()];
    let signin = 0, protectedCalls = 0;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") {
        const value = sessions[signin++];
        if (signin === 2) await chmod(dir, 0o500);
        return Response.json(value);
      }
      if (operation === "/auth.logout") return Response.json({status: "ok"});
      protectedCalls++;
      return new Headers(init?.headers).get("authorization") === "Bearer " + sessions[signin - 1].access_token ?
        Response.json({ok: true}) : Response.json({error: "invalid_token"}, {status: 401});
    };
    try {
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      const memory = new HTTP(origin, {persist: {dir}});
      await memory.invoke("auth.signin", {});
      await memory.invoke("notes.list", {});
      await assert.rejects(memory.invoke("auth.logout", {}), unavailable);
      const blockedCalls = protectedCalls;
      await assert.rejects(memory.invoke("notes.list", {}), error => error instanceof OperationError && error.code === "unauthenticated");
      assert.ok(protectedCalls === blockedCalls);
      await chmod(dir, 0o700);
      await new HTTP(origin, {persist: {dir}}).invoke("auth.logout", {});
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      const before = protectedCalls;
      await assert.rejects(memory.invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
      assert.ok(protectedCalls === before);
      await memory.invoke("notes.list", {});
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  for (const duringCleanup of [false, true]) test(`rejects an E1 account change ${duringCleanup ? "during" : "before"} expired attempt cleanup`, {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-memory-expiry-"));
    const sessions = [credential(), credential(), credential()];
    let signins = 0;
    const accounts: string[] = [];
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") {
        const session = sessions[signins++];
        if (signins === 2) await chmod(dir, 0o500);
        return Response.json(session);
      }
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt: randomUUID()});
      const authorization = new Headers(init?.headers).get("authorization");
      const session = sessions.find(value => authorization === "Bearer " + value.access_token);
      accounts.push(session?.user_id ?? "anonymous");
      return Response.json({user: session?.user_id});
    };
    try {
      const options = {persist: {dir}};
      await new HTTP(origin, options).invoke("auth.signin", {});
      await new HTTP(origin, options).invoke("auth.signup", {email: "pending@example.com"});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const attempt = JSON.parse(await readFile(file, "utf8")).attempts[0];
      const expire = async () => {
        const bundle = JSON.parse(await readFile(file, "utf8"));
        bundle.attempts = [{...attempt, startedAt: Date.now() - 86_400_000}];
        bundle.selections[attempt.screen] = attempt.sequence;
        await writeFile(file, JSON.stringify(bundle), {mode: 0o600});
      };
      const client = new HTTP(origin, options);
      await client.invoke("auth.signin", {});
      await client.invoke("notes.list", {});
      assert.ok(accounts.length === 1 && accounts[0] === sessions[1].user_id);
      accounts.length = 0;
      await chmod(dir, 0o700);
      if (duringCleanup) {
        await expire();
        const device = Reflect.get(client, "device"), read = device.read.bind(device);
        let reads = 0;
        device.read = async () => {
          const value = await read();
          if (++reads === 1) {await new HTTP(origin, options).invoke("auth.signin", {}); await expire();}
          return value;
        };
      } else {
        await new HTTP(origin, options).invoke("auth.signin", {});
        await expire();
      }
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.code === "unauthenticated");
      assert.ok(accounts.length === 0);
      const value = await client.invoke("notes.list", {}) as {user: string};
      assert.ok(accounts.length === 1 && accounts[0] === sessions[2].user_id && value.user === sessions[2].user_id);
    } finally {globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true});}
  });

  test("sends public operations without credentials after logout while protected calls stay blocked", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-public-"));
    const session = credential(); let calls = 0;
    const anonymous: boolean[] = [];
    globalThis.fetch = async (url, init) => {
      calls++;
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(session);
      if (operation === "/auth.logout") return Response.json({status: "ok"});
      anonymous.push(!new Headers(init?.headers).has("authorization"));
      return Response.json({account: "anonymous"});
    };
    try {
      const client = new HTTP(origin, scoped("a", {persist: {dir}}));
      Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      await client.invoke("auth.signin", {}); await client.invoke("auth.logout", {});
      const before = calls;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.code === "unauthenticated");
      assert.ok(calls === before);
      for (const names of [[], ["Catalog.list_items"], ["list_items"], ["other.list_items"]]) {
        Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), names);
        await assert.rejects(client.invoke("catalog.list_items", {}), error => error instanceof OperationError && error.code === "unauthenticated");
        assert.ok(calls === before);
      }
      Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      const restored = new HTTP(origin, scoped("b", {persist: {dir}}));
      Reflect.set(restored, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      const options = scoped("c", {persist: {dir}});
      Reflect.set(options, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      for (const current of [client, restored, new HTTP(origin, options)]) {
        const value = await current.invoke("catalog.list_items", {}) as {account: string};
        assert.ok(value.account === "anonymous");
      }
      assert.ok(calls === before + 3 && anonymous.length === 3 && anonymous.every(Boolean));
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("starts public authentication without expired credentials on the first request", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-expired-session-"));
    const expired = {...credential(), expires_at: new Date(Date.now() - 120_000).toISOString(),
      refresh_expires_at: new Date(Date.now() - 60_000).toISOString()};
    const current = credential(); let calls = 0;
    const anonymous: boolean[] = [], accounts: string[] = [];
    globalThis.fetch = async (url, init) => {
      calls++;
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin" && JSON.parse(String(init?.body)).seed) return Response.json(expired);
      if (["/auth.signin", "/auth.request_password_reset", "/catalog.list_items"].includes(operation)) {
        anonymous.push(!new Headers(init?.headers).has("authorization"));
        return Response.json(operation === "/auth.signin" ? current : {accepted: true});
      }
      const authenticated = new Headers(init?.headers).get("authorization") === "Bearer " + current.access_token;
      accounts.push(authenticated ? current.user_id : "anonymous");
      return Response.json({user: authenticated ? current.user_id : "anonymous"});
    };
    try {
      for (const operation of ["auth.signin", "auth.request_password_reset", "catalog.list_items", "notes.list", "auth.refresh"]) {
        await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {seed: true});
        const client = new HTTP(origin, {persist: {dir}});
        Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
        const before = calls;
        if (operation === "notes.list" || operation === "auth.refresh") {
          await assert.rejects(client.invoke(operation, {refresh_token: expired.refresh_token}), error => error instanceof OperationError && error.status === 401);
          assert.ok(calls === before);
        } else {
          await client.invoke(operation, {});
          assert.ok(calls === before + 1 && anonymous.at(-1) === true);
          if (operation === "auth.signin") {
            const value = await client.invoke("notes.list", {}) as {user: string};
            assert.ok(calls === before + 2 && value.user === current.user_id && accounts.at(-1) === current.user_id);
          }
        }
      }
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("keeps successful refresh credentials in memory while a failed commit blocks restart reuse", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-refresh-"));
    const initial = credential(), updated = {...credential(), user_id: initial.user_id, session_id: initial.session_id};
    let refreshes = 0;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(initial);
      if (operation === "/auth.refresh") { refreshes++; await chmod(dir, 0o500); return Response.json(updated); }
      return new Headers(init?.headers).get("authorization") === "Bearer " + updated.access_token ?
        Response.json({ok: true}) : Response.json({error: "invalid_token"}, {status: 401});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {}); await client.invoke("notes.list", {});
      await client.invoke("notes.list", {});
      await chmod(dir, 0o700);
      await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
      assert.ok(refreshes === 1);
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  test("does not send an account switch when its durable marker cannot be written", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-marker-"));
    let calls = 0;
    globalThis.fetch = async () => { calls++; return Response.json(credential()); };
    try {
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      await chmod(dir, 0o500);
      await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {}), unavailable);
      assert.ok(calls === 1);
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  test("prunes expired attempts at the 24 hour boundary without extending them on resend", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-expiry-"));
    const realNow = Date.now, start = realNow();
    const attempt = randomUUID(); let selected = false;
    Date.now = () => start;
    globalThis.fetch = async (url, init) => {
      if (new URL(String(url)).pathname === "/auth.signup") return Response.json({accepted: true, attempt});
      selected = JSON.parse(String(init?.body)).attempt !== undefined;
      return Response.json({accepted: true});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signup", {email: "a@example.com"});
      Date.now = () => start + 86_400_000;
      await client.invoke("auth.send_verification_email", {});
      assert.ok(!selected);
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      assert.ok(JSON.parse(await readFile(file, "utf8")).attempts.length === 0);
    } finally { Date.now = realNow; globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("continues a browser signup in memory when localStorage is blocked or full", async () => {
    for (const blocked of [true, false]) {
      const attempt = randomUUID(); let selected = false;
      Object.defineProperty(globalThis, "localStorage", {configurable: true, value: {
        getItem: () => { if (blocked) throw new DOMException("Blocked", "SecurityError"); return null; },
        setItem: () => { throw new DOMException("Full", "QuotaExceededError"); },
      }});
      globalThis.fetch = async (url, init) => {
        if (new URL(String(url)).pathname === "/auth.signup") return Response.json({accepted: true, attempt});
        selected = JSON.parse(String(init?.body)).attempt === attempt;
        return Response.json({accepted: true});
      };
      try {
        const client = new BrowserHTTP(origin, scoped());
        await client.invoke("auth.signup", {email: "a@example.com"});
        await client.invoke("auth.send_verification_email", {});
        assert.ok(selected);
      } finally { globalThis.fetch = originalFetch; Reflect.deleteProperty(globalThis, "localStorage"); }
    }
  });

  test("releases an exclusive lock when its owning process exits without closing the database", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-lock-"));
    const session = credential();
    globalThis.fetch = async () => Response.json(session);
    try {
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".lock"))!);
      const holder = spawn(process.execPath, ["--input-type=module", "-e",
        'import {DatabaseSync} from "node:sqlite"; const db=new DatabaseSync(process.argv[1]); db.exec("BEGIN IMMEDIATE"); console.log("ready"); process.stdin.once("data",()=>process.exit(23));', file], {
        env: {HOME: process.env.HOME!, PATH: dirname(process.execPath), TMPDIR: tmpdir(), LANG: "en_US.UTF-8"},
        stdio: ["pipe", "pipe", "pipe"],
      });
      holder.stderr.resume();
      const exited = new Promise<number | null>(resolve => holder.once("exit", resolve));
      await new Promise<void>((resolve, reject) => {holder.stdout.once("data", () => resolve()); holder.once("error", reject);});
      try { await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("auth.session", {}), unavailable); }
      finally { holder.stdin.end("exit\n"); }
      assert.ok(await exited === 23);
      await new HTTP(origin, {persist: {dir}}).invoke("auth.session", {});
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("reports a missing built-in SQLite module without sending authentication", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-module-"));
    try {
      await writeFile(join(dir, "server.json"), JSON.stringify(credential()), {mode: 0o600});
      const loader = join(dir, "loader.mjs");
      await writeFile(loader, 'export function resolve(name,context,next) { if(name === "node:sqlite") throw Error("Unavailable"); return next(name,context); }');
      await child("load-failure", dir, ["--experimental-loader", loader]);
    } finally { await rm(dir, {recursive: true}); }
  });

  test("removes abandoned owner temporary files before logout completes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-temporary-"));
    globalThis.fetch = async () => Response.json(credential());
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const file = (await readdir(dir)).find(name => name.endsWith(".json"))!;
      const temporary = join(dir, file.slice(0, -5) + "." + randomUUID() + ".tmp");
      await writeFile(temporary, await readFile(join(dir, file)), {mode: 0o600});
      await client.invoke("auth.logout", {});
      assert.ok(!(await readdir(dir)).some(name => name.endsWith(".tmp")));
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("keeps an explicitly nonpersistent generated signup usable within the current client", async () => {
    const attempt = randomUUID(); let selected = false;
    globalThis.fetch = async (url, init) => {
      if (new URL(String(url)).pathname === "/auth.signup") return Response.json({accepted: true, attempt});
      selected = JSON.parse(String(init?.body)).attempt === attempt;
      return Response.json({accepted: true});
    };
    try {
      const client = new HTTP(origin, scoped("disabled", {persist: false}));
      await client.invoke("auth.signup", {email: "a@example.com"});
      await client.invoke("auth.send_verification_email", {});
      assert.ok(selected);
    } finally { globalThis.fetch = originalFetch; }
  });

  test("can log out while a refresh response is still outstanding", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-refresh-logout-"));
    const initial = credential(), updated = {...credential(), user_id: initial.user_id, session_id: initial.session_id};
    const started = deferred<void>(), response = deferred<Response>();
    globalThis.fetch = async url => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(initial);
      if (operation === "/auth.refresh") {started.resolve(); return response.promise;}
      if (operation === "/auth.logout") return Response.json({status: "ok"});
      return Response.json({error: "invalid_token"}, {status: 401});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const protectedCall = client.invoke("notes.list", {}).then(() => false, () => true);
      await started.promise;
      const logout = client.invoke("auth.logout", {});
      let timer: ReturnType<typeof setTimeout>;
      const completed = await Promise.race([logout.then(() => true), new Promise<boolean>(resolve => {timer = setTimeout(() => resolve(false), 1000);})]);
      clearTimeout(timer!);
      response.resolve(Response.json(updated));
      await logout;
      assert.ok(await protectedCall);
      assert.ok(completed, "Logout waited for the outstanding refresh response.");
    } finally { globalThis.fetch = originalFetch; await rm(dir, {recursive: true}); }
  });

  test("retains an E1 session when a later signup can write to the device again", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-memory-write-"));
    const first = credential(), second = credential(); let signins = 0;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") {
        if (++signins === 2) await chmod(dir, 0o500);
        return Response.json(signins === 1 ? first : second);
      }
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt: randomUUID()});
      return new Headers(init?.headers).get("authorization") === "Bearer " + second.access_token ?
        Response.json({ok: true}) : Response.json({error: "unauthenticated"}, {status: 401});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {}); await client.invoke("auth.signin", {});
      await chmod(dir, 0o700);
      await client.invoke("auth.signup", {email: "pending@example.com"});
      await client.invoke("notes.list", {});
    } finally {globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true});}
  });

  test("blocks a late verification even if the durable logout deletion failed", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-delete-failure-"));
    const started = deferred<void>(), response = deferred<Response>();
    const session = credential(); let business = 0;
    globalThis.fetch = async url => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(session);
      if (operation === "/auth.signup") return Response.json({accepted: true, attempt: randomUUID()});
      if (operation === "/auth.verify_email") {started.resolve(); return response.promise;}
      business++;
      return Response.json({ok: true});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      await client.invoke("auth.signup", {email: "a@example.com"});
      const verifying = client.invoke("auth.verify_email", {}); await started.promise;
      await chmod(dir, 0o500); await assert.rejects(client.invoke("auth.logout", {}), unavailable);
      await chmod(dir, 0o700);
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
      assert.ok(business === 0);
      response.resolve(Response.json(credential())); await verifying;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
      assert.ok(business === 0);
    } finally {globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true});}
  });

  test("does not refresh a prior account left under an unresolved transition marker", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-transition-"));
    const first = credential(); let signins = 0, refreshes = 0;
    globalThis.fetch = async url => {
      if (new URL(String(url)).pathname === "/auth.refresh") {refreshes++; return Response.json(first);}
      if (++signins === 2) await chmod(dir, 0o500);
      return Response.json(signins === 1 ? first : credential());
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {}); await client.invoke("auth.signin", {});
      await chmod(dir, 0o700);
      await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("auth.refresh", {refresh_token: first.refresh_token}),
        error => error instanceof OperationError && error.status === 401);
      assert.ok(refreshes === 0);
    } finally {globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true});}
  });

  test("clears quarantined data only on an explicit logout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-recovery-"));
    globalThis.fetch = async url => Response.json(new URL(String(url)).pathname === "/auth.logout" ? {status: "ok"} : credential());
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      await writeFile(file, "{", {mode: 0o600});
      await assert.rejects(client.invoke("auth.session", {}), error => error instanceof OperationError && error.code === "device_storage_corrupt");
      await client.invoke("auth.logout", {});
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("keeps concurrent signup screens usable after bounded local CAS retries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-concurrent-"));
    const attempts = new Map<string, string>(); let sent: string | undefined;
    globalThis.fetch = async (url, init) => {
      const input = JSON.parse(String(init?.body));
      if (new URL(String(url)).pathname === "/auth.signup") {
        const attempt = randomUUID(); attempts.set(input.email, attempt); return Response.json({accepted: true, attempt});
      }
      sent = input.attempt; return Response.json({accepted: true});
    };
    try {
      const clients = ["a", "b", "c"].map(screen => ({screen, client: new HTTP(origin, scoped(screen, {persist: {dir}}))}));
      await Promise.all(clients.map(({screen, client}) => client.invoke("auth.signup", {email: screen + "@example.com"})));
      for (const {screen, client} of clients) {
        await client.invoke("auth.send_verification_email", {});
        assert.ok(sent === attempts.get(screen + "@example.com"));
      }
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const saved = JSON.parse(await readFile(file, "utf8")).attempts;
      assert.ok(saved.length > 0 && saved.length <= 3);
      for (const attempt of saved) {
        await new HTTP(origin, scoped(attempt.screen, {persist: {dir}})).invoke("auth.send_verification_email", {});
        assert.ok(sent === attempt.id);
      }
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("does not refresh a stale business response after a new session was installed", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-old-response-"));
    const first = credential(), second = credential();
    const started = deferred<void>(), response = deferred<Response>();
    let signins = 0, refreshes = 0, business = 0;
    globalThis.fetch = async url => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(++signins === 1 ? first : second);
      if (operation === "/auth.refresh") {refreshes++; return Response.json(first);}
      if (++business === 1) {started.resolve(); return response.promise;}
      return Response.json({ok: true});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const pending = client.invoke("notes.list", {}).then(() => false, error => error instanceof OperationError && error.status === 401);
      await started.promise;
      await client.invoke("auth.signin", {});
      response.resolve(Response.json({error: "invalid_token"}, {status: 401}));
      assert.ok(await pending);
      assert.ok(refreshes === 0);
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("fixes a relative persistence directory against the construction-time working directory", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-relative-")), previous = process.cwd();
    globalThis.fetch = async () => Response.json(credential());
    try {
      const before = join(dir, "before"), after = join(dir, "after");
      await mkdir(before); await mkdir(after);
      process.chdir(before); const client = new HTTP(origin, {persist: {dir: "state"}});
      process.chdir(after); Reflect.set(client, scopeKey, Reflect.get(scoped("relative"), scopeKey));
      await client.invoke("auth.signin", {});
      assert.ok((await readdir(join(before, "state"))).some(name => name.endsWith(".json")));
      assert.ok((await readdir(after)).length === 0);
    } finally {process.chdir(previous); globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("does not let an older local logout delete another client's new session", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-old-logout-"));
    const first = credential(), second = credential(); let signins = 0, business = 0;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") return Response.json(++signins === 1 ? first : second);
      if (operation === "/auth.logout") return Response.json({status: "ok"});
      business++;
      return new Headers(init?.headers).get("authorization") === "Bearer " + second.access_token ?
        Response.json({user: second.user_id}) : Response.json({error: "unauthenticated"}, {status: 401});
    };
    const ready = deferred<void>(), resume = deferred<void>();
    try {
      const client = new HTTP(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const device = Reflect.get(client, "device"), read = device.read.bind(device); let reads = 0;
      device.read = async () => {const value = await read(); if (++reads === 1) {ready.resolve(); await resume.promise;} return value;};
      const logout = client.invoke("auth.logout", {}); await ready.promise;
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      resume.resolve(); await logout;
      await new HTTP(origin, {persist: {dir}}).invoke("notes.list", {});
      let value = await client.invoke("notes.list", {}) as {user: string};
      assert.ok(business === 2 && value.user === second.user_id);
      await client.invoke("auth.logout", {});
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof OperationError && error.code === "unauthenticated");
      assert.ok(business === 2);
      await new HTTP(origin, {persist: {dir}}).invoke("auth.signin", {});
      value = await client.invoke("notes.list", {}) as {user: string};
      assert.ok(business === 3 && value.user === second.user_id);
    } finally {resume.resolve(); globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("attaches a generated scope to an existing transport without crossing signup screens", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-attach-")), attempt = randomUUID(); let sent: string | undefined;
    globalThis.fetch = async (url, init) => {
      if (new URL(String(url)).pathname === "/auth.signup") return Response.json({accepted: true, attempt});
      sent = JSON.parse(String(init?.body)).attempt; return Response.json({accepted: true});
    };
    try {
      const first = new HTTP(origin, {persist: {dir}}), second = new HTTP(origin, {persist: {dir}});
      Reflect.set(first, scopeKey, Reflect.get(scoped("a"), scopeKey));
      Reflect.set(second, scopeKey, Reflect.get(scoped("b"), scopeKey));
      await first.invoke("auth.signup", {email: "a@example.com"});
      await second.invoke("auth.send_verification_email", {}); assert.ok(sent === undefined);
      await first.invoke("auth.send_verification_email", {}); assert.ok(sent === attempt);
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("rejects conflicting or malformed attached scopes without calling the server", async () => {
    let calls = 0; globalThis.fetch = async () => {calls++; return Response.json({accepted: true});};
    try {
      for (const Transport of [HTTP, BrowserHTTP]) {
        const client = new Transport(origin, scoped("a", {persist: false}));
        Reflect.set(client, scopeKey, Reflect.get(scoped("b"), scopeKey));
        await assert.rejects(Promise.resolve().then(() => client.invoke("auth.send_verification_email", {})), unavailable);
        const malformed = new Transport(origin);
        Reflect.set(malformed, scopeKey, {});
        await assert.rejects(Promise.resolve().then(() => malformed.invoke("auth.send_verification_email", {})), unavailable);
        for (const value of [undefined, null, {}, [""], [1], [undefined]]) {
          const options = scoped("a", {persist: false});
          Reflect.set(options, Symbol.for("chickinfry.store.public.v1"), value);
          assert.throws(() => new Transport(origin, options), unavailable);
          const invalid = new Transport(origin, scoped("a", {persist: false}));
          Reflect.set(invalid, Symbol.for("chickinfry.store.public.v1"), value);
          await assert.rejects(invalid.invoke("auth.bot_config", {}), unavailable);
        }
      }
      assert.ok(calls === 0);
    } finally {globalThis.fetch = originalFetch;}
  });

  test("keeps explicit bearer and disabled persistence settings when a scope is attached later", async () => {
    for (const phase of ["bearer-string", "bearer-options", "late-disabled"]) {
      const dir = await mkdtemp(join(tmpdir(), "device-attach-options-"));
      try {
        await writeFile(join(dir, "server.json"), JSON.stringify({...credential(), attempt: randomUUID()}), {mode: 0o600});
        await child(phase, dir);
        assert.ok((await readdir(dir)).every(name => name === "server.json"));
      } finally {await rm(dir, {recursive: true});}
    }
  });

  test("keeps the first three persisted attempts when a fourth remains in memory", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-count-"));
    const attempts = new Map<string, string>(); let sent: string | undefined;
    globalThis.fetch = async (url, init) => {
      const input = JSON.parse(String(init?.body));
      if (new URL(String(url)).pathname === "/auth.signup") {
        const attempt = randomUUID(); attempts.set(input.email, attempt); return Response.json({accepted: true, attempt});
      }
      sent = input.attempt; return Response.json({accepted: true});
    };
    try {
      const clients = ["a", "b", "c", "d"].map(screen => ({screen, client: new HTTP(origin, scoped(screen, {persist: {dir}}))}));
      for (const {screen, client} of clients) await client.invoke("auth.signup", {email: screen + "@example.com"});
      await clients[3].client.invoke("auth.send_verification_email", {}); assert.ok(sent === attempts.get("d@example.com"));
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const saved = JSON.parse(await readFile(file, "utf8")).attempts;
      assert.ok(saved.length === 3 && saved.every((value: {email: string; id: string}) => value.email !== "d@example.com" && attempts.get(value.email) === value.id));
      await new HTTP(origin, scoped("a", {persist: {dir}})).invoke("auth.send_verification_email", {});
      assert.ok(sent === attempts.get("a@example.com"));
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  test("keeps an oversized successful session in memory without evicting the confirmed bundle", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-bytes-")), session = credential();
    globalThis.fetch = async (url, init) => {
      if (new URL(String(url)).pathname === "/auth.signin") return Response.json(session);
      if (new URL(String(url)).pathname === "/auth.bot_config") return Response.json({mode: "off"});
      return new Headers(init?.headers).get("authorization") === "Bearer " + session.access_token ?
        Response.json({ok: true}) : Response.json({error: "unauthenticated"}, {status: 401});
    };
    try {
      const client = new HTTP(origin, {persist: {dir}}); await client.invoke("auth.bot_config", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const bundle = JSON.parse(await readFile(file, "utf8"));
      for (let index = 0; ; index++) {
        const key = ("screen-" + index).padEnd(64, "x"); bundle.selections[key] = "0";
        if (new TextEncoder().encode(JSON.stringify(bundle)).length > 8100) {delete bundle.selections[key]; break;}
      }
      const raw = JSON.stringify(bundle); assert.ok(new TextEncoder().encode(raw).length > 8000);
      await writeFile(file, raw, {mode: 0o600});
      await client.invoke("auth.signin", {}); await client.invoke("notes.list", {});
      assert.ok((await readFile(file, "utf8")) === raw);
      await assert.rejects(new HTTP(origin, {persist: {dir}}).invoke("notes.list", {}), error => error instanceof OperationError && error.status === 401);
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  // Reuses the generated-auth browser harness's optional Playwright setup.
  test("restores device state in real browser pages and keeps tabs separate", {skip: !process.env.CHIK_PLAYWRIGHT_ROOT}, async context => {
    const engines = await import(process.env.CHIK_PLAYWRIGHT_ROOT + "/index.mjs");
    const esbuildName = "esbuild";
    const {build} = await import(esbuildName);
    const bundled = await build({entryPoints: [fileURLToPath(new URL("../src/http.ts", import.meta.url))],
      bundle: true, write: false, format: "esm", platform: "browser"});
    const script = bundled.outputFiles[0].text;
    const info = {id: randomUUID(), session_id: randomUUID(), email: "a@example.com", expires_at: new Date(Date.now() + 900_000).toISOString()};
    const cookie = randomBytes(32).toString("base64url");
    const attempts = new Map<string, string>();
    let lastAttempt: string | undefined, anonymousCalls = 0;
    const server = createServer(async (incoming, outgoing) => {
      if (incoming.url === "/transport.js") {outgoing.setHeader("Content-Type", "text/javascript"); outgoing.end(script); return;}
      if (incoming.method === "GET") {
        outgoing.setHeader("Content-Type", "text/html");
        outgoing.end('<script type="module">import {BrowserHTTP} from "/transport.js"; window.create=(screen)=>{window.client=new BrowserHTTP(location.origin); Reflect.set(window.client,Symbol.for("chickinfry.store.scope.v1"),{appId:"browser-test",projectId:"browser-project",origin:location.origin,screen});Reflect.set(window.client,Symbol.for("chickinfry.store.public.v1"),["catalog.list_items"]);};window.ready=true;</script>');
        return;
      }
      let body = ""; for await (const chunk of incoming) body += chunk;
      const input = JSON.parse(body);
      outgoing.setHeader("Content-Type", "application/json");
      if (incoming.url === "/catalog.list_items") {
        if (!incoming.headers.cookie && !incoming.headers.authorization) anonymousCalls++;
        outgoing.end('{"account":"anonymous"}'); return;
      }
      if (incoming.url === "/auth.signup") {
        const attempt = randomUUID(); attempts.set(input.email, attempt);
        outgoing.end(JSON.stringify({accepted: true, attempt})); return;
      }
      if (incoming.url === "/auth.send_verification_email") {lastAttempt = input.attempt; outgoing.end('{"accepted":true}'); return;}
      if (incoming.url === "/auth.signin") {
        outgoing.setHeader("Set-Cookie", "__Host-device_test=" + cookie + "; Secure; HttpOnly; SameSite=Strict; Path=/");
        outgoing.end(JSON.stringify(info)); return;
      }
      if (incoming.url === "/auth.session") {
        const valid = incoming.headers.cookie?.includes("__Host-device_test=" + cookie);
        outgoing.statusCode = valid ? 200 : 401;
        outgoing.end(JSON.stringify(valid ? info : {error: "unauthenticated"})); return;
      }
      outgoing.end('{"status":"ok"}');
    });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const endpoint = `http://127.0.0.1:${address.port}`;
    try {
      for (const name of ["chromium", "firefox", "webkit"]) await context.test(name, async engineTest => {
        let browser;
        try { browser = await engines[name].launch({headless: true}); }
        catch (error) {engineTest.skip(error instanceof Error ? error.name : "LaunchError"); return;}
        try {
          for (const locks of [true, false]) await engineTest.test(locks ? "Web Locks" : "single-write fallback", async () => {
            const profile = await browser.newContext();
            try {
              const first = await profile.newPage(), second = await profile.newPage();
              if (!locks) await profile.addInitScript('Object.defineProperty(navigator,"locks",{value:undefined});');
              await first.goto(endpoint); await first.waitForFunction("window.ready");
              await first.evaluate('window.create("a"); window.client.invoke("auth.signup",{email:"a@example.com",password:crypto.randomUUID()})');
              await second.goto(endpoint); await second.waitForFunction("window.ready");
              await second.evaluate('window.create("b"); window.client.invoke("auth.signup",{email:"b@example.com",password:crypto.randomUUID()})');
              await first.reload(); await first.waitForFunction("window.ready");
              await first.evaluate('window.create("a"); window.client.invoke("auth.send_verification_email",{})');
              assert.ok(lastAttempt === attempts.get("a@example.com"));
              await second.evaluate('window.client.invoke("auth.send_verification_email",{})');
              assert.ok(lastAttempt === attempts.get("b@example.com"));
              if (name !== "webkit") {
                await first.evaluate('window.client.invoke("auth.signin",{email:"a@example.com"})');
                await first.reload(); await first.waitForFunction("window.ready");
                await first.evaluate('window.create("a"); window.client.invoke("auth.session",{})');
              }
              assert.ok(await first.evaluate('!Object.values(localStorage).some(value=>/password|accessToken|refreshToken|cookie|code/i.test(value))'));
              await first.evaluate('window.client.invoke("auth.logout",{})');
              assert.ok(await first.evaluate('window.client.invoke("notes.list",{}).then(()=>false,error=>error.code==="unauthenticated")'));
              const before = anonymousCalls;
              assert.ok(await first.evaluate('window.client.invoke("catalog.list_items",{}).then(value=>value.account==="anonymous")'));
              assert.ok(anonymousCalls === before + 1);
              await second.reload(); await second.waitForFunction("window.ready");
              await second.evaluate('window.create("b"); window.client.invoke("auth.send_verification_email",{})');
              assert.ok(lastAttempt === undefined);
            } finally {await profile.close();}
          });
        } finally {await browser.close();}
      });
    } finally {await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));}
  });
}
