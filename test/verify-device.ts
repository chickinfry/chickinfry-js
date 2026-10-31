import {strict as assert} from "node:assert";
import {randomBytes, randomUUID} from "node:crypto";
import {mkdir, mkdtemp, readFile, readdir, writeFile, stat, chmod, rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";
import {spawn} from "node:child_process";
import {test} from "node:test";
import {createServer} from "node:http";
import {HttpTransport, BrowserHttpTransport, ClientError, OperationError} from "../src/http.js";
import type {TransportOptions} from "../src/http.js";
import type {Store} from "../src/device.js";

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
const unavailable = (error: unknown) => error instanceof ClientError &&
  error.code === "failed_precondition" && error.status === undefined;
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
    const transport = phase === "bearer-string" ? new HttpTransport(origin, session.access_token) :
      phase === "bearer-options" ? new HttpTransport(origin, {token: session.access_token, persist: {dir: join(dir, "ignored")}}) :
      new HttpTransport(origin, requestedPhase.startsWith("default-") ? scoped() : phase === "late-disabled" ? {persist: false} : {persist: {dir: join(dir, "device")}});
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
      catch (error) { rejected = error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined; }
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
      await new HttpTransport(origin, {token: access, persist: false}).invoke("notes.list", {});
      assert.ok(authorization === "Bearer " + access);
      await new HttpTransport(origin, {persist: false}).invoke("notes.list", {});
      assert.ok(authorization === null);
      assert.throws(() => new BrowserHttpTransport(origin, {persist: {dir: "device"}}), unavailable);
      assert.throws(() => new HttpTransport(origin, {persist: {dir: ""}}), unavailable);
      assert.throws(() => new HttpTransport(origin, {[scopeKey]: {}} as never), unavailable);
    } finally { globalThis.fetch = originalFetch; }
  });

  test("preserves corrupt records and newer versions instead of restoring an empty session", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-corrupt-"));
    globalThis.fetch = async () => Response.json(credential());
    try {
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      for (const [text, code] of [["{", "data_loss"],
        [JSON.stringify({version: 2}), "unimplemented"]]) {
        await writeFile(file, text, {mode: 0o600});
        await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("notes.list", {}),
          error => error instanceof ClientError && error.code === code);
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
      await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {}), unavailable);
      const nested = join(dir, "private"); await mkdir(nested, {mode: 0o700});
      await assert.rejects(new HttpTransport(origin, {persist: {dir: nested}}).invoke("auth.signin", {}), unavailable);
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
      await new BrowserHttpTransport(origin, scoped("a")).invoke("auth.signup", {email: "a@example.com", password: randomUUID()});
      await new BrowserHttpTransport(origin, scoped("b")).invoke("auth.signup", {email: "b@example.com", password: randomUUID()});
      await new BrowserHttpTransport(origin, scoped("a")).invoke("auth.send_verification_email", {});
      await new BrowserHttpTransport(origin, scoped("b")).invoke("auth.send_verification_email", {});
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signup", {email: "a@example.com"});
      const pending = client.invoke("auth.verify_email", {});
      await started.promise;
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.logout", {});
      response.resolve(Response.json(credential()));
      await pending;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
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
      const first = new HttpTransport(origin, scoped("a", {persist: {dir}}));
      await first.invoke("auth.signup", {email: "a@example.com"});
      const pending = first.invoke("auth.verify_email", {});
      await started.promise;
      await new HttpTransport(origin, scoped("b", {persist: {dir}})).invoke("auth.signup", {email: "b@example.com"});
      response.resolve(Response.json(credential())); await pending;
      await new HttpTransport(origin, scoped("b", {persist: {dir}})).invoke("auth.send_verification_email", {});
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
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      const memory = new HttpTransport(origin, {persist: {dir}});
      await memory.invoke("auth.signin", {});
      await memory.invoke("notes.list", {});
      await assert.rejects(memory.invoke("auth.logout", {}), unavailable);
      const blockedCalls = protectedCalls;
      await assert.rejects(memory.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(protectedCalls === blockedCalls);
      await chmod(dir, 0o700);
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.logout", {});
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      const before = protectedCalls;
      await assert.rejects(memory.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(protectedCalls === before);
      await memory.invoke("notes.list", {});
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  for (const [duringCleanup, applied] of [[false, false], [true, false], [true, true]]) test(
    `rejects an E1 account change ${duringCleanup ? "during" : "before"} expired attempt cleanup` +
      (applied ? " (post-commit failure)" : ""), {skip: process.platform === "win32"}, async context => {
    const dir = await mkdtemp(join(tmpdir(), "device-memory-expiry-"));
    const sessions = [credential(), credential(), credential()];
    let signins = 0;
    const accounts: string[] = [];
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname;
      if (operation === "/auth.signin") {
        const session = sessions[signins++];
        if (signins === 2 && !applied) await chmod(dir, 0o500);
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
      await new HttpTransport(origin, options).invoke("auth.signin", {});
      await new HttpTransport(origin, options).invoke("auth.signup", {email: "pending@example.com"});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const attempt = JSON.parse(await readFile(file, "utf8")).attempts[0];
      const expire = async (startedAt = Date.now() - 86_400_000) => {
        const bundle = JSON.parse(await readFile(file, "utf8"));
        bundle.attempts = [{...attempt, startedAt}];
        bundle.selections[attempt.screen] = attempt.sequence;
        await writeFile(file, JSON.stringify(bundle), {mode: 0o600});
      };
      const client = new HttpTransport(origin, options);
      if (applied) {
        await expire(Date.now() - 86_400_000 + 60_000);
        const device = Reflect.get(client, "device"), store: Store = await device.storage();
        let fail = true;
        Reflect.set(device, "store", Promise.resolve({read: () => store.read(), async swap(expected, raw, reset) {
          const written = await store.swap(expected, raw, reset);
          if (written && fail && JSON.parse(raw).session?.accessToken === sessions[1].access_token) {
            fail = false; throw new ClientError("failed_precondition");
          }
          return written;
        }} satisfies Store));
      }
      await client.invoke("auth.signin", {});
      if (applied) {
        assert.ok(Reflect.get(Reflect.get(client, "device"), "memory"));
        const now = Date.now() + 120_000;
        context.mock.method(Date, "now", () => now);
      } else {
        await client.invoke("notes.list", {});
        assert.ok(accounts.length === 1 && accounts[0] === sessions[1].user_id);
      }
      accounts.length = 0;
      await chmod(dir, 0o700);
      if (duringCleanup) {
        if (!applied) await expire();
        const device = Reflect.get(client, "device"), read = device.read.bind(device);
        let reads = 0;
        device.read = async () => {
          const value = await read();
          if (++reads === 1) {await new HttpTransport(origin, options).invoke("auth.signin", {}); await expire();}
          return value;
        };
      } else {
        await new HttpTransport(origin, options).invoke("auth.signin", {});
        await expire();
      }
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
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
      const client = new HttpTransport(origin, scoped("a", {persist: {dir}}));
      Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      await client.invoke("auth.signin", {}); await client.invoke("auth.logout", {});
      const before = calls;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(calls === before);
      for (const names of [[], ["Catalog.list_items"], ["list_items"], ["other.list_items"]]) {
        Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), names);
        await assert.rejects(client.invoke("catalog.list_items", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
        assert.ok(calls === before);
      }
      Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      const restored = new HttpTransport(origin, scoped("b", {persist: {dir}}));
      Reflect.set(restored, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      const options = scoped("c", {persist: {dir}});
      Reflect.set(options, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
      for (const current of [client, restored, new HttpTransport(origin, options)]) {
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
        await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {seed: true});
        const client = new HttpTransport(origin, {persist: {dir}});
        Reflect.set(client, Symbol.for("chickinfry.store.public.v1"), ["catalog.list_items"]);
        const before = calls;
        if (operation === "notes.list" || operation === "auth.refresh") {
          await assert.rejects(client.invoke(operation, {refresh_token: expired.refresh_token}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {}); await client.invoke("notes.list", {});
      await client.invoke("notes.list", {});
      await chmod(dir, 0o700);
      await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(refreshes === 1);
    } finally { globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true}); }
  });

  test("does not send an account switch when its durable marker cannot be written", {skip: process.platform === "win32"}, async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-marker-"));
    let calls = 0;
    globalThis.fetch = async () => { calls++; return Response.json(credential()); };
    try {
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      await chmod(dir, 0o500);
      await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {}), unavailable);
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
      const client = new HttpTransport(origin, {persist: {dir}});
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
        const client = new BrowserHttpTransport(origin, scoped());
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
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".lock"))!);
      const holder = spawn(process.execPath, ["--input-type=module", "-e",
        'import {DatabaseSync} from "node:sqlite"; const db=new DatabaseSync(process.argv[1]); db.exec("BEGIN IMMEDIATE"); console.log("ready"); process.stdin.once("data",()=>process.exit(23));', file], {
        env: {HOME: process.env.HOME!, PATH: dirname(process.execPath), TMPDIR: tmpdir(), LANG: "en_US.UTF-8"},
        stdio: ["pipe", "pipe", "pipe"],
      });
      holder.stderr.resume();
      const exited = new Promise<number | null>(resolve => holder.once("exit", resolve));
      await new Promise<void>((resolve, reject) => {holder.stdout.once("data", () => resolve()); holder.once("error", reject);});
      try { await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("auth.session", {}), unavailable); }
      finally { holder.stdin.end("exit\n"); }
      assert.ok(await exited === 23);
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.session", {});
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
      const client = new HttpTransport(origin, {persist: {dir}});
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
      const client = new HttpTransport(origin, scoped("disabled", {persist: false}));
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
      const client = new HttpTransport(origin, {persist: {dir}});
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
      const client = new HttpTransport(origin, {persist: {dir}});
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      await client.invoke("auth.signup", {email: "a@example.com"});
      const verifying = client.invoke("auth.verify_email", {}); await started.promise;
      await chmod(dir, 0o500); await assert.rejects(client.invoke("auth.logout", {}), unavailable);
      await chmod(dir, 0o700);
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(business === 0);
      response.resolve(Response.json(credential())); await verifying;
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {}); await client.invoke("auth.signin", {});
      await chmod(dir, 0o700);
      await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("auth.refresh", {refresh_token: first.refresh_token}),
        error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(refreshes === 0);
    } finally {globalThis.fetch = originalFetch; await chmod(dir, 0o700); await rm(dir, {recursive: true});}
  });

  test("clears quarantined data only on an explicit logout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "device-recovery-"));
    globalThis.fetch = async url => Response.json(new URL(String(url)).pathname === "/auth.logout" ? {status: "ok"} : credential());
    try {
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      await writeFile(file, "{", {mode: 0o600});
      await assert.rejects(client.invoke("auth.session", {}), error => error instanceof ClientError && error.code === "data_loss");
      await client.invoke("auth.logout", {});
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
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
      const clients = ["a", "b", "c"].map(screen => ({screen, client: new HttpTransport(origin, scoped(screen, {persist: {dir}}))}));
      await Promise.all(clients.map(({screen, client}) => client.invoke("auth.signup", {email: screen + "@example.com"})));
      for (const {screen, client} of clients) {
        await client.invoke("auth.send_verification_email", {});
        assert.ok(sent === attempts.get(screen + "@example.com"));
      }
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const saved = JSON.parse(await readFile(file, "utf8")).attempts;
      assert.ok(saved.length > 0 && saved.length <= 3);
      for (const attempt of saved) {
        await new HttpTransport(origin, scoped(attempt.screen, {persist: {dir}})).invoke("auth.send_verification_email", {});
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const pending = client.invoke("notes.list", {}).then(() => false, error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
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
      process.chdir(before); const client = new HttpTransport(origin, {persist: {dir: "state"}});
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
      const client = new HttpTransport(origin, {persist: {dir}});
      await client.invoke("auth.signin", {});
      const device = Reflect.get(client, "device"), read = device.read.bind(device); let reads = 0;
      device.read = async () => {const value = await read(); if (++reads === 1) {ready.resolve(); await resume.promise;} return value;};
      const logout = client.invoke("auth.logout", {}); await ready.promise;
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
      resume.resolve(); await logout;
      await new HttpTransport(origin, {persist: {dir}}).invoke("notes.list", {});
      let value = await client.invoke("notes.list", {}) as {user: string};
      assert.ok(business === 2 && value.user === second.user_id);
      await client.invoke("auth.logout", {});
      await assert.rejects(client.invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
      assert.ok(business === 2);
      await new HttpTransport(origin, {persist: {dir}}).invoke("auth.signin", {});
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
      const first = new HttpTransport(origin, {persist: {dir}}), second = new HttpTransport(origin, {persist: {dir}});
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
      for (const Transport of [HttpTransport, BrowserHttpTransport]) {
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
      const clients = ["a", "b", "c", "d"].map(screen => ({screen, client: new HttpTransport(origin, scoped(screen, {persist: {dir}}))}));
      for (const {screen, client} of clients) await client.invoke("auth.signup", {email: screen + "@example.com"});
      await clients[3].client.invoke("auth.send_verification_email", {}); assert.ok(sent === attempts.get("d@example.com"));
      const file = join(dir, (await readdir(dir)).find(name => name.endsWith(".json"))!);
      const saved = JSON.parse(await readFile(file, "utf8")).attempts;
      assert.ok(saved.length === 3 && saved.every((value: {email: string; id: string}) => value.email !== "d@example.com" && attempts.get(value.email) === value.id));
      await new HttpTransport(origin, scoped("a", {persist: {dir}})).invoke("auth.send_verification_email", {});
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
      const client = new HttpTransport(origin, {persist: {dir}}); await client.invoke("auth.bot_config", {});
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
      await assert.rejects(new HttpTransport(origin, {persist: {dir}}).invoke("notes.list", {}), error => error instanceof ClientError && error.code === "unauthenticated" && error.status === undefined);
    } finally {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});}
  });

  async function rejoinFixture() {
    const dir = await mkdtemp(join(tmpdir(), "device-rejoin-"));
    const first = credential(), verified = credential(), rotated = {...credential(), user_id: first.user_id, session_id: first.session_id};
    const attempts = new Map<string, string>();
    const calls = {signup: 0, signin: 0, verify: 0, refresh: 0, reset: 0, protected: 0};
    let sentAccess: string | null = null, sentAttempt: string | undefined;
    let onSignup: (() => Promise<void>) | undefined, onSignin: (() => Promise<void>) | undefined;
    let onRefresh: (() => Promise<void>) | undefined, onReset: (() => Promise<void>) | undefined;
    globalThis.fetch = async (url, init) => {
      const operation = new URL(String(url)).pathname, input = JSON.parse(String(init?.body));
      if (operation === "/auth.signin") {const session = {...first}; calls.signin++; await onSignin?.(); return Response.json(session);}
      if (operation === "/auth.verify_email") {calls.verify++; return Response.json(verified);}
      if (operation === "/auth.refresh") {calls.refresh++; await onRefresh?.(); return Response.json(rotated);}
      if (operation === "/auth.signup") {
        calls.signup++; await onSignup?.();
        const attempt = randomUUID(); attempts.set(input.email, attempt);
        return Response.json({accepted: true, attempt});
      }
      if (["/auth.request_password_reset", "/auth.reset_password"].includes(operation)) {
        calls.reset++; await onReset?.(); return Response.json({accepted: true});
      }
      if (operation === "/notes.list") calls.protected++;
      sentAttempt = input.attempt;
      sentAccess = new Headers(init?.headers).get("authorization");
      return Response.json({ok: true});
    };
    const a = new HttpTransport(origin, scoped("a", {persist: {dir}}));
    /** Different path spellings share the file but model separate process refresh flights. */
    const b = new HttpTransport(origin, scoped("b", {persist: {dir: dir + "/."}}));
    await a.invoke("auth.signin", {});
    const device = Reflect.get(a, "device"), store: Store = await device.storage();
    const writes: {expected: string | null; value: any}[] = [];
    let reject: ((candidate: any) => boolean) | undefined, afterWrite = false, readsUntilFailure: number | undefined;
    Reflect.set(device, "store", Promise.resolve({async read() {
      if (readsUntilFailure !== undefined && readsUntilFailure-- === 0) {
        readsUntilFailure = undefined; throw new ClientError("failed_precondition");
      }
      return store.read();
    }, async swap(expected, raw, reset) {
      writes.push({expected, value: JSON.parse(raw)});
      if (reject?.(JSON.parse(raw))) {
        reject = undefined;
        if (afterWrite) assert.ok(await store.swap(expected, raw, reset));
        throw new ClientError("failed_precondition");
      }
      return store.swap(expected, raw, reset);
    }} satisfies Store));
    const read = async () => JSON.parse((await store.read())!);
    const peer = async (change: (bundle: any) => void) => {
      const raw = await store.read(), value = JSON.parse(raw!);
      change(value); value.revision = String(BigInt(value.revision) + 1n);
      assert.ok(await store.swap(raw, JSON.stringify(value)));
    };
    return {a, b, dir, device, store, first, verified, rotated, attempts, calls, read, peer, writes,
      access: () => sentAccess, attempt: () => sentAttempt,
      failReadAfter: (successfulReads: number) => {readsUntilFailure = successfulReads;},
      fail: (predicate: (candidate: any) => boolean, applied = false) => {reject = predicate; afterWrite = applied;},
      signupHook: (hook?: () => Promise<void>) => {onSignup = hook;},
      signinHook: (hook?: () => Promise<void>) => {onSignin = hook;},
      refreshHook: (hook?: () => Promise<void>) => {onRefresh = hook;},
      resetHook: (hook?: () => Promise<void>) => {onReset = hook;},
      async memorySignup(applied = true) {
        const before = (await read()).attempts.length;
        afterWrite = applied; reject = candidate => candidate.attempts.length > before;
        await a.invoke("auth.signup", {email: "memory@example.com"});
        assert.ok(Reflect.get(device, "memory"));
      },
      async close() {globalThis.fetch = originalFetch; await rm(dir, {recursive: true});},
    };
  }
  const locallyUnauthenticated = (error: unknown) => error instanceof ClientError &&
    error.code === "unauthenticated" && error.status === undefined;

  for (const operation of ["auth.signin", "auth.signup", "auth.request_password_reset", "auth.reset_password"]) test(
    "STORE-REJOIN explicit authentication clears observed peer marks" + (operation === "auth.signin" ? "" : ` (${operation})`), async () => {
    const f = await rejoinFixture(), peerStarted = deferred<void>(), peerResponse = deferred<void>();
    const started = deferred<void>(), response = deferred<void>();
    let peer: Promise<unknown> | undefined, request: Promise<unknown> | undefined, timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      await f.memorySignup();
      const resetting = operation.includes("password"), previous = {...f.first};
      if (resetting) {
        f.refreshHook(async () => {peerStarted.resolve(); await peerResponse.promise;});
        /** Share the refresh flight to exercise the reset wait before snapshot. */
        const client = new HttpTransport(origin, scoped("peer", {persist: {dir: f.dir}}));
        peer = client.invoke("auth.refresh", {refresh_token: previous.refresh_token});
      } else {
        Object.assign(f.first, credential());
        f.signinHook(async () => {peerStarted.resolve(); await peerResponse.promise;});
        peer = f.b.invoke("auth.signin", {});
      }
      await peerStarted.promise;
      const before = await f.store.read(), saved = JSON.parse(before!);
      assert.ok(resetting ? saved.refresh : saved.pending.length === 1);
      assert.ok(Reflect.get(f.device, "memory"));
      if (operation === "auth.signin") {
        await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
        assert.ok(!Reflect.get(f.device, "memory"));
        Object.assign(f.first, credential());
      }
      const hold = async () => {started.resolve(); await response.promise;};
      if (operation === "auth.signin") f.signinHook(hold);
      else if (operation === "auth.signup") f.signupHook(hold);
      else f.resetHook(hold);
      const calls = operation === "auth.signin" ? f.calls.signin : operation === "auth.signup" ? f.calls.signup : f.calls.reset;
      const writes = f.writes.length;
      request = f.a.invoke(operation, {email: "next@example.com"});
      await Promise.race([started.promise, new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error("Explicit authentication waited for the peer response.")), 5000);
      })]);
      clearTimeout(timeout);
      const cleared = await f.read();
      assert.equal(cleared.authGeneration, String(BigInt(saved.authGeneration) + 1n));
      assert.deepEqual(cleared.pending, []); assert.equal(cleared.refresh, undefined); assert.equal(cleared.session, undefined);
      assert.deepEqual(cleared.attempts, saved.attempts); assert.ok(!Reflect.get(f.device, "memory"));
      const cleanup = f.writes.slice(writes).find(write => write.value.authGeneration === cleared.authGeneration)!;
      assert.ok(cleanup && cleanup.expected !== null);
      assert.deepEqual(cleanup.value.selections, saved.selections);
      assert.equal(JSON.parse(cleanup.expected).authGeneration, saved.authGeneration);
      assert.ok(resetting ? JSON.parse(cleanup.expected).refresh === saved.refresh :
        JSON.parse(cleanup.expected).pending.includes(saved.pending[0]));
      assert.equal(operation === "auth.signin" ? f.calls.signin : operation === "auth.signup" ? f.calls.signup : f.calls.reset, calls + 1);
      const raw = await f.store.read();
      peerResponse.resolve(); await peer;
      assert.equal(await f.store.read(), raw, "The late peer response must install nothing.");
      response.resolve(); await request;
      if (operation === "auth.signin") {
        assert.equal((await f.read()).session.userId, f.first.user_id);
        await f.a.invoke("notes.list", {});
        assert.equal(f.access(), "Bearer " + f.first.access_token);
      } else {
        await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
        assert.equal(f.calls.protected, 0);
        if (operation === "auth.signup") {
          await f.a.invoke("auth.verify_email", {attempt: f.attempts.get("next@example.com"), code: "123456"});
          assert.equal((await f.read()).session.userId, f.verified.user_id);
        }
      }
    } finally {
      clearTimeout(timeout); peerResponse.resolve(); response.resolve();
      await peer?.catch(() => {}); await request?.catch(() => {}); await f.close();
    }
  });

  test("STORE-REJOIN explicit authentication clears observed peer marks (start write failure)", async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup();
      f.signinHook(async () => {throw new ClientError("unavailable", undefined, true);});
      await assert.rejects(f.b.invoke("auth.signin", {}));
      const saved = await f.read(), calls = f.calls.signin;
      assert.equal(saved.pending.length, 1);
      f.fail(value => value.authGeneration !== saved.authGeneration);
      await assert.rejects(f.a.invoke("auth.signin", {}), unavailable);
      const after = await f.read();
      assert.equal(f.calls.signin, calls);
      assert.equal(after.authGeneration, saved.authGeneration); assert.deepEqual(after.pending, saved.pending);
      assert.deepEqual(after.session, saved.session);
    } finally {await f.close();}
  });

  test("STORE-REJOIN explicit authentication clears observed peer marks (stale observation keeps reset waiting)", async () => {
    const f = await rejoinFixture(), started = deferred<void>(), response = deferred<void>();
    let peer: Promise<unknown> | undefined, refresh: Promise<unknown> | undefined, request: Promise<unknown> | undefined;
    const refreshing = deferred<void>(), refreshed = deferred<void>();
    try {
      await f.memorySignup();
      f.signinHook(async () => {started.resolve(); await response.promise;});
      peer = f.b.invoke("auth.signin", {}); await started.promise;
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      response.resolve(); await peer;
      f.refreshHook(async () => {refreshing.resolve(); await refreshed.promise;});
      const client = new HttpTransport(origin, scoped("peer", {persist: {dir: f.dir}}));
      refresh = client.invoke("auth.refresh", {refresh_token: f.first.refresh_token}); await refreshing.promise;
      const snapshot = f.device.snapshot.bind(f.device), current = await snapshot();
      /** A validated snapshot without I/O makes the send-versus-wait ordering deterministic. */
      let first = true;
      f.device.snapshot = async () => {if (first) {first = false; return current;} return snapshot();};
      request = f.a.invoke("auth.request_password_reset", {email: "next@example.com"});
      await new Promise<void>(resolve => setImmediate(resolve));
      assert.equal(f.calls.reset, 0);
      refreshed.resolve(); await refresh; await request;
      const saved = await f.read();
      assert.equal(f.calls.reset, 1); assert.equal(saved.authGeneration, current.bundle.authGeneration);
      assert.equal(saved.session.refreshToken, f.rotated.refresh_token);
    } finally {
      response.resolve(); refreshed.resolve(); await peer?.catch(() => {});
      await refresh?.catch(() => {}); await request?.catch(() => {}); await f.close();
    }
  });

  for (const conflict of [false, true]) for (const operation of ["auth.signin", "auth.request_password_reset"]) test(
    `STORE-REJOIN explicit authentication continues after peer refresh (${operation}, ${conflict ? "CAS retry" : "cleanup reread"})`, async () => {
    const f = await rejoinFixture(), refreshing = deferred<void>(), refreshed = deferred<void>();
    const started = deferred<void>(), response = deferred<void>();
    let refresh: Promise<unknown> | undefined, request: Promise<unknown> | undefined;
    try {
      await f.memorySignup();
      f.refreshHook(async () => {refreshing.resolve(); await refreshed.promise;});
      const client = new HttpTransport(origin, scoped("peer", {persist: {dir: f.dir}}));
      refresh = client.invoke("auth.refresh", {refresh_token: f.first.refresh_token}); await refreshing.promise;
      await f.device.snapshot();
      assert.equal(Reflect.get(f.device, "memory"), undefined);
      const before = await f.read(), store: Store = await f.device.storage();
      assert.ok(before.refresh);
      let raced = false, conflicts = 0;
      Reflect.set(f.device, "store", Promise.resolve({async read() {
        const raw = await store.read();
        if (!conflict && !raced) {
          raced = true; assert.equal(JSON.parse(raw!).refresh, before.refresh);
          refreshed.resolve(); await refresh;
        }
        return raw;
      }, async swap(expected, raw, reset) {
        if (conflict && !raced) {
          raced = true; assert.equal(JSON.parse(expected!).refresh, before.refresh);
          assert.equal(JSON.parse(raw).authGeneration, String(BigInt(before.authGeneration) + 1n));
          refreshed.resolve(); await refresh;
          const swapped = await store.swap(expected, raw, reset);
          assert.equal(swapped, false); conflicts++; return swapped;
        }
        return store.swap(expected, raw, reset);
      }} satisfies Store));
      Object.assign(f.first, f.rotated);
      const hold = async () => {started.resolve(); await response.promise;};
      if (operation === "auth.signin") f.signinHook(hold); else f.resetHook(hold);
      const calls = {...f.calls};
      request = f.a.invoke(operation, {email: "next@example.com"});
      await Promise.race([started.promise, request]);
      const saved = await f.read();
      assert.ok(raced); assert.equal(conflicts, conflict ? 1 : 0);
      assert.equal(saved.authGeneration, before.authGeneration);
      assert.equal(saved.refresh, undefined);
      assert.deepEqual(saved.session, {accessToken: f.rotated.access_token, refreshToken: f.rotated.refresh_token,
        userId: f.rotated.user_id, sessionId: f.rotated.session_id, expiresAt: f.rotated.expires_at,
        refreshExpiresAt: f.rotated.refresh_expires_at});
      assert.equal(operation === "auth.signin" ? f.calls.signin - calls.signin : f.calls.reset - calls.reset, 1);
      response.resolve(); await request;
      await f.a.invoke("notes.list", {});
      assert.equal(f.access(), "Bearer " + f.rotated.access_token);
      assert.equal((await f.read()).authGeneration, before.authGeneration);
      assert.equal(f.calls.refresh, 1);
    } finally {
      refreshed.resolve(); response.resolve(); await refresh?.catch(() => {});
      await request?.catch(() => {}); await f.close();
    }
  });

  for (const applied of [false, true]) test("review5 public: cleanup recovery preserves refresh complete" +
    (applied ? " (post-commit failure)" : ""), async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup(applied);
      if (!applied) await f.peer(value => {value.pending = [];});
      const before = await f.read();
      await f.b.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      assert.ok((await f.read()).authGeneration === before.authGeneration);
      await f.a.invoke("notes.list", {});
      assert.ok(f.access() === "Bearer " + f.rotated.access_token);
      await f.a.invoke("auth.signup", {email: "next@example.com"});
      assert.ok((await f.read()).session.refreshToken === f.rotated.refresh_token);
      assert.ok(f.calls.refresh === 1 && f.calls.signup === 2);
      assert.ok(Reflect.get(f.device, "memory") === undefined);
    } finally {await f.close();}
  });

  test("review5: recovery must preserve another object refresh claim", async () => {
    const f = await rejoinFixture(), started = deferred<void>(), response = deferred<void>();
    let refresh: Promise<unknown> | undefined;
    try {
      await f.memorySignup();
      f.refreshHook(async () => {started.resolve(); await response.promise;});
      refresh = f.b.invoke("auth.refresh", {refresh_token: f.first.refresh_token}); await started.promise;
      const marker = (await f.read()).refresh;
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      assert.ok((await f.read()).refresh === marker && f.calls.refresh === 1 && f.calls.protected === 0);
      response.resolve(); await refresh;
    } finally {response.resolve(); await refresh?.catch(() => {}); await f.close();}
  });

  for (const failedRead of [false, true]) test("review5: recovery must preserve another object unknown auth mark" +
    (failedRead ? " (recovery reread failure)" : ""), async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup();
      f.signinHook(async () => {throw new ClientError("unavailable", undefined, true);});
      await assert.rejects(f.b.invoke("auth.signin", {}));
      const pending = (await f.read()).pending;
      assert.ok(pending.length === 1);
      if (failedRead) f.failReadAfter(1);
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      assert.deepEqual((await f.read()).pending, pending);
      assert.ok(f.calls.protected === 0);
    } finally {await f.close();}
  });

  test("STORE-REJOIN own refresh with peer attempt cleanup", async () => {
    const f = await rejoinFixture();
    try {
      await f.a.invoke("auth.signup", {email: "removed@example.com"});
      f.fail(value => value.session?.refreshToken === f.rotated.refresh_token);
      await f.a.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      await f.b.invoke("auth.signup", {email: "peer@example.com"});
      /** Peer cleanup is prepared at the real commit boundary; server consumption is not exercised. */
      await f.peer(value => {
        value.attempts = value.attempts.filter((item: any) => item.email !== "removed@example.com");
        value.session = Object.fromEntries(Object.entries(value.session).reverse());
      });
      await f.a.invoke("notes.list", {});
      const saved = await f.read();
      assert.ok(saved.session.refreshToken === f.rotated.refresh_token && saved.refresh === undefined);
      assert.deepEqual(saved.attempts.map((item: any) => item.email), ["peer@example.com"]);
      assert.ok(f.calls.refresh === 1 && Reflect.get(f.device, "memory") === undefined);
    } finally {await f.close();}
  });

  test("STORE-REJOIN own verification preserves consumed email scope", async () => {
    const f = await rejoinFixture();
    try {
      await f.a.invoke("auth.signup", {email: "consumed@example.com"});
      f.fail(value => value.session?.sessionId === f.verified.session_id);
      await f.a.invoke("auth.verify_email", {attempt: f.attempts.get("consumed@example.com"), code: "123456"});
      assert.ok(Reflect.get(f.device, "memory"));
      await f.b.invoke("auth.signup", {email: "consumed@example.com"});
      await f.b.invoke("auth.signup", {email: "other@example.com"});
      await f.a.invoke("notes.list", {});
      const saved = await f.read();
      assert.ok(saved.session.sessionId === f.verified.session_id && f.access() === "Bearer " + f.verified.access_token);
      assert.deepEqual(saved.attempts.map((item: any) => item.email), ["other@example.com"]);
      assert.ok(Reflect.get(f.device, "memory") === undefined && f.calls.verify === 1);
    } finally {await f.close();}
  });

  test("STORE-REJOIN own refresh with peer pending", async () => {
    const f = await rejoinFixture(), started = deferred<void>(), response = deferred<void>();
    let signup: Promise<unknown> | undefined;
    try {
      f.fail(value => value.session?.refreshToken === f.rotated.refresh_token);
      await f.a.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      f.signupHook(async () => {started.resolve(); await response.promise;});
      signup = f.b.invoke("auth.signup", {email: "peer@example.com"}); await started.promise;
      const marker = (await f.read()).pending[0];
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      const saved = await f.read();
      assert.ok(saved.session.refreshToken === f.rotated.refresh_token && saved.refresh === undefined);
      assert.deepEqual(saved.pending, [marker]);
      response.resolve(); await signup;
      await f.a.invoke("notes.list", {});
      assert.ok(f.access() === "Bearer " + f.rotated.access_token && f.calls.refresh === 1);
    } finally {response.resolve(); await signup?.catch(() => {}); await f.close();}
  });

  test("STORE-REJOIN own refresh with peer pending (auth generation changes)", async () => {
    const f = await rejoinFixture(), started = deferred<void>(), response = deferred<void>();
    let signin: Promise<unknown> | undefined;
    try {
      f.fail(value => value.session?.refreshToken === f.rotated.refresh_token);
      await f.a.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      f.first.session_id = randomUUID();
      f.signinHook(async () => {started.resolve(); await response.promise;});
      signin = f.b.invoke("auth.signin", {}); await started.promise;
      assert.ok((await f.read()).pending.length === 1);
      response.resolve(); await signin;
      const raw = await f.store.read();
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      assert.ok(await f.store.read() === raw && f.calls.protected === 0);
      assert.ok(Reflect.get(f.device, "memory") === undefined);
      await f.a.invoke("notes.list", {});
      assert.ok(f.calls.protected === 1 && f.calls.refresh === 1);
    } finally {response.resolve(); await signin?.catch(() => {}); await f.close();}
  });

  test("STORE-REJOIN E1 login preserves access after unrelated peer write", async () => {
    const f = await rejoinFixture();
    try {
      await f.a.invoke("auth.logout", {});
      f.first.session_id = randomUUID();
      f.fail(value => value.session?.sessionId === f.first.session_id);
      await f.a.invoke("auth.signin", {});
      assert.ok(Reflect.get(f.device, "memory"));
      await f.b.invoke("auth.signup", {email: "peer@example.com"});
      await f.a.invoke("notes.list", {});
      const saved = await f.read();
      assert.ok(!saved.blocked && saved.session.sessionId === f.first.session_id);
      assert.deepEqual(saved.attempts.map((item: any) => item.email), ["peer@example.com"]);
      assert.ok(f.access() === "Bearer " + f.first.access_token && Reflect.get(f.device, "memory") === undefined);
      assert.ok(f.calls.signin === 2 && f.calls.refresh === 0);
    } finally {await f.close();}
  });

  test("STORE-REJOIN preserves an unowned blocked boolean", async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup(); await f.peer(value => {value.blocked = true;});
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      assert.ok((await f.read()).blocked && f.calls.protected === 0);
    } finally {await f.close();}
  });

  test("STORE-REJOIN merge bounds and CAS conflict (byte bound)", async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup(false);
      await f.peer(value => {
        value.pending = [];
        for (let index = 0; ; index++) {
          const key = ("filler-" + index).padEnd(64, "x"); value.selections[key] = "0";
          if (new TextEncoder().encode(JSON.stringify(value)).length > 8180) {delete value.selections[key]; break;}
        }
      });
      const before = await f.store.read();
      assert.ok(new TextEncoder().encode(before!).length <= 8192);
      const memory = Reflect.get(f.device, "memory"), persisted = JSON.parse(before!);
      assert.ok(new TextEncoder().encode(JSON.stringify(memory)).length <= 8192);
      assert.ok(new TextEncoder().encode(JSON.stringify({...persisted, attempts: [...persisted.attempts, ...memory.attempts]})).length > 8192);
      await f.a.invoke("auth.bot_config", {});
      assert.ok(await f.store.read() === before && Reflect.get(f.device, "memory"));
      await f.peer(value => {value.selections = {};});
      await f.a.invoke("auth.bot_config", {});
      assert.ok((await f.read()).attempts.some((item: any) => item.email === "memory@example.com"));
      assert.ok(Reflect.get(f.device, "memory") === undefined);
    } finally {await f.close();}
  });

  test("STORE-REJOIN peer rotation is not proof of an own commit", async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup(false); await f.peer(value => {value.pending = [];});
      await f.b.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      f.fail(value => value.session?.refreshToken === f.rotated.refresh_token);
      await f.a.invoke("auth.bot_config", {});
      assert.ok(Reflect.get(f.device, "memory") && (await f.read()).attempts.length === 0);
      await f.a.invoke("auth.bot_config", {});
      assert.ok((await f.read()).attempts.some((item: any) => item.email === "memory@example.com"));
      assert.ok(Reflect.get(f.device, "memory") === undefined && f.calls.refresh === 1 && f.calls.signup === 1);
    } finally {await f.close();}
  });

  for (const peerChange of [false, true]) test("STORE-REJOIN uncertain commit already applied" +
    (peerChange ? " with peer attempts" : ""), async () => {
    const f = await rejoinFixture();
    try {
      f.fail(value => value.authGeneration === "2", true);
      /** A new session identity uses the existing sign-in transition. */
      f.first.session_id = randomUUID();
      await f.a.invoke("auth.signin", {});
      assert.ok(Reflect.get(f.device, "memory"));
      if (peerChange) await f.b.invoke("auth.signup", {email: "peer@example.com"});
      await f.a.invoke("notes.list", {});
      assert.ok(f.access() === "Bearer " + f.first.access_token);
      assert.ok((await f.read()).attempts.length === (peerChange ? 1 : 0));
      assert.ok(Reflect.get(f.device, "memory") === undefined && f.calls.signin === 2);
    } finally {await f.close();}
  });

  test("STORE-REJOIN uncertain commit then refresh with new session during read outage", async () => {
    const f = await rejoinFixture(), refreshing = deferred<void>(), refreshed = deferred<void>();
    const signingIn = deferred<void>(), signedIn = deferred<void>();
    let refresh: Promise<unknown> | undefined, signin: Promise<unknown> | undefined;
    try {
      await f.a.invoke("auth.signup", {email: "kept@example.com"});
      f.refreshHook(async () => {refreshing.resolve(); await refreshed.promise;});
      refresh = f.a.invoke("auth.refresh", {refresh_token: f.first.refresh_token}); await refreshing.promise;
      const next = credential(); Object.assign(f.first, next);
      f.signinHook(async () => {signingIn.resolve(); await signedIn.promise;});
      signin = f.a.invoke("auth.signin", {email: "next@example.com"}); await signingIn.promise;
      const before = await f.read();
      assert.ok(before.refresh && before.pending.length === 1);
      assert.notEqual(next.session_id, before.session.sessionId);
      f.fail(value => value.session?.refreshToken === f.rotated.refresh_token, true);
      refreshed.resolve(); await refresh;
      const candidate = Reflect.get(f.device, "memoryGeneration").candidate;
      assert.equal(candidate.bundle.authGeneration, before.authGeneration);
      assert.equal(candidate.raw, await f.store.read());
      assert.equal(candidate.bundle.session.refreshToken, f.rotated.refresh_token);
      f.failReadAfter(0); signedIn.resolve(); await signin;
      const memory = Reflect.get(f.device, "memory"), recovery = Reflect.get(f.device, "memoryGeneration");
      const targetGeneration = String(BigInt(before.authGeneration) + 1n);
      assert.equal(recovery.candidate.raw, candidate.raw);
      assert.equal(recovery.candidate.bundle.authGeneration, before.authGeneration);
      assert.equal(memory.authGeneration, targetGeneration);
      assert.equal(memory.session.sessionId, next.session_id);
      const calls = {...f.calls};
      await f.a.invoke("notes.list", {});
      const saved = await f.read();
      assert.equal(f.access(), "Bearer " + next.access_token);
      assert.deepEqual(saved.session, {accessToken: next.access_token, refreshToken: next.refresh_token,
        userId: next.user_id, sessionId: next.session_id, expiresAt: next.expires_at,
        refreshExpiresAt: next.refresh_expires_at});
      assert.equal(saved.authGeneration, targetGeneration);
      assert.deepEqual(saved.attempts, before.attempts); assert.deepEqual(saved.selections, before.selections);
      assert.equal(Reflect.get(f.device, "memory"), undefined);
      assert.equal(Reflect.get(f.device, "memoryGeneration"), undefined);
      assert.equal(f.calls.refresh, calls.refresh); assert.equal(f.calls.signin, calls.signin);
      assert.equal(calls.refresh, 1); assert.equal(calls.signin, 2);
    } finally {
      refreshed.resolve(); signedIn.resolve(); await refresh?.catch(() => {});
      await signin?.catch(() => {}); await f.close();
    }
  });

  test("STORE-REJOIN logout failure remains blocked", async () => {
    const f = await rejoinFixture();
    try {
      f.fail(value => value.blocked);
      await assert.rejects(f.a.invoke("auth.logout", {}), unavailable);
      await f.memorySignup();
      await f.a.invoke("auth.bot_config", {});
      await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
      assert.ok(f.calls.protected === 0);
    } finally {await f.close();}
  });

  for (const remove of [false, true]) test("recovery 6 unchanged auth preserves peer attempt additions and removals" +
    (remove ? " (removal)" : " (addition)"), async () => {
    const f = await rejoinFixture();
    try {
      await f.a.invoke("auth.signup", {email: "base@example.com"});
      await f.memorySignup(false);
      await f.peer(value => {value.pending = []; if (remove) value.attempts = [];});
      await f.b.invoke("auth.signup", {email: "peer@example.com"});
      await f.a.invoke("auth.bot_config", {});
      const saved = await f.read(), expected = ["memory@example.com", "peer@example.com"];
      if (!remove) expected.push("base@example.com");
      assert.deepEqual(saved.attempts.map((item: any) => item.email).sort(), expected.sort());
      assert.ok(Reflect.get(f.device, "memory") === undefined);
      await new HttpTransport(origin, scoped("a", {persist: {dir: f.dir}})).invoke("auth.send_verification_email", {});
      assert.ok(f.attempt() === f.attempts.get("memory@example.com"));
    } finally {await f.close();}
  });

  test("recovery 7 changed auth does not resurrect consumed attempts", async () => {
    const f = await rejoinFixture();
    try {
      await f.a.invoke("auth.signup", {email: "consumed@example.com"});
      await f.memorySignup(false);
      /** Completed same-email cleanup is prepared at the bridge commit boundary. */
      f.fail(value => value.attempts.every((item: any) => item.email !== "consumed@example.com"));
      await f.device.update(undefined, (value: any) => {
        value.attempts = value.attempts.filter((item: any) => item.email !== "consumed@example.com"); return true;
      }, true);
      await f.peer(value => {value.pending = [];});
      await f.b.invoke("auth.signup", {email: "peer@example.com"});
      await f.b.invoke("auth.refresh", {refresh_token: f.first.refresh_token});
      await f.a.invoke("notes.list", {});
      const saved = await f.read();
      assert.ok(saved.session.refreshToken === f.rotated.refresh_token);
      assert.deepEqual(saved.attempts.map((item: any) => item.email).sort(), ["memory@example.com", "peer@example.com"]);
    } finally {await f.close();}
  });

  for (const conflict of [false, true]) test("STORE-REJOIN merge bounds and CAS conflict" +
    (conflict ? " (conflict)" : " (attempt bound)"), async () => {
    const f = await rejoinFixture();
    try {
      await f.memorySignup(false); await f.peer(value => {value.pending = [];});
      for (const email of (conflict ? ["peer@example.com"] : ["b@example.com", "c@example.com", "d@example.com"])) {
        await f.b.invoke("auth.signup", {email});
      }
      const before = await f.store.read();
      if (conflict) {
        let conflicts = 0;
        const wrapped = await f.device.storage();
        Reflect.set(f.device, "store", Promise.resolve({read: () => wrapped.read(), async swap(expected, raw, reset) {
          if (conflicts++ === 0) {await f.peer(value => {value.pending.push(randomUUID());}); return false;}
          return wrapped.swap(expected, raw, reset);
        }} satisfies Store));
        await assert.rejects(f.a.invoke("notes.list", {}), locallyUnauthenticated);
        assert.ok(conflicts === 2 && (await f.read()).pending.length === 1);
        assert.ok((await f.read()).attempts.some((item: any) => item.email === "peer@example.com"));
      } else {
        await f.a.invoke("auth.bot_config", {});
        assert.ok(await f.store.read() === before && Reflect.get(f.device, "memory"));
        await f.peer(value => {value.attempts.pop();});
        await f.a.invoke("auth.bot_config", {});
        assert.ok((await f.read()).attempts.length === 3 && Reflect.get(f.device, "memory") === undefined);
      }
      assert.ok(f.calls.refresh === 0 && f.calls.signin === 1);
    } finally {await f.close();}
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
        outgoing.end('<script type="module">import {BrowserHttpTransport} from "/transport.js"; window.create=(screen)=>{window.client=new BrowserHttpTransport(location.origin); Reflect.set(window.client,Symbol.for("chickinfry.store.scope.v1"),{appId:"browser-test",projectId:"browser-project",origin:location.origin,screen});Reflect.set(window.client,Symbol.for("chickinfry.store.public.v1"),["catalog.list_items"]);};window.ready=true;</script>');
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
              /** STORE-REJOIN browser two writers: a peer commits after recovery reads its expected value. */
              await first.evaluate(`(async () => {
                window.create("rejoin-a"); await window.client.invoke("auth.bot_config", {});
                const device = window.client.device, store = await device.storage();
                const {ClientError} = await import("/transport.js"); let failed = false;
                device.store = Promise.resolve({read: () => store.read(), async swap(expected, raw, reset) {
                  const saved = await store.swap(expected, raw, reset);
                  if (saved && !failed && JSON.parse(raw).attempts.length === 1) {
                    failed = true; throw new ClientError("failed_precondition");
                  }
                  return saved;
                }});
                await window.client.invoke("auth.signup", {email: "memory@example.com"});
                if (!device.memory) throw new Error("Expected memory recovery.");
              })()`);
              await second.evaluate('window.create("rejoin-b"); window.client.invoke("auth.signup",{email:"peer@example.com"})');
              const hit = deferred<void>(), release = deferred<void>();
              await first.exposeFunction("rejoinSwap", async () => {hit.resolve(); await release.promise;});
              await first.evaluate(`(async () => {
                const device = window.client.device, store = await device.storage(); let paused = false;
                device.store = Promise.resolve({read: () => store.read(), async swap(expected, raw, reset) {
                  if (!paused) {paused = true; await window.rejoinSwap();}
                  return store.swap(expected, raw, reset);
                }});
              })()`);
              const recovering = first.evaluate('window.client.invoke("auth.bot_config",{})');
              try {
                await Promise.race([hit.promise, recovering.then(() => {throw new Error("Recovery skipped conditional replacement.");})]);
                await second.evaluate('window.create("rejoin-c"); window.client.invoke("auth.signup",{email:"concurrent@example.com"})');
                release.resolve(); await recovering;
                const emails = await first.evaluate('JSON.parse(Object.values(localStorage)[0]).attempts.map(value=>value.email).sort()');
                assert.deepEqual(emails, ["concurrent@example.com", "memory@example.com", "peer@example.com"]);
                assert.ok(await first.evaluate('window.client.device.memory === undefined'));
                context.diagnostic("STORE-REJOIN browser two writers: " + name + ", " + (locks ? "Web Locks" : "sequential fallback CAS"));
              } finally {release.resolve(); await recovering.catch(() => {});}
              await first.evaluate('window.client.invoke("auth.logout",{})');
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
