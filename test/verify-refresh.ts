import { strict as assert } from "node:assert";
import { HttpTransport, BrowserHttpTransport, ClientError, OperationError } from "../src/http.js";

class CustomHTTP extends HttpTransport {
  refreshFailed(): void {}
}
new CustomHTTP("https://example.com").refreshFailed();

const oldAccessToken = "a".repeat(43);
const newAccessToken = "c".repeat(43);
let accessToken = oldAccessToken;
let refreshToken = "b".repeat(43);
let refreshes = 0;
let cleared = false;
let rejectRefresh = false;
let refreshExpiresAt = "2099-01-02T00:00:00Z";
interface Credentials {
  accessToken: string; refreshToken: string; expiresAt: string;
  refreshExpiresAt: string; userId: string; sessionId: string;
}
const store = {
  credentials: (): Credentials => ({accessToken,refreshToken,expiresAt:"2099-01-01T00:00:00Z",refreshExpiresAt,userId:"user",sessionId:"session"}),
  refresh: async (operation: (credentials: Credentials) => Promise<Credentials>) => {
    const refreshed = await operation({accessToken,refreshToken,expiresAt:"2099-01-01T00:00:00Z",refreshExpiresAt:"2099-01-02T00:00:00Z",userId:"user",sessionId:"session"});
    accessToken = refreshed.accessToken;
    refreshToken = refreshed.refreshToken;
    refreshExpiresAt = refreshed.refreshExpiresAt;
    return refreshed;
  },
  clear: async (expected: Credentials) => {
    if (expected.accessToken !== accessToken || expected.refreshToken !== refreshToken) return;
    accessToken = ""; refreshToken = ""; cleared = true;
  },
};
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  if (init?.credentials !== "omit" || init.cache !== "no-store") throw new Error("Native credential isolation failed.");
  const url = new URL(String(input));
  if (url.pathname === "/auth.refresh") {
    refreshes += 1;
    if (rejectRefresh) return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
    if (refreshes > 1) return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
    return new Response(JSON.stringify({access_token:newAccessToken,refresh_token:"d".repeat(43),expires_at:"2099-01-01T00:00:00Z",refresh_expires_at:"2099-02-02T00:00:00Z",user_id:"user",session_id:"session"}),{status:200});
  }
  if (new Headers(init?.headers).get("authorization") !== "Bearer "+newAccessToken) {
    return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
  }
  return new Response("{}",{status:200});
};
try {
  const transport = new HttpTransport("https://example.com").withSession(store);
  const secondTransport = new HttpTransport("https://example.com").withSession(store);
  await Promise.all(Array.from({length:8},(_, index) => (index%2 ? secondTransport : transport).invoke("catalog.create",{})));
  if (refreshes !== 1 || accessToken !== newAccessToken || refreshToken !== "d".repeat(43) || cleared) {
    throw new Error("Refresh state mismatch.");
  }
  assert.equal(refreshExpiresAt, "2099-02-02T00:00:00Z", "Rolling expiry was not persisted.");
  rejectRefresh = true;
  accessToken = oldAccessToken;
  refreshToken = "e".repeat(43);
  try {
    await transport.invoke("catalog.create",{});
    throw new Error("rejected refresh was accepted");
  } catch (error) {
    if (!(error instanceof OperationError) || error.status !== 401) throw error;
  }
  assert.ok(cleared, "Failure state mismatch.");
  assert.equal(refreshes, 2);
  let calls = 0;
  globalThis.fetch = async (_input, init) => {
    calls++;
    const headers = new Headers(init?.headers);
    if (headers.has("authorization") || headers.get("x-chik-browser") !== "1" ||
        init?.credentials !== "include" || init.cache !== "no-store" || init.redirect !== "manual") {
      throw new Error("Browser transport boundary failed.");
    }
    return Response.json({error: "invalid_token"}, {status: 401});
  };
  const browser = new BrowserHttpTransport("http://127.0.0.1:8012");
  await Promise.all(Array.from({length: 8}, async () => {
    try { await browser.invoke("catalog.create", {}); throw new Error("Rejected browser request succeeded."); }
    catch (error) { if (!(error instanceof OperationError) || error.status !== 401) throw error; }
  }));
  if (calls !== 8) throw new Error("Browser request was retried.");

  const unknownOutcomes = [
    ["timeout", () => { throw new DOMException("Request timed out.", "TimeoutError"); }],
    ["timeout with successful cleanup", () => { throw new DOMException("Request timed out.", "TimeoutError"); }],
    ["connection dropped", () => { throw new TypeError("Connection dropped."); }],
    ["response body interrupted", () => new Response(new ReadableStream({start(controller) {
      controller.error(new TypeError("Response interrupted."));
    }}))],
    ["unreadable response", () => new Response("{")],
    ["invalid credentials", () => Response.json({})],
    ["persisting rotated credentials", () => Response.json({access_token:newAccessToken,refresh_token:"g".repeat(43),
      expires_at:"2099-01-01T00:00:00Z",refresh_expires_at:"2099-01-02T00:00:00Z",user_id:"user",session_id:"session"})],
  ] as const;
  for (const [name, fail] of unknownOutcomes) {
    let current = store.credentials();
    current = {...current, accessToken: oldAccessToken, refreshToken: "f".repeat(43)};
    const initial = current;
    let attempts = 0;
    let clears = 0;
    let recover = false;
    const unknownStore = {
      credentials: () => current,
      refresh: async (operation: (credentials: Credentials) => Promise<Credentials>) => {
        const updated = await operation(current);
        if (name === "persisting rotated credentials" && !recover) throw new OperationError("invalid_token", 401);
        current = updated;
        return current;
      },
      clear: async (expected: Credentials) => {
        assert.deepEqual(expected, initial);
        clears++;
        if (name === "timeout with successful cleanup") {
          current = {...initial, accessToken:"", refreshToken:""};
          return;
        }
        // Even when storage cleanup fails, credentials with unknown consumption state are not sent again.
        throw new Error("Session storage unavailable.");
      },
    };
    globalThis.fetch = async input => {
      if (new URL(String(input)).pathname === "/auth.refresh") {
        attempts++;
        if (!recover) return fail();
        return Response.json({access_token:newAccessToken,refresh_token:"g".repeat(43),expires_at:initial.expiresAt,
          refresh_expires_at:initial.refreshExpiresAt,user_id:initial.userId,session_id:initial.sessionId});
      }
      return current.accessToken === newAccessToken ? Response.json({}) : Response.json({error:"invalid_token"}, {status:401});
    };
    const first = new HttpTransport("https://example.com").withSession(unknownStore);
    const second = new HttpTransport("https://example.com").withSession(unknownStore);
    const invalidToken = (error: unknown) => (error instanceof OperationError && error.code === "invalid_token" && error.status === 401) || (error instanceof ClientError && ["unauthenticated", "failed_precondition", "deadline_exceeded", "unavailable", "internal"].includes(error.code));
    const results = await Promise.allSettled(Array.from({length:8}, (_, index) =>
      (index % 2 ? first : second).invoke("catalog.create", {})));
    assert.equal(attempts, 1, name);
    await assert.rejects(first.invoke("catalog.create", {}));
    assert.equal(attempts, 1, name);
    assert.ok(results.every(result => result.status === "rejected" && invalidToken(result.reason)), name);
    assert.ok(results.every(result => result.status === "rejected" && result.reason instanceof ClientError && result.reason.outcomeUnknown), name);
    if (name.startsWith("timeout")) assert.ok(results.every(result=>result.status === "rejected" && result.reason.code === "deadline_exceeded"));
    assert.equal(clears, 1, name);
    await assert.rejects(first.invoke("catalog.create", {}), invalidToken, name);
    if (name === "timeout with successful cleanup") {
      assert.throws(() => new HttpTransport("https://example.com").withSession(unknownStore), error => error instanceof ClientError && error.code === "unauthenticated");
    } else {
      await assert.rejects(new HttpTransport("https://example.com").withSession(unknownStore).invoke("catalog.create", {}), invalidToken, name);
    }
    assert.equal(attempts, 1, name);
    recover = true;
    // Recover via the existing explicit call, then resume normal calls with the newly stored credentials.
    const recovered = await first.invoke("auth.refresh", {refresh_token:initial.refreshToken}) as Record<string, string>;
    current = {...initial, accessToken:recovered.access_token, refreshToken:recovered.refresh_token};
    await second.invoke("catalog.create", {});
    assert.equal(attempts, 2, name);
    current = {...initial, refreshToken:"h".repeat(43)};
    await first.invoke("catalog.create", {});
    assert.equal(attempts, 3, name);
  }

  const initial = {...store.credentials(), accessToken:oldAccessToken, refreshToken:"k".repeat(43)};
  const signedIn = {...initial, accessToken:newAccessToken, refreshToken:"l".repeat(43)};
  let current = initial;
  let attempts = 0;
  const racingStore = {
    credentials: () => current,
    refresh: async (operation: (credentials: Credentials) => Promise<Credentials>) => {
      const updated = await operation(current);
      current = updated;
      return updated;
    },
    clear: async (expected: Credentials) => {
      assert.deepEqual(expected, initial);
      if (expected.accessToken === current.accessToken && expected.refreshToken === current.refreshToken) {
        current = {...current, accessToken:"", refreshToken:""};
      }
    },
  };
  globalThis.fetch = async input => {
    if (new URL(String(input)).pathname === "/auth.refresh") {
      attempts++;
      current = signedIn;
      throw new TypeError("Connection dropped after sign-in.");
    }
    return current === signedIn ? Response.json({}) : Response.json({error:"invalid_token"}, {status:401});
  };
  const racingTransport = new HttpTransport("https://example.com").withSession(racingStore);
  await assert.rejects(racingTransport.invoke("catalog.create", {}),
    error => (error instanceof OperationError && error.code === "invalid_token" && error.status === 401) || (error instanceof ClientError && ["unauthenticated", "failed_precondition", "deadline_exceeded", "unavailable", "internal"].includes(error.code)));
  assert.deepEqual(current, signedIn);
  await racingTransport.invoke("catalog.create", {});
  assert.equal(attempts, 1);

  const reviewCases: Array<readonly [string, () => Promise<void>]> = [];
  const invalidToken = (error: unknown) => (error instanceof OperationError && error.code === "invalid_token" && error.status === 401) || (error instanceof ClientError && ["unauthenticated", "failed_precondition", "deadline_exceeded", "unavailable", "internal"].includes(error.code));
  const fresh = (userId = "user-a", sessionId = "session-a"): Credentials => ({
    ...initial, accessToken:"m".repeat(43), refreshToken:"n".repeat(43), userId, sessionId,
  });
  const fixture = () => {
    let credentials = fresh();
    const session = {
      credentials: () => credentials,
      refresh: async (operation: (value: Credentials) => Promise<Credentials>) => {
        const expected = credentials;
        const refreshed = await operation(expected);
        if (credentials.accessToken === expected.accessToken && credentials.refreshToken === expected.refreshToken) credentials = refreshed;
        return credentials;
      },
      clear: async (expected: Credentials) => {
        if (credentials.accessToken === expected.accessToken && credentials.refreshToken === expected.refreshToken) {
          credentials = {...credentials, accessToken:"", refreshToken:""};
        }
      },
    };
    return {session, set: (value: Credentials) => { credentials = value; },
      client: () => new HttpTransport("https://example.com").withSession(session)};
  };
  for (const outcome of ["timeout", "connection dropped", "response interrupted"]) {
    reviewCases.push([`explicit ${outcome} blocks automatic refresh`, async () => {
      const {session, client} = fixture();
      if (outcome === "connection dropped") session.clear = async () => { throw new Error("Session storage unavailable."); };
      const first = client();
      const second = client();
      let refreshCalls = 0;
      globalThis.fetch = async input => {
        if (new URL(String(input)).pathname !== "/auth.refresh") return Response.json({error:"invalid_token"}, {status:401});
        refreshCalls++;
        if (outcome === "timeout") throw new DOMException("Request timed out.", "TimeoutError");
        if (outcome === "connection dropped") throw new TypeError("Connection dropped.");
        return new Response(new ReadableStream({start(controller) { controller.error(new TypeError("Response interrupted.")); }}));
      };
      const input = {refresh_token:session.credentials().refreshToken};
      await assert.rejects(first.invoke("auth.refresh", input));
      const firstCalls = refreshCalls;
      await assert.rejects(first.invoke("catalog.create", {}), invalidToken);
      await assert.rejects(second.invoke("catalog.create", {}), invalidToken);
      assert.ok(refreshCalls === firstCalls, "Explicit failure allowed an automatic refresh.");
      await assert.rejects(second.invoke("auth.refresh", input), invalidToken);
      assert.ok(refreshCalls === firstCalls + 1, "Intentional explicit recovery was blocked.");
      await assert.rejects(first.invoke("catalog.create", {}), invalidToken);
      assert.ok(refreshCalls === firstCalls + 1, "Failed explicit recovery allowed an automatic refresh.");
    }]);
  }
  reviewCases.push(["explicit foreign credential preserves stored session", async () => {
    const {session, set, client} = fixture();
    const first = client();
    const saved = session.credentials();
    let refreshCalls = 0;
    globalThis.fetch = async input => {
      if (new URL(String(input)).pathname !== "/auth.refresh") return Response.json({});
      refreshCalls++;
      throw new TypeError("Connection dropped.");
    };
    await assert.rejects(first.invoke("auth.refresh", {refresh_token:"o".repeat(43)}));
    assert.ok(session.credentials() === saved, "Unrelated explicit refresh cleared the stored session.");
    await first.invoke("catalog.create", {});
    set({...saved, refreshToken:"o".repeat(43)});
    await assert.rejects(client().invoke("catalog.create", {}), invalidToken);
    assert.equal(refreshCalls, 1, "The actual explicit credential was not blocked.");
  }]);
  for (const transition of ["clear", "different user", "new session for same user", "rotation"]) {
    reviewCases.push([`delayed 401 after ${transition}`, async () => {
      const {session, set, client} = fixture();
      const first = client();
      const second = client();
      const saved = session.credentials();
      let release!: (value: Response) => void;
      let received!: () => void;
      const ready = new Promise<void>(resolve => { received = resolve; });
      const delayed = new Promise<Response>(resolve => { release = resolve; });
      let pendingCalls = 0;
      let refreshCalls = 0;
      globalThis.fetch = async (input, init) => {
        if (new URL(String(input)).pathname === "/auth.refresh") {
          refreshCalls++;
          throw new TypeError("Connection dropped.");
        }
        if (JSON.parse(String(init?.body)).pending) {
          pendingCalls++;
          if (pendingCalls === 1) { received(); return delayed; }
          return Response.json({});
        }
        return Response.json({error:"invalid_token"}, {status:401});
      };
      const pending = first.invoke("catalog.create", {pending:true});
      await ready;
      if (transition === "rotation") {
        set({...saved, accessToken:"p".repeat(43), refreshToken:"q".repeat(43)});
      } else {
        await assert.rejects(second.invoke("catalog.create", {}), invalidToken);
        if (transition !== "clear") set({...fresh(transition === "different user" ? "user-b" : saved.userId,
          transition === "different user" ? saved.sessionId : "session-b"), accessToken:"r".repeat(43), refreshToken:"s".repeat(43)});
      }
      release(Response.json({error:"invalid_token"}, {status:401}));
      const result = await pending.then(() => null, error => error);
      assert.equal(pendingCalls, transition === "rotation" ? 2 : 1, "The original request crossed a session boundary.");
      if (transition === "rotation") assert.equal(result, null);
      else assert.ok(invalidToken(result), "A superseded request must fail with invalid_token.");
      assert.equal(refreshCalls, transition === "rotation" ? 0 : 1);
    }]);
  }
  reviewCases.push(["synchronous sign-in preserves initial request credential", async () => {
    const {session, set, client} = fixture();
    const first = client();
    const saved = session.credentials();
    let usedInitial = false;
    globalThis.fetch = async (_input, init) => {
      usedInitial = new Headers(init?.headers).get("authorization") === "Bearer " + saved.accessToken;
      return Response.json({});
    };
    const pending = first.invoke("catalog.create", {});
    set({...fresh("user-b", "session-b"), accessToken:"r".repeat(43), refreshToken:"s".repeat(43)});
    await pending;
    assert.ok(usedInitial, "A synchronous sign-in changed the first request's user.");
    assert.ok(session.credentials().userId === "user-b");
  }]);
  reviewCases.push(["waiting refresh rejects a different sign-in", async () => {
    const {session, set, client} = fixture();
    const first = client();
    const second = client();
    const saved = session.credentials();
    let release!: (value: Response) => void;
    let received!: () => void;
    const ready = new Promise<void>(resolve => { received = resolve; });
    const delayed = new Promise<Response>(resolve => { release = resolve; });
    let calls = 0;
    globalThis.fetch = async input => {
      if (new URL(String(input)).pathname === "/auth.refresh") { received(); return delayed; }
      calls++;
      return calls === 1 ? Response.json({error:"invalid_token"}, {status:401}) : Response.json({});
    };
    const pending = first.invoke("catalog.create", {});
    await ready;
    const waiting = second.invoke("catalog.create", {});
    set({...fresh("user-b", "session-b"), accessToken:"r".repeat(43), refreshToken:"s".repeat(43)});
    release(Response.json({access_token:"p".repeat(43),refresh_token:"q".repeat(43),expires_at:saved.expiresAt,
      refresh_expires_at:saved.refreshExpiresAt,user_id:saved.userId,session_id:saved.sessionId}));
    const results = await Promise.allSettled([pending, waiting]);
    assert.equal(calls, 1, "A request waiting on refresh switched to the new sign-in.");
    assert.ok(results.every(result => result.status === "rejected" && invalidToken(result.reason)));
    assert.ok(session.credentials().userId === "user-b");
  }]);
  reviewCases.push(["stored callback honors a later explicit refresh failure", async () => {
    const {session, client} = fixture();
    const automatic = client();
    const explicit = client();
    let resume!: () => void;
    let received!: () => void;
    const ready = new Promise<void>(resolve => { received = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const refresh = session.refresh;
    session.refresh = async operation => {
      received();
      await gate;
      return refresh(operation);
    };
    session.clear = async () => { throw new Error("Session storage unavailable."); };
    let refreshCalls = 0;
    globalThis.fetch = async input => {
      if (new URL(String(input)).pathname !== "/auth.refresh") return Response.json({error:"invalid_token"}, {status:401});
      refreshCalls++;
      throw new TypeError("Connection dropped.");
    };
    const pending = automatic.invoke("catalog.create", {});
    await ready;
    await assert.rejects(explicit.invoke("auth.refresh", {refresh_token:session.credentials().refreshToken}), invalidToken);
    assert.equal(refreshCalls, 1);
    resume();
    const result = await pending.then(() => null, error => error);
    assert.equal(refreshCalls, 1, "A stored callback resent a refresh after its explicit failure.");
    assert.ok(invalidToken(result), "The blocked callback must fail with invalid_token.");
    await assert.rejects(explicit.invoke("catalog.create", {}), invalidToken);
    await assert.rejects(client().invoke("catalog.create", {}), invalidToken);
    assert.equal(refreshCalls, 1, "Callback cleanup removed the shared failure.");
  }]);
  const refreshErrorResponses: ReadonlyArray<readonly [number, string]> = [
    [400, "invalid_input"],
    [403, "permission_denied"],
    [429, "rate_limited"],
    [500, "operation_failed"],
    [503, "unavailable"],
  ];
  for (const [status, code] of refreshErrorResponses) {
    for (const start of ["automatic", "explicit"]) {
      reviewCases.push([`${start} refresh ${status} pauses automatic reuse`, async () => {
        const {session, client} = fixture();
        const first = client();
        const second = client();
        const saved = session.credentials();
        let clears = 0;
        session.clear = async expected => {
          assert.ok(expected.accessToken === saved.accessToken && expected.refreshToken === saved.refreshToken);
          clears++;
          throw new Error("Session storage unavailable.");
        };
        let refreshCalls = 0;
        globalThis.fetch = async input => {
          if (new URL(String(input)).pathname !== "/auth.refresh") return Response.json({error:"invalid_token"}, {status:401});
          refreshCalls++;
          return Response.json({error:code}, {status});
        };
        const result = await first.invoke(start === "automatic" ? "catalog.create" : "auth.refresh",
          start === "automatic" ? {} : {refresh_token:saved.refreshToken}).then(() => null, error => error);
        assert.equal(refreshCalls, 1);
        const next = await second.invoke("catalog.create", {}).then(() => null, error => error);
        assert.equal(refreshCalls, 1, "A non-401 refresh error allowed automatic reuse.");
        assert.ok(invalidToken(result) && invalidToken(next), "An unknown refresh outcome must fail with invalid_token.");
        assert.equal(clears, 1);
        await assert.rejects(first.invoke("catalog.create", {}), invalidToken);
        await assert.rejects(client().invoke("catalog.create", {}), invalidToken);
        assert.equal(refreshCalls, 1);
      }]);
    }
  }
  for (const start of ["automatic", "explicit"]) {
    reviewCases.push([`${start} refresh 401 remains a definitive rejection`, async () => {
      const {session, set, client} = fixture();
      const first = client();
      const saved = session.credentials();
      let refreshCalls = 0;
      globalThis.fetch = async input => {
        if (new URL(String(input)).pathname === "/auth.refresh") refreshCalls++;
        return Response.json({error:"invalid_token"}, {status:401});
      };
      await assert.rejects(first.invoke(start === "automatic" ? "catalog.create" : "auth.refresh",
        start === "automatic" ? {} : {refresh_token:saved.refreshToken}), invalidToken);
      assert.ok(session.credentials().accessToken === "" && session.credentials().refreshToken === "");
      set(saved);
      await assert.rejects(client().invoke("catalog.create", {}), invalidToken);
      assert.equal(refreshCalls, 2, "A definitive 401 was incorrectly cached as an unknown outcome.");
    }]);
  }
  const failures: string[] = [];
  for (const [name, run] of reviewCases) {
    try { await run(); }
    catch { failures.push(name); }
  }
  assert.deepEqual(failures, [], "Refresh review scenarios failed: " + failures.join(", "));
} finally {
  globalThis.fetch = originalFetch;
}
