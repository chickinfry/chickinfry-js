import assert from "node:assert/strict";
import {mock, test} from "node:test";
import {mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync} from "node:fs";
import {createRequire} from "node:module";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {createRealtimeClient, sessionRenewal} from "../dist/realtime/client.js";
import {BrowserHttpTransport, ClientError, OperationError, HttpTransport, MemoryStore, type SessionCredentials} from "../dist/http.js";

const consumer = mkdtempSync(join(tmpdir(), "chickinfry-realtime-"));
try {
  const scope = join(consumer, "node_modules", "@chickinfry");
  mkdirSync(scope, {recursive: true});
  const runtime = fileURLToPath(new URL("../dist/realtime/", import.meta.url));
  symlinkSync(runtime, join(scope, "chickinfry-realtime"), "dir");
  const resolve = createRequire(join(consumer, "client.js")).resolve;
  const client = resolve("@chickinfry/chickinfry-realtime");
  assert.equal(realpathSync(client), realpathSync(join(runtime, "client.js")));
  assert.equal(typeof (await import(pathToFileURL(client).href)).createRealtimeClient, "function");
} finally { rmSync(consumer, {recursive: true, force: true}); }

const address="wss://33333333-3333-4333-8333-333333333333.chickinfry.app/realtime";
const ticket="11111111-1111-4111-8111-111111111111";
const connections:string[]=[];
let closedSockets = 0;
const original=globalThis.WebSocket;
class Socket {
  onopen:(()=>void)|null=null;
  onmessage:((event:{data:string})=>void)|null=null;
  onclose:(()=>void)|null=null;
  onerror:(()=>void)|null=null;
  static OPEN=1;
  readyState=1;
  constructor(url:string){connections.push(url);queueMicrotask(()=>{this.onopen?.();});}
  send(frame:string){const value=JSON.parse(frame);if(value.type==="subscribe" || value.type==="confirm")queueMicrotask(()=>this.onmessage?.({data:JSON.stringify({type:"ready",channel:value.channel,cursor:"",confirmation:value.confirmation})}));}
  close(){closedSockets++;}
}
Reflect.set(globalThis,"WebSocket",Socket);
try{
  for(const endpoint of [undefined,"invalid", "ws://example.test/realtime","wss://example.test/realtime",address+"?ticket=other",address+"#part",address.replace("/realtime","/other"),address.replace("33333333-3333-4333-8333-333333333333","r-33333333-3333-4333-8333-333333333333")]){
    await assert.rejects(createRealtimeClient({invoke:async()=>({ticket,endpoint})}).subscribe("news"), error => error instanceof ClientError && error.code === "internal");
  }
  assert.equal(connections.length,0);
  const subscription=await createRealtimeClient({invoke:async()=>({ticket,endpoint:address})}).subscribe("news");
  assert.deepEqual(connections,[address+"?ticket="+ticket]);
  await subscription.unsubscribe();
  const originalFetch = globalThis.fetch;
  try {
    const isolatedOrigin = "https://22222222-2222-4222-8222-222222222222.chickinfry.io";
    const isolatedEndpoint = "wss://33333333-3333-4333-8333-333333333333.chickinfry.io/realtime";
    for (const transport of [new HttpTransport(isolatedOrigin), new BrowserHttpTransport(isolatedOrigin)]) {
      globalThis.fetch = async input => {
        assert.equal(String(input), isolatedOrigin+"/realtime.ticket");
        return Response.json({ticket, endpoint: isolatedEndpoint});
      };
      const isolated = await createRealtimeClient(transport).subscribe("news");
      assert.equal(connections.at(-1), isolatedEndpoint+"?ticket="+ticket);
      await isolated.unsubscribe();
    }
    const connectionCount = connections.length;
    for (const [issuer, endpoint] of [
      ["https://22222222-2222-4222-8222-222222222222.chickinfry.app", isolatedEndpoint],
      [isolatedOrigin+".example.com", isolatedEndpoint],
      [isolatedOrigin.replace("22222222-2222-4222-8222-222222222222", "custom"), isolatedEndpoint],
      [isolatedOrigin+":8443", isolatedEndpoint],
      [isolatedOrigin, address],
      [isolatedOrigin, isolatedEndpoint.replace(".io/", ".io.example.com/")],
    ]) {
      globalThis.fetch = async () => Response.json({ticket, endpoint});
      await assert.rejects(createRealtimeClient(new HttpTransport(issuer)).subscribe("news"),
        error => error instanceof ClientError && error.code === "internal");
    }
    await assert.rejects(createRealtimeClient({invoke:async()=>({ticket,endpoint:isolatedEndpoint})}).subscribe("news"),
      error => error instanceof ClientError && error.code === "internal");
    assert.equal(connections.length, connectionCount);

    let requests = 0;
    globalThis.fetch = async () => ++requests === 1 ? Response.json(null) : Response.json({ticket, endpoint: address});
    await assert.rejects(createRealtimeClient(new HttpTransport("https://example.com")).subscribe("news"),
      error => error instanceof ClientError && error.code === "internal");
    assert.equal(requests, 1, "A malformed ticket must fail without retrying.");
    for (const error of [new TypeError("Network unavailable."), new DOMException("Request timed out.", "TimeoutError")]) {
      let requests = 0;
      globalThis.fetch = async () => {
        if (++requests === 1) throw error;
        return Response.json({ticket, endpoint: address});
      };
      const subscription = await createRealtimeClient(new HttpTransport("https://example.com")).subscribe("news");
      try {

        assert.equal(requests, 2);
      } finally { await subscription.unsubscribe(); }
    }
  } finally { globalThis.fetch = originalFetch; }
}finally{Reflect.set(globalThis,"WebSocket",original);}
console.log("Validated realtime endpoint and ticket-only connection: verified");

let credentials: SessionCredentials = {
  accessToken:"a".repeat(43), refreshToken:"b".repeat(43),
  expiresAt:"2099-01-01T00:00:00Z", refreshExpiresAt:"2099-01-02T00:00:00Z",
  userId:"user", sessionId:"session",
};
const store = {
  credentials: () => credentials,
  refresh: async (operation: (value: SessionCredentials) => Promise<SessionCredentials>) => {
    credentials = await operation(credentials);
    return credentials;
  },
  clear: async (expected: SessionCredentials) => { assert.fail("Successful renewal cleared the session."); },
};
const transport = new HttpTransport("https://example.com").withSession(store);
const renewal = sessionRenewal(transport)!;
const otherRenewal = sessionRenewal(new HttpTransport("https://example.com").withSession(store))!;
const originalFetch = globalThis.fetch;
let refreshes = 0;
globalThis.fetch = async (input, init) => {
  assert.equal(String(input), "https://example.com/auth.refresh");
  assert.deepEqual(JSON.parse(String(init?.body)), {refresh_token:"b".repeat(43)});
  refreshes++;
  return Response.json({access_token:"c".repeat(43), refresh_token:"d".repeat(43),
    expires_at:credentials.expiresAt, refresh_expires_at:credentials.refreshExpiresAt,
    user_id:credentials.userId, session_id:credentials.sessionId});
};
try {
  assert.equal(sessionRenewal(transport), renewal);
  assert.equal(renewal.dueAt(), Date.parse(credentials.expiresAt));
  await Promise.all([renewal.renew(), otherRenewal.renew()]);
  assert.equal(refreshes, 1);
  assert.equal(credentials.accessToken, "c".repeat(43));
  assert.equal(credentials.refreshToken, "d".repeat(43));
  const session = new MemoryStore(credentials);
  globalThis.fetch = async () => Response.json({ticket, endpoint: address});
  Reflect.set(globalThis, "WebSocket", Socket);
  mock.timers.enable({apis: ["setTimeout"]});
  const subscription = await createRealtimeClient(new HttpTransport("https://example.com").withSession(session)).subscribe("news");
  try {

    const closed = closedSockets;
    await session.clear(session.credentials());
    assert.doesNotThrow(() => mock.timers.tick(2_147_000_000), "Session removal must not escape the renewal timer.");
    await assert.rejects(subscription.events[Symbol.asyncIterator]().next(), error =>
      error instanceof ClientError && error.code === "unauthenticated");
    assert.equal(closedSockets, closed + 1, "Renewal failure must close the subscription.");
  } finally {
    await subscription.unsubscribe();
    mock.timers.reset();
    Reflect.set(globalThis, "WebSocket", original);
  }
} finally { globalThis.fetch = originalFetch; }
console.log("Realtime renewal uses shared native credential refresh: verified");

// Contract scenarios share the existing ticket and socket verification harness.
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return {promise, resolve}; };
const cursorA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const cursorB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const cursorC = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
class Peer {
  static OPEN = 1;
  static sockets: Peer[] = [];
  static openingGap = false;
  readyState = 1;
  onopen: (() => void) | null = null;
  onmessage: ((event: {data: string}) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  frames: Record<string, any>[] = [];
  constructor(_url: string) { Peer.sockets.push(this); queueMicrotask(() => this.onopen?.()); }
  send(text: string) {
    const frame = JSON.parse(text);
    this.frames.push(frame);
    if (frame.type === "subscribe") queueMicrotask(() => {
      if (Peer.openingGap) { Peer.openingGap = false; this.gap(cursorA); }
      this.frame({type: "ready", cursor: frame.cursor ?? ""});
    });
  }
  frame(frame: Record<string, unknown>) { this.onmessage?.({data: JSON.stringify({channel: "news", ...frame})}); }
  event(cursor: string, previous: string = "") { this.frame({type: "event", cursor, previous, payload: cursor}); }
  gap(cursor: string) { this.frame({type: "gap", cursor}); }
  confirm() { const frame = this.frames.findLast(f => f.type === "confirm"); assert.ok(frame, "SDK must request a fresh confirmation."); this.frame({type: "ready", cursor: "", confirmation: frame.confirmation}); }
  close() { if (this.readyState === 3) return; this.readyState = 3; this.onclose?.(); }
}
const code = (expected: string) => (error: unknown) => error instanceof ClientError && error.code === expected && error.status === undefined;
async function scenario(body: (open: (onGap?: (gap: any) => Promise<void>, invoke?: () => Promise<any>) => Promise<any>) => Promise<void>) {
  Reflect.set(globalThis, "WebSocket", Peer);
  Peer.sockets = [];
  Peer.openingGap = false;
  mock.timers.enable({apis: ["setTimeout", "Date"], now: 0});
  const owned: any[] = [];
  try {
    await body(async (onGap, invoke) => {
      const raw: any = createRealtimeClient({invoke: invoke ?? (async () => ({ticket, endpoint: address}))}).subscribe("news", {onGap});
      const pending = Promise.resolve(raw);
      void pending.catch(() => undefined);
      await flush();
      if (Peer.sockets.at(-1)?.frames.some(f => f.type === "confirm")) Peer.sockets.at(-1)!.confirm();
      await flush();
      const subscription = await pending;
      if (subscription.ready) await subscription.ready;
      owned.push(subscription);
      return subscription;
    });
  } finally {
    for (const subscription of owned) await subscription.unsubscribe();
    mock.timers.reset();
    Reflect.set(globalThis, "WebSocket", original);
  }
}
const events = (s: any): AsyncIterator<any> => (s.events ?? s)[Symbol.asyncIterator]();
const reconnect = async () => { await flush(); mock.timers.tick(500); await flush(); };

await test("normal reconnects keep pending Promise handlers bounded", async () => scenario(async open => {
  const waiting = new Map<Promise<unknown>, number>();
  const then = Promise.prototype.then;
  Promise.prototype.then = function (onFulfilled, onRejected) {
    if (!waiting.has(this)) {
      waiting.set(this, 0);
      const settled = () => { waiting.delete(this); };
      then.call(this, settled, settled);
    }
    waiting.set(this, waiting.get(this)! + 1);
    return then.call(this, onFulfilled, onRejected);
  };
  try {
    let gaps = 0;
    await open(async () => { gaps++; });
    for (let i = 0; i < 100; i++) {
      Peer.sockets.at(-1)!.close();
      await reconnect();
      Peer.sockets.at(-1)!.confirm();
      await flush();
    }
    assert.equal(Peer.sockets.length, 101);
    assert.equal(gaps, 0);
    const handlers = Math.max(0, ...waiting.values());
    assert.ok(handlers <= 1, `A pending Promise retained ${handlers} handlers after 100 normal reconnects.`);
  } finally { Promise.prototype.then = then; }
}));

await test("unsubscribe finishes during a pending ticket and discards its late completion", async () => scenario(async open => {
  const gate = deferred(); let requests = 0;
  const subscription = await open(undefined, async () => {
    if (++requests > 1) await gate.promise;
    return {ticket, endpoint: address};
  });
  try {
    Peer.sockets.at(-1)!.close();
    await reconnect();
    assert.equal(requests, 2);
    let stopped = false;
    const stopping = subscription.unsubscribe().then(() => { stopped = true; });
    await flush();
    assert.equal(stopped, true);
    await stopping;
    gate.resolve();
    await flush();
    assert.equal(Peer.sockets.length, 1);
    assert.equal((await events(subscription).next()).done, true);
  } finally { gate.resolve(); }
}));

await test("previous awaited event completes before gap recovery; replay waits for fresh confirmation", async () => scenario(async open => {
  const order: string[] = [];
  const subscription = await open(async () => { order.push("gap"); });
  const iterator = events(subscription);
  Peer.sockets.at(-1)!.event(cursorA);
  await iterator.next();
  Peer.sockets.at(-1)!.gap(cursorB);
  await flush();
  assert.deepEqual(order, []);
  order.push("applied");
  const next = iterator.next();
  let delivered = false; void next.then(() => { delivered = true; });
  await flush(); await reconnect();
  assert.deepEqual(order, ["applied", "gap"]);
  const current = Peer.sockets.at(-1)!;
  assert.equal(current.frames.find(f => f.type === "subscribe")?.cursor, cursorB);
  current.event(cursorC, cursorB);
  await flush(); assert.equal(delivered, false);
  current.confirm();
  assert.deepEqual((await next).value, {type: "event", channel: "news", payload: cursorC});
}));

await test("reconnect during onGap preserves G and requires replay on the current K", async () => scenario(async open => {
  const gate = deferred(); let calls = 0;
  const s = await open(async () => { calls++; await gate.promise; });
  const iterator = events(s);
  const old = Peer.sockets.at(-1)!;
  old.gap(cursorA);
  const next = iterator.next(); let delivered = false; void next.then(() => { delivered = true; });
  await flush(); old.close(); await reconnect();
  Peer.sockets.at(-1)!.confirm();
  gate.resolve(); await flush(); await reconnect();
  const current = Peer.sockets.at(-1)!;
  current.event(cursorB, cursorA);
  old.frame({type: "ready", cursor: cursorA});
  await flush(); assert.equal(delivered, false);
  assert.equal(calls, 1);
  assert.equal(current.frames.find(f => f.type === "subscribe")?.cursor, cursorA);
  current.confirm(); assert.equal((await next).value.payload, cursorB);
}));

await test("G2 discards stale callback completion and callbacks remain serial", async () => scenario(async open => {
  const first = deferred(); const second = deferred(); let calls = 0;
  const s = await open(async () => { calls++; await (calls === 1 ? first : second).promise; });
  const iterator = events(s);
  Peer.sockets.at(-1)!.gap(cursorA);
  const next = iterator.next();
  await flush(); Peer.sockets.at(-1)!.gap(cursorB); await flush(); assert.equal(calls, 1);
  first.resolve(); await flush(); assert.equal(calls, 2);
  second.resolve(); await flush(); await reconnect();
  const current = Peer.sockets.at(-1)!;
  assert.equal(current.frames.find(f => f.type === "subscribe")?.cursor, cursorB);
  current.confirm(); current.event(cursorC, cursorB);
  assert.equal((await next).value.payload, cursorC);
}));

for (const reason of ["unsubscribe", "authorization"] as const) await test(`late G completion cannot revive ${reason}`, async () => scenario(async open => {
  const gate = deferred(); let calls = 0;
  const s = await open(async () => { calls++; await gate.promise; });
  const iterator = events(s);
  Peer.sockets.at(-1)!.gap(cursorA);
  const next = iterator.next(); void next.catch(() => undefined);
  await flush(); assert.equal(calls, 1);
  if (reason === "unsubscribe") await s.unsubscribe();
  else Peer.sockets.at(-1)!.frame({type: "error", error: "unauthorized_channel"});
  if (reason === "unsubscribe") assert.equal((await next).done, true);
  else await assert.rejects(next, code("permission_denied"));
  const count = Peer.sockets.length;
  gate.resolve(); await flush(); await reconnect();
  assert.equal(Peer.sockets.length, count);
}));

await test("missing onGap fails the first connection with data_loss", async () => scenario(async () => {
  Peer.openingGap = true;
  const result: any = createRealtimeClient({invoke: async () => ({ticket, endpoint: address})}).subscribe("news");
  const failure = Promise.resolve(result).then(async s => { await s.ready; await s.unsubscribe(); });
  void failure.catch(() => undefined); await flush();
  await assert.rejects(failure, code("data_loss"));
}));
await test("missing onGap fails a reconnect gap with data_loss", async () => scenario(async open => {
  const s = await open(); const iterator = events(s);
  Peer.sockets.at(-1)!.close(); await reconnect();
  Peer.sockets.at(-1)!.gap(cursorA);
  await assert.rejects(iterator.next(), code("data_loss"));
  assert.equal((await iterator.next()).done, true);
}));
for (const [wire, expected] of [["unauthorized_channel", "permission_denied"], ["already_subscribed", "internal"]]) await test(`socket ${wire} has distinct ${expected} without HTTP status`, async () => scenario(async open => {
  const s = await open(); Peer.sockets.at(-1)!.frame({type: "error", error: wire});
  await assert.rejects(events(s).next(), code(expected));
}));
await test("callback preserves its original cause without exposing customer values", async () => scenario(async open => {
  const cause = new Error("customer-value-must-stay-private");
  const s = await open(async () => { throw cause; });
  Peer.sockets.at(-1)!.gap(cursorA);
  await assert.rejects(events(s).next(), error => error instanceof ClientError && error.cause === cause && !error.message.includes(cause.message) && error.code === "unknown");
}));
await test("409 after ready ends once with the actual OperationError and no retry", async () => scenario(async open => {
  let requests = 0; const failure = new OperationError("realtime_busy", 409);
  const s = await open(undefined, async () => { if (++requests > 1) throw failure; return {ticket, endpoint: address}; });
  const iterator = events(s); Peer.sockets.at(-1)!.close(); await reconnect();
  const next = iterator.next(); let caught: unknown;
  void next.catch(error => { caught = error; }); await flush();
  assert.equal(caught, failure);
  await assert.rejects(next, error => error === failure);
  assert.equal((await iterator.next()).done, true);
  mock.timers.tick(30_000); await flush(); assert.equal(requests, 2);
}));
await test("close-only reconnects share a 30 second loss budget", async () => scenario(async open => {
  const s = await open(); const iterator = events(s);
  const next = iterator.next(); let caught: unknown; void next.catch(error => { caught = error; });
  Peer.sockets.at(-1)!.close();
  for (let i = 0; i < 59; i++) { await reconnect(); Peer.sockets.at(-1)!.close(); }
  assert.equal(caught, undefined);
  await reconnect(); assert.ok(code("deadline_exceeded")(caught));
  await assert.rejects(next, code("deadline_exceeded"));
}));
await test("exclusive consumption rejects another iterator without opening a connection", async () => scenario(async open => {
  const s = await open(); const count = Peer.sockets.length; events(s);
  assert.throws(() => events(s), code("failed_precondition"));
  await flush(); assert.equal(Peer.sockets.length, count);
}));
await test("first gap completes callback and replay before subscribe resolves", async () => scenario(async () => {
  const gate = deferred(); let calls = 0; let resolved = false;
  Peer.openingGap = true;
  const pending: any = createRealtimeClient({invoke: async () => ({ticket, endpoint: address})}).subscribe("news", {onGap: async () => { calls++; await gate.promise; }});
  void Promise.resolve(pending).then(() => { resolved = true; });
  await flush(); assert.equal(calls, 1); assert.equal(resolved, false);
  gate.resolve(); await flush(); await reconnect();
  assert.equal(resolved, false);
  const current = Peer.sockets.at(-1)!;
  assert.equal(current.frames.find(f => f.type === "subscribe")?.cursor, cursorA);
  current.confirm();
  const s = await pending;
  await s.unsubscribe();
}));
await test("bounded overflow becomes a new gap instead of delivering a partial queue", async () => scenario(async open => {
  let calls = 0;
  const s = await open(async () => { calls++; });
  const iterator = events(s);
  let previous = "";
  for (let i = 0; i < 257; i++) {
    const cursor = `${i.toString(16).padStart(8, "0")}-aaaa-4aaa-8aaa-aaaaaaaaaaaa`;
    Peer.sockets.at(-1)!.event(cursor, previous); previous = cursor;
  }
  const next = iterator.next();
  await flush(); await reconnect(); assert.equal(calls, 1);
  const current = Peer.sockets.at(-1)!;
  assert.equal(current.frames.find(f => f.type === "subscribe")?.cursor, previous);
  current.confirm(); current.event(cursorC, previous);
  assert.equal((await next).value.payload, cursorC);
}));
