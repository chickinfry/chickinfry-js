import assert from "node:assert/strict";
import {mock} from "node:test";
import {mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync} from "node:fs";
import {createRequire} from "node:module";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";
import {createRealtimeClient} from "../dist/realtime/client.js";
import {ClientError, HttpTransport, MemoryStore, type SessionCredentials} from "../dist/http.js";

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
  constructor(url:string){connections.push(url);queueMicrotask(()=>{this.onopen?.();});}
  send(frame:string){const value=JSON.parse(frame);if(value.type==="subscribe")queueMicrotask(()=>this.onmessage?.({data:JSON.stringify({type:"ready",channel:value.channel,cursor:""})}));}
  close(){closedSockets++;}
}
Reflect.set(globalThis,"WebSocket",Socket);
try{
  for(const endpoint of [undefined,"invalid", "ws://example.test/realtime","wss://example.test/realtime",address+"?ticket=other",address+"#part",address.replace("/realtime","/other"),address.replace("33333333-3333-4333-8333-333333333333","r-33333333-3333-4333-8333-333333333333")]){
    const subscription=createRealtimeClient({invoke:async()=>({ticket,endpoint})}).subscribe("news");
    await assert.rejects(subscription.ready);
    subscription.unsubscribe();
  }
  assert.equal(connections.length,0);
  const subscription=createRealtimeClient({invoke:async()=>({ticket,endpoint:address})}).subscribe("news");
  await subscription.ready;
  assert.deepEqual(connections,[address+"?ticket="+ticket]);
  subscription.unsubscribe();
  const originalFetch = globalThis.fetch;
  try {
    let requests = 0;
    globalThis.fetch = async () => ++requests === 1 ? Response.json(null) : Response.json({ticket, endpoint: address});
    const invalidTicket = createRealtimeClient(new HttpTransport("https://example.com")).subscribe("news");
    try {
      await assert.rejects(invalidTicket.ready, error => error instanceof Error && error.constructor === Error && /Invalid realtime ticket/.test(error.message));
      assert.equal(requests, 1, "A malformed ticket must fail without retrying.");
    } finally { invalidTicket.unsubscribe(); }
    for (const error of [new TypeError("Network unavailable."), new DOMException("Request timed out.", "TimeoutError")]) {
      let requests = 0;
      globalThis.fetch = async () => {
        if (++requests === 1) throw error;
        return Response.json({ticket, endpoint: address});
      };
      const subscription = createRealtimeClient(new HttpTransport("https://example.com")).subscribe("news");
      try {
        await assert.doesNotReject(subscription.ready);
        assert.equal(requests, 2);
      } finally { subscription.unsubscribe(); }
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
const renewal = transport.sessionRenewal()!;
const otherRenewal = new HttpTransport("https://example.com").withSession(store).sessionRenewal()!;
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
  assert.equal(transport.sessionRenewal(), renewal);
  assert.equal(renewal.dueAt(), Date.parse(credentials.expiresAt));
  await Promise.all([renewal.renew(), otherRenewal.renew()]);
  assert.equal(refreshes, 1);
  assert.equal(credentials.accessToken, "c".repeat(43));
  assert.equal(credentials.refreshToken, "d".repeat(43));
  const session = new MemoryStore(credentials);
  globalThis.fetch = async () => Response.json({ticket, endpoint: address});
  Reflect.set(globalThis, "WebSocket", Socket);
  mock.timers.enable({apis: ["setTimeout"]});
  const subscription = createRealtimeClient(new HttpTransport("https://example.com").withSession(session)).subscribe("news");
  try {
    await subscription.ready;
    const closed = closedSockets;
    await session.clear(session.credentials());
    assert.doesNotThrow(() => mock.timers.tick(2_147_000_000), "Session removal must not escape the renewal timer.");
    await assert.rejects(subscription[Symbol.asyncIterator]().next(), error =>
      error instanceof ClientError && error.code === "unauthenticated");
    assert.equal(closedSockets, closed + 1, "Renewal failure must close the subscription.");
  } finally {
    subscription.unsubscribe();
    mock.timers.reset();
    Reflect.set(globalThis, "WebSocket", original);
  }
} finally { globalThis.fetch = originalFetch; }
console.log("Realtime renewal uses shared native credential refresh: verified");
