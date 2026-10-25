import {strict as assert} from "node:assert";
import * as sdk from "../src/http.js";

const originalFetch = globalThis.fetch;
const local = (code: string, status: number | undefined, outcomeUnknown = false) => (error: unknown) => {
  assert.equal(typeof sdk.ClientError,"function","local failures need a public ClientError type");
  assert.ok(error instanceof sdk.ClientError);
  assert.equal(error.code, code);
  assert.equal(error.status, status);
  assert.equal(error.outcomeUnknown, outcomeUnknown);
  assert.equal(error.message.includes("private-canary"), false);
  return true;
};
assert.throws(() => new sdk.HttpTransport("http://example.test"), local("invalid_argument", undefined));
for (const timeout of [0,-1,1.1,NaN,Infinity,2_147_483_648,Number.MAX_SAFE_INTEGER+1]) {
  assert.throws(() => new sdk.HttpTransport("https://example.test",undefined,{timeout}), local("invalid_argument",undefined));
}
const transport = new sdk.HttpTransport("https://example.test");
try {
  let calls = 0;
  globalThis.fetch = async () => { calls++; return Response.json({}); };
  await assert.rejects(transport.invoke("bad",{}), local("invalid_argument",undefined));
  await assert.rejects(transport.invoke("catalog.create",{value:1n}), local("invalid_argument",undefined));
  await assert.rejects(transport.invoke("catalog.create",{value:"x".repeat(4<<20)}), local("resource_exhausted",undefined));
  assert.equal(calls,0);
  const options = {persist:false as const};
  Reflect.set(options,Symbol.for("chickinfry.store.scope.v1"),{appId:"test-app",projectId:"test-project",origin:"https://example.test",screen:"screen-a"});
  await assert.rejects(new sdk.HttpTransport("https://example.test",options).invoke("catalog.create",{}),local("unauthenticated",undefined));
  assert.equal(calls,0,"missing protected sessions must fail before fetch");
  for (const [failure,code] of [[new DOMException("private-canary","TimeoutError"),"deadline_exceeded"],
    [new DOMException("private-canary","AbortError"),"canceled"], [new TypeError("private-canary"),"unavailable"],
    [new Error("private-canary"),"unknown"]] as const) {
    globalThis.fetch = async () => { throw failure; };
    await assert.rejects(transport.invoke("catalog.create",{}), local(code,undefined,true));
  }
  globalThis.fetch = async (_url, init) => new Promise((_,reject) => {
    init!.signal!.addEventListener("abort",()=>reject(init!.signal!.reason),{once:true});
  });
  // Keep the event loop alive while AbortSignal's unref'd timer expires.
  const hold = setTimeout(()=>{},1000);
  try { await assert.rejects(new sdk.HttpTransport("https://example.test",undefined,{timeout:5}).invoke("catalog.create",{}),local("deadline_exceeded",undefined,true)); }
  finally { clearTimeout(hold); }
  for (const [body,status,code] of [["{",502,"internal"],["{}",401,"internal"],["x".repeat((1<<20)+1),503,"resource_exhausted"]] as const) {
    globalThis.fetch = async () => new Response(body,{status});
    await assert.rejects(transport.invoke("catalog.create",{}),local(code,status,true));
  }
  globalThis.fetch = async () => new Response(new ReadableStream({start(controller) {controller.error(new TypeError("private-canary"));}}),{status:200});
  await assert.rejects(transport.invoke("catalog.create",{}),local("unavailable",200,true));
  globalThis.fetch = async () => Response.json({error:"x"},{status:422});
  await assert.rejects(transport.invoke("catalog.create",{}),error=>error instanceof sdk.OperationError && error.code === "x" && error.status === 422);
  const initial = {accessToken:"a".repeat(43),refreshToken:"b".repeat(43),expiresAt:"2099-01-01T00:00:00Z",refreshExpiresAt:"2099-02-01T00:00:00Z",userId:"user",sessionId:"session"};
  const store = new sdk.MemoryStore(initial);
  initial.accessToken = "c".repeat(43);
  assert.equal(store.credentials().accessToken,"a".repeat(43));
  const snapshot = store.credentials();
  const rotated = await store.refresh(async value => ({...value,accessToken:"d".repeat(43),refreshToken:"e".repeat(43)}));
  assert.equal(rotated.accessToken,"d".repeat(43));
  await store.clear(snapshot);
  assert.equal(store.credentials().accessToken,"d".repeat(43),"stale cleanup must preserve rotated credentials");
  await store.clear(rotated);
  assert.throws(()=>store.credentials(),local("unauthenticated",undefined));
  assert.throws(()=>new sdk.HttpTransport("https://example.test").withSession({credentials(){throw new Error("private-canary");}} as never),local("failed_precondition",undefined));
  const cookie = {id:"11111111-1111-4111-8111-111111111111",session_id:"22222222-2222-4222-8222-222222222222",email:"test@example.test",expires_at:"2099-01-01T00:00:00Z"};
  let browserCalls=0;
  globalThis.fetch=async (_url,init)=>{browserCalls++;assert.equal(init?.credentials,"include");return Response.json(cookie);};
  const browser=new sdk.BrowserHttpTransport("https://example.test",options);
  assert.deepEqual(await browser.invoke("auth.session",{}),cookie,"a cookie session must be checked without local metadata");
  assert.deepEqual(await new sdk.BrowserHttpTransport("https://example.test",options).invoke("auth.session",{}),cookie);
  assert.equal(browserCalls,2);
  globalThis.fetch=async ()=>Response.json({status:"ok"});
  await browser.invoke("auth.logout",{});
  await assert.rejects(browser.invoke("catalog.create",{}),local("unauthenticated",undefined));
  for(const status of [201,206]) {
    globalThis.fetch=async ()=>Response.json({}, {status});
    await assert.rejects(new sdk.HttpTransport("https://example.test",options).invoke("auth.signin",{}),local("internal",status,true));
    await assert.rejects(new sdk.BrowserHttpTransport("https://example.test",options).invoke("auth.session",{}),local("internal",status,true));
    for (const interrupted of [false,true]) {
    const broken = {credentials:()=>({...initial,accessToken:"a".repeat(43)}),refresh:async (work: (value:typeof initial)=>Promise<typeof initial>)=>work({...initial,accessToken:"a".repeat(43)}),clear:async()=>{throw new Error("private-canary");}};
    const client=new sdk.HttpTransport("https://example.test").withSession(broken);
    let sent=0;
    globalThis.fetch=async url=>{sent++;return String(url).endsWith("/auth.refresh")?(interrupted ? new Response(new ReadableStream({start(controller){controller.error(new TypeError("private-canary"));}}),{status}) : Response.json({}, {status})):Response.json({error:"invalid_token"},{status:401});};
    await assert.rejects(client.invoke("catalog.create",{}),local(interrupted ? "unavailable" : "internal",status,true));
    const before=sent;
    await assert.rejects(client.invoke("catalog.create",{}),local("unauthenticated",undefined));
    assert.equal(sent,before,"blocked reuse must fail without a request or stale response status");
    }
  }
  const overlappingStore={credentials:()=>({...initial,accessToken:"a".repeat(43)}),refresh:async (work:(value:typeof initial)=>Promise<typeof initial>)=>work({...initial,accessToken:"a".repeat(43)}),clear:async()=>{throw new Error("private-canary");}};
  const overlapping=new sdk.HttpTransport("https://example.test").withSession(overlappingStore);
  let received!:()=>void, releaseResponse!:(value:Response)=>void;
  const ready=new Promise<void>(resolve=>{received=resolve;});
  const delayed=new Promise<Response>(resolve=>{releaseResponse=resolve;});
  let refreshCalls=0;
  globalThis.fetch=async url=>{
    if(!String(url).endsWith("/auth.refresh"))return Response.json({error:"invalid_token"},{status:401});
    if(++refreshCalls===1){received();return delayed;}
    throw new DOMException("private-canary","TimeoutError");
  };
  const automatic=overlapping.invoke("catalog.create",{});
  await ready;
  await assert.rejects(overlapping.invoke("auth.refresh",{refresh_token:initial.refreshToken}),local("deadline_exceeded",undefined,true));
  releaseResponse(new Response(new ReadableStream({start(controller){controller.error(new TypeError("private-canary"));}}),{status:206}));
  await assert.rejects(automatic,local("unavailable",206,true));
  await assert.rejects(overlapping.invoke("catalog.create",{}),local("unauthenticated",undefined));
  assert.equal(refreshCalls,2);
  for(const status of [201,206]) {
    const wire={access_token:"a".repeat(43),refresh_token:"b".repeat(43),expires_at:initial.expiresAt,refresh_expires_at:initial.refreshExpiresAt,user_id:cookie.id,session_id:cookie.session_id};
    const device=new sdk.HttpTransport("https://example.test",options);
    globalThis.fetch=async ()=>Response.json(wire);
    await device.invoke("auth.signin",{});
    let received!:()=>void, release!:(value:Response)=>void;
    const ready=new Promise<void>(resolve=>{received=resolve;});
    const response=new Promise<Response>(resolve=>{release=resolve;});
    let refreshes=0, business=0;
    globalThis.fetch=async url=>{
      if(String(url).endsWith("/auth.refresh")){refreshes++;received();return response;}
      business++;return Response.json({});
    };
    const refreshing=device.invoke("auth.refresh",{refresh_token:wire.refresh_token});
    await ready;
    const waiting=device.invoke("catalog.create",{});
    release(Response.json({}, {status}));
    const failures=await Promise.allSettled([refreshing,waiting]);
    for(const result of failures){assert.equal(result.status,"rejected");if(result.status==="rejected")local("internal",status,true)(result.reason);}
    assert.equal(refreshes,1,"both requests must share one refresh");
    assert.equal(business,0,"a waiting business operation must not be sent after failed refresh");
    await assert.rejects(device.invoke("catalog.create",{}),local("unauthenticated",undefined));
    assert.equal(business,0);
  }
  const racing = new sdk.MemoryStore({...initial,accessToken:"a".repeat(43)});
  const saved = racing.credentials();
  let release!: () => void;
  const gate = new Promise<void>(resolve=>{release=resolve;});
  const pending = racing.refresh(async value=>{await gate; return {...value,accessToken:"f".repeat(43)};});
  await racing.clear(saved);
  release();
  await assert.rejects(pending,local("failed_precondition",undefined));
} finally {globalThis.fetch=originalFetch;}
