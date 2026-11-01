import {closeSync, readFileSync} from "node:fs";
import {createInterface} from "node:readline";
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";
import {hookKey, install} from "./hooks.mjs";

export const driverVersion = "typescript-realtime-v1";
const capabilities = ["client.create", "client.call", "realtime-v1"];
const terminal = state => ["ended", "error", "canceled"].includes(state);

export class DecodeFailure extends Error {}
export class RecoveryFailure extends Error {}

export class Driver {
  clients = new Map();
  points = new Set();
  waiters = new Set();
  held = new Map();
  frames = [];
  holdDispatch = false;
  facts = {state: "ready", eventIds: [], callbackStarts: 0, callbackCompletions: 0,
    callbackOverlapAtMost: 0, dbReads: 0, deliveredAfterEnd: 0, publicWireOperations: 0,
    terminalErrors: 0, staleFramesHeld: 0, staleFramesDiscarded: 0};
  gaps = 0;
  callbacks = 0;
  connections = 0;
  lossBudgets = 0;
  httpRequests = 0;
  httpStatus = null;

  constructor(sdk, runtime) {
    this.sdk = sdk;
    this.runtime = runtime;
    this.hook = {
      gap: () => { this.mark(++this.gaps === 1 ? "gap-received" : "gap-received-again"); },
      overflow: () => this.mark("overflow-received"),
      recovered: () => this.mark("recovered"),
      discarded: () => { this.facts.staleFramesDiscarded++; },
      budget: (afterReady, ms) => {
        if (!afterReady) return;
        this.facts.reprepareBudgetMs = ms;
        this.facts.budgetResets = this.lossBudgets++;
      },
      endpoint: value => {
        const expected = this.origin.replace(/^http/, "ws") + "/realtime";
        if (value !== expected) throw new Error("Invalid peer endpoint.");
        return value;
      },
    };
  }

  mark(point) { this.points.add(point); for (const wake of this.waiters) wake(); }

  async wait(point, timeoutMs) {
    if (point === "snapshot") return;
    if (this.points.has(point)) return;
    await new Promise((resolve, reject) => {
      const finish = error => { clearTimeout(timer); this.waiters.delete(wake); error ? reject(error) : resolve(); };
      const wake = () => { if (this.points.has(point)) finish(); };
      const timer = setTimeout(() => finish(new Error("deadline_exceeded")), timeoutMs);
      this.waiters.add(wake);
    });
  }

  hold(point) {
    if (this.held.has(point)) throw new Error("invalid_args");
    return new Promise(resolve => this.held.set(point, resolve));
  }

  release(point) {
    const release = this.held.get(point);
    if (!release) throw new Error("invalid_args");
    this.held.delete(point);
    release();
  }

  snapshot() {
    return structuredClone({...this.facts, ...(this.hook.inspect?.() ?? {})});
  }

  async start(args) {
    const entry = this.clients.get(args.clientRef);
    if (!entry || entry.transport !== args.transport || this.running ||
        !["hold", "absent", "fail", "cause"].includes(args.onGap) ||
        !["normal", "hold-a"].includes(args.eventHandler)) throw new Error("invalid_args");
    const options = args.onGap === "absent" ? undefined : {onGap: async () => {
      this.facts.callbackStarts++;
      this.facts.callbackOverlapAtMost = Math.max(this.facts.callbackOverlapAtMost, ++this.callbacks);
      try {
        await entry.client.probe.list({});
        this.facts.dbReads++;
        if (args.onGap === "fail" || args.onGap === "cause") {
          this.customerCause = new DecodeFailure("Customer decode failed.");
          this.customerError = new RecoveryFailure("Customer recovery failed.", {cause: this.customerCause});
          throw this.customerError;
        }
        const held = this.hold("gap");
        this.mark(this.facts.callbackStarts === 1 ? "gap-entered" : "gap-entered-again");
        await held;
        this.facts.callbackCompletions++;
      } finally { this.callbacks--; }
    }};
    this.running = (async () => {
      let phase = "subscribe";
      try {
        this.subscription = await entry.client.realtime.subscribe(args.channel, options);
        this.iterator = this.subscription.events[Symbol.asyncIterator]();
        this.mark("subscribed");
        phase = "events";
        while (true) {
          const item = await this.iterator.next();
          if (item.done) break;
          if (terminal(this.facts.state)) this.facts.deliveredAfterEnd++;
          const id = item.value.payload?.id;
          if (!["A", "B", "C", "overflow"].includes(id)) throw new Error("Invalid observed payload.");
          this.facts.eventIds.push(id);
          if (id === "A" && args.eventHandler === "hold-a") {
            const held = this.hold("event-a");
            this.mark("event-a-entered");
            await held;
          }
          this.mark(`event-${id.toLowerCase()}-complete`);
        }
        if (!terminal(this.facts.state)) this.facts.state = "ended";
      } catch (error) {
        this.facts.state = "error";
        this.facts.errorCode = error.code ?? "unknown";
        this.facts.httpStatus = error instanceof this.runtime.OperationError ? error.status : null;
        this.facts.errorPhase = phase;
        this.facts.terminalErrors++;
        if (this.customerError) {
          const original = error === this.customerError ? error : error.cause;
          if (original instanceof RecoveryFailure) this.facts.errorType = "RecoveryFailure";
          if (original?.cause instanceof DecodeFailure) this.facts.causeType = "DecodeFailure";
          this.facts.causePreserved = original === this.customerError && original.cause === this.customerCause;
        }
      } finally { this.mark("ended"); }
    })();
  }

  async command(command, args) {
    if (args.caseId !== undefined && args.caseId !== "RT-DX-01") throw new Error("unimplemented");
    switch (command) {
      case "handshake":
        if (!args.protocolVersions?.includes(2)) throw new Error("protocol_mismatch");
        return {protocolVersion: 2, driverVersion, capabilities: args.requiredCapabilities?.includes("realtime-v1") ? capabilities : ["realtime-v1"]};
      case "client.create": {
        if (this.clients.has(args.clientRef) || !["plain", "browser"].includes(args.transport)) throw new Error("invalid_args");
        const url = new URL(args.origin);
        if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.pathname !== "/" || url.search || url.hash || url.username || url.password) throw new Error("invalid_args");
        this.origin = url.origin;
        const before = this.httpRequests;
        const transport = args.transport === "browser" ? new this.runtime.BrowserHttpTransport(args.origin, {persist: false}) : new this.runtime.HttpTransport(args.origin, {persist: false});
        // The auth-free fixture uses the existing browser transport with createClient.
        const client = this.sdk.createClient(transport);
        this.clients.set(args.clientRef, {client, transport: args.transport});
        return {clientRef: args.clientRef, constructorNetworkRequests: this.httpRequests - before};
      }
      case "client.call": {
        const entry = this.clients.get(args.clientRef);
        if (!entry || args.operation !== "probe.list") throw new Error("invalid_reference");
        const output = await entry.client.probe.list(args.input);
        return {output, credentialRefs: {}, httpStatus: this.httpStatus};
      }
      case "realtime.start": await this.start(args); break;
      case "realtime.observe":
        await this.wait(args.point, args.timeoutMs);
        return {facts: this.snapshot()};
      case "realtime.release":
        this.release(args.point);
        await new Promise(resolve => setImmediate(resolve));
        break;
      case "realtime.unsubscribe":
        await this.subscription.unsubscribe();
        await this.subscription.unsubscribe();
        await this.running;
        break;
      case "realtime.cancel":
        this.facts.state = "canceled";
        await this.iterator.return();
        await this.running;
        break;
      case "realtime.second-consumer": {
        const before = this.connections;
        try { this.subscription.events[Symbol.asyncIterator](); }
        catch (error) { this.facts.exclusiveConsumption = error instanceof this.runtime.ClientError && error.code === "failed_precondition"; this.facts.consumptionRejection = "runtime"; }
        this.facts.newConnections = this.connections - before;
        break;
      }
      case "realtime.hold-dispatch": this.holdDispatch = true; break;
      case "realtime.release-dispatch":
        this.holdDispatch = false;
        for (const dispatch of this.frames.splice(0)) dispatch();
        await new Promise(resolve => setImmediate(resolve));
        break;
      default: throw new Error("unimplemented");
    }
    return {accepted: true};
  }
}

export function observeSockets(driver) {
  const NativeWebSocket = globalThis.WebSocket;
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = async (...args) => {
    driver.httpRequests++;
    const response = await nativeFetch(...args);
    driver.httpStatus = response.status;
    return response;
  };
  globalThis.WebSocket = class extends NativeWebSocket {
    constructor(...args) { super(...args); driver.connections++; }
    set onmessage(handler) {
      super.onmessage = event => {
        const type = JSON.parse(event.data).type;
        if (driver.holdDispatch && ["ready", "event"].includes(type)) {
          driver.frames.push(() => handler.call(this, event));
          driver.facts.staleFramesHeld++;
          if (driver.facts.staleFramesHeld >= 2) driver.mark("stale-frames-held");
        } else handler.call(this, event);
      };
    }
  };
  return () => { globalThis.WebSocket = NativeWebSocket; globalThis.fetch = nativeFetch; };
}

async function main() {
  const options = new Map();
  for (let index = 2; index < process.argv.length; index += 2) options.set(process.argv[index], process.argv[index + 1]);
  if (options.size !== 2 || !options.has("--plain-sdk") || !options.has("--auth-sdk")) throw new Error("invalid_args");
  // Credentials arrive only on fd 3; RT-DX-01 uses its anonymous fixture.
  const bootstrap = readFileSync(3, "utf8");
  closeSync(3);
  for (const line of bootstrap.split("\n").filter(Boolean)) {
    const record = JSON.parse(line);
    if (typeof record.ref !== "string" || typeof record.value !== "string") throw new Error("invalid_reference");
  }
  install(fileURLToPath(new URL("../../", import.meta.url)), {
    "chickinfry-client-plain": options.get("--plain-sdk"),
    "chickinfry-client-auth": options.get("--auth-sdk"),
  });
  const sdk = await import("chickinfry-client-plain");
  const runtime = await import("@chickinfry/chickinfry");
  const driver = new Driver(sdk, runtime);
  globalThis[hookKey] = driver.hook;
  observeSockets(driver);
  const seen = new Set();
  const pending = new Set();
  const input = createInterface({input: process.stdin, crlfDelay: Infinity});
  for await (const line of input) {
    let request;
    try {
      if (Buffer.byteLength(line) > 1024 * 1024) throw new Error();
      request = JSON.parse(line);
      if (typeof request.id !== "string" || seen.has(request.id) || typeof request.command !== "string" || !request.args || !Number.isFinite(request.args.timeoutMs) && request.command !== "handshake") throw new Error();
      seen.add(request.id);
    } catch { process.exitCode = 1; break; }
    // Observation waits must not block release or cancellation commands.
    const work = driver.command(request.command, request.args).then(result => {
      process.stdout.write(JSON.stringify({id: request.id, result, error: null}) + "\n");
    }, error => {
      const unimplemented = error.message === "unimplemented";
      process.stdout.write(JSON.stringify({id: request.id, result: null, error: {kind: unimplemented ? "unimplemented" : "driver", code: unimplemented ? "unimplemented" : "driver_failed", httpStatus: null, outcomeUnknown: null}}) + "\n");
    });
    pending.add(work);
    void work.finally(() => pending.delete(work));
  }
  await driver.subscription?.unsubscribe();
  await Promise.all(pending);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => { process.stderr.write("Realtime driver failed.\n"); process.exitCode = 1; });
}
