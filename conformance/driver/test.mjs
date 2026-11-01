import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import {Driver, RecoveryFailure, DecodeFailure} from "./main.mjs";
import {fileURLToPath} from "node:url";
import {instrument, install} from "./hooks.mjs";

test("base SDK cases remain explicitly unimplemented in this skeleton", async () => {
  const driver = new Driver({}, {});
  const result = await driver.command("handshake", {protocolVersions: [2], requiredCapabilities: ["client.create", "client.call"]});
  assert.deepEqual(result.capabilities, ["realtime-v1"]);
  await assert.rejects(driver.command("client.create", {caseId: "C-01"}), /unimplemented/);
});

test("private instrumentation rejects runtime drift and leaves source bytes alone", () => {
  const path = new URL("../../src/realtime/client.ts", import.meta.url);
  const source = readFileSync(path, "utf8");
  const result = instrument(source);
  assert.match(result, /queue.length >= 512/);
  assert.throws(() => instrument(source.replace("queue.length >= 256", "queue.length >= 128")));
  assert.equal(readFileSync(path, "utf8"), source);
});

test("isolated Node loader imports the pinned runtime without installed dependencies", async () => {
  const hooks = install(fileURLToPath(new URL("../../", import.meta.url)), {});
  try {
    const runtime = await import("@chickinfry/chickinfry");
    assert.equal(typeof runtime.HttpTransport, "function");
    assert.equal(typeof runtime.BrowserHttpTransport, "function");
  } finally { hooks.deregister(); }
});

test("observation waits allow the customer gap callback to be released", async () => {
  let recover;
  let finish;
  let calls = 0;
  const events = {async *[Symbol.asyncIterator]() { await recover(); await new Promise(resolve => { finish = resolve; }); }};
  const subscription = {events, async unsubscribe() { finish?.(); }};
  const sdk = {createClient: () => ({probe: {list: async () => {calls++; return {rows: []};}}, realtime: {subscribe: async (_channel, options) => {recover = options.onGap; return subscription;}}})};
  const runtime = {HttpTransport: class {}, BrowserHttpTransport: class {}, OperationError: class extends Error {}};
  const driver = new Driver(sdk, runtime);
  await driver.command("client.create", {clientRef: "client", origin: "http://127.0.0.1:1234", transport: "plain"});
  await driver.command("realtime.start", {clientRef: "client", channel: "orders", transport: "plain", onGap: "hold", eventHandler: "normal"});
  const observed = await driver.command("realtime.observe", {point: "gap-entered", timeoutMs: 1000});
  assert.equal(observed.facts.dbReads, 1);
  assert.equal(calls, 1);
  await driver.command("realtime.release", {point: "gap"});
  await driver.command("realtime.unsubscribe", {});
  assert.equal(driver.snapshot().state, "ended");
  assert.equal(driver.snapshot().callbackCompletions, 1);
});

test("customer failure reports concrete error and cause identities", async () => {
  const sdk = {createClient: () => ({probe: {list: async () => ({rows: []})}, realtime: {subscribe: async (_channel, options) => {await options.onGap();}}})};
  const runtime = {HttpTransport: class {}, OperationError: class extends Error {}};
  const driver = new Driver(sdk, runtime);
  await driver.command("client.create", {clientRef: "client", origin: "http://127.0.0.1:1234", transport: "plain"});
  await driver.command("realtime.start", {clientRef: "client", channel: "orders", transport: "plain", onGap: "cause", eventHandler: "normal"});
  await driver.command("realtime.observe", {point: "ended", timeoutMs: 1000});
  assert.ok(driver.customerError instanceof RecoveryFailure);
  assert.ok(driver.customerError.cause instanceof DecodeFailure);
  assert.equal(driver.snapshot().causePreserved, true);
  assert.equal(driver.snapshot().errorType, "RecoveryFailure");
  assert.equal(driver.snapshot().errorPhase, "subscribe");
});
