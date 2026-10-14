import assert from "node:assert/strict";
import { test } from "node:test";

const original = globalThis.console;
const originalLog = console.log;
await import("../dist/index.js");
assert.equal(globalThis.console === original, true, "browser import leaves console unchanged");
assert.equal(console.log === originalLog, true, "browser import leaves console methods unchanged");
const writes = [];
let failSink = false;
const methods = ["log", "info", "debug", "warn", "error", "trace", "table", "group", "groupCollapsed", "groupEnd", "count", "countReset", "dir", "dirxml", "time", "timeEnd", "timeLog", "timeStamp", "profile", "profileEnd", "clear", "assert"];
globalThis.console = Object.fromEntries(methods.map(method => [method, (...args) => {
  if (failSink && method === "log") throw new Error("Fixture sink failed.");
  writes.push({method, args});
}]));
const { redactLog, runWithLogRedaction } = await import(process.env.LOGGING_MODULE ?? "../dist/logging.js");
let cases = 0;
function equal(actual, expected, id) {
  cases++;
  assert.equal(actual === expected, true, id);
}
function reference(message, values, databaseURL) {
  const units = Array(message.length).fill(false);
  const password = databaseURL ? new URL(databaseURL).password : "";
  const exact = values.concat(password ? [decodeURIComponent(password)] : []).filter(Boolean);
  const encoded = databaseURL ? [databaseURL, password].filter(Boolean) : [];
  const normalize = value => value.replace(/%[0-9a-fA-F]{2}/g, escape => escape.toLowerCase());
  for (let start = 0; start < message.length; start++) {
    for (const value of exact) if (message.startsWith(value, start)) units.fill(true, start, start + value.length);
    for (const value of encoded) if (normalize(message.slice(start, start + value.length)) === normalize(value)) units.fill(true, start, start + value.length);
  }
  let output = "";
  for (let i = 0; i < message.length; i++) {
    if (!units[i]) output += message[i];
    else if (!i || !units[i - 1]) output += "[redacted]";
  }
  return output;
}

test("exact corpus, crossing matches, case-sensitive literals and percent escapes agree with the host oracle", () => {
  const values = ["private", "private-long", "a.*$[x]\n가", "redacted", "z", "xy", "abc", "four", "가", "가a", "ABCD", "BCDEFG", "literal%2F", ""];
  for (const message of ["normal line\nretained", ...values, "ABCDEFG ABCDBCDABC", "private-long private a.*$[x]\n가 redacted four 가a", "literal%2f literal%2F"]) {
    equal(redactLog(message, {values}), reference(message, values), "host corpus");
  }
  let seed = 0x234;
  const random = limit => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % limit; };
  for (const alphabet of [["a", "b", "c"], ["a", "b", "\ud83d", "\ude00"], ["%", "4", "A", "a"]]) {
    const word = length => Array.from({length}, () => alphabet[random(alphabet.length)]).join("");
    const secrets = Array.from({length: 20}, () => word(1 + random(8)));
    for (let i = 0; i < 1000; i++) {
      const message = word(random(80));
      equal(redactLog(message, {values: secrets}), reference(message, secrets), "seeded host oracle");
    }
  }
  for (const password of ["Mixed%2FPass%3FValue", "AA%4A", "x"]) {
    const databaseURL = `postgresql://fixture:${password}@localhost/test`;
    const values = ["bound%2FCase", "ExactCase"];
    const variants = [password, password.toLowerCase(), password.replace(/%[0-9A-F]{2}/g, escape => escape.toLowerCase()), decodeURIComponent(password)];
    for (const variant of variants) {
      for (const message of [variant, "%2" + variant, databaseURL.replace(password, variant), "bound%2fCase ExactCase exactcase", ".".repeat(8191) + variant]) {
        equal(redactLog(message, {values, databaseURL}), reference(message, values, databaseURL), "percent host oracle");
      }
    }
  }
});

test("snapshot and byte, state and merged-range limits fail without returning partial text", () => {
  for (const snapshot of [undefined, null, {}, {values: [1]}, {values: [], databaseURL: "invalid"}, {values: [], databaseURL: "postgresql://u:%xx@localhost/db"}]) {
    assert.throws(() => runWithLogRedaction(snapshot, () => assert.fail("invalid snapshot invoked work")));
  }
  equal(redactLog("normal\ntext", {values: []}), "normal\ntext", "explicit empty snapshot");
  equal(redactLog("s.".repeat(8192), {values: ["s"]}), "[redacted].".repeat(8192), "range boundary");
  assert.throws(() => redactLog("s.".repeat(8193), {values: ["s"]}));
  equal(redactLog("x".repeat(131071), {values: ["x".repeat(131071)]}), "[redacted]", "state boundary");
  assert.throws(() => redactLog("normal", {values: ["x".repeat(131072)]}));
  equal(runWithLogRedaction({values: ["x".repeat(131072)]}, () => { console.log("discard this record"); return "business result"; }), "business result", "matcher budget cannot change work result");
  equal(redactLog("x".repeat(4 << 20), {values: []}).length, 4 << 20, "input byte boundary");
  assert.throws(() => redactLog("가".repeat(1500000), {values: []}));
  assert.throws(() => redactLog("x".repeat((4 << 20) + 1), {values: ["x"]}));
  assert.throws(() => redactLog(".".repeat((4 << 20) - 2) + "s", {values: ["s"]}));
});

test("console writes safe strings, hides escaped leaves, and preserves work during formatting and sink failures", () => {
  writes.length = 0;
  const saved = console.log;
  saved("before snapshot");
  let inspected = 0;
  const values = ["sensitive\n\"leaf", "private", "redacted", "composed secret"];
  const object = {nested: [values[0], {get hidden() { inspected++; throw new Error(values[1]); }}], toJSON() { inspected++; throw new Error(values[1]); }};
  object.loop = object;
  const error = new Error("private", {cause: new Error(values[0])});
  const result = runWithLogRedaction({values}, () => {
    for (const method of methods) {
      if (method === "assert") console.assert(false, "private", object, error);
      else console[method]("%s %o", "private", object, error);
    }
    console.log("redacted");
    console.log("composed", "secret");
    console.assert(true, "not emitted");
    console.log(new Proxy({}, {ownKeys() { console.log("private"); throw new Error("private"); }}));
    console.log("x".repeat((4 << 20) + 1));
    failSink = true;
    saved("private");
    failSink = false;
    saved("normal after failure");
    return "business result";
  });
  equal(result, "business result", "logging preserves business result");
  equal(inspected, 0, "user formatters were not executed");
  equal(writes.some(write => write.args.some(arg => typeof arg !== "string" && arg !== false)), false, "writer receives strings only");
  equal(writes.some(write => write.args.some(arg => typeof arg === "string" && (arg.includes(values[0]) || arg.includes("private")))), false, "no sensitive leaf reaches sink");
  equal(writes.some(write => write.args.some(arg => typeof arg === "string" && arg.includes(values[3]))), false, "secret formed only by joining arguments never reaches sink");
  equal(writes.some(write => write.args.some(arg => typeof arg === "string" && arg.includes(JSON.stringify(values[0]).slice(1, -1)))), false, "escaped sensitive leaf never reaches sink");
  equal(writes.some(write => write.args.includes("[redacted]")), true, "inserted marker is not re-redacted");
  equal(writes.some(write => write.args.includes("normal after failure")), true, "normal text retained");
  equal(writes.some(write => write.args.some(arg => typeof arg === "string" && arg.includes("droppedLogs"))), true, "dropped records counted");
});

test("overlapping requests and detached descendants retain their own snapshots", async () => {
  writes.length = 0;
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const tasks = [];
  const first = runWithLogRedaction({values: ["first-value"]}, async () => {
    await gate;
    console.log("A first-value");
    tasks.push(new Promise(resolve => setTimeout(() => { console.log("late-A first-value"); resolve(); }, 5)));
  });
  const second = runWithLogRedaction({values: ["second-value"]}, async () => {
    console.log("B second-value");
    release();
    await Promise.resolve();
  });
  await Promise.all([first, second]);
  await Promise.all(tasks);
  equal(writes.some(write => write.args.includes("A [redacted]")), true, "first request snapshot");
  equal(writes.some(write => write.args.includes("B [redacted]")), true, "second request snapshot");
  equal(writes.some(write => write.args.includes("late-A [redacted]")), true, "detached descendant snapshot");
  equal(writes.length, 3, "request record count");
});

process.on("exit", () => { process.stdout.write(JSON.stringify({loggingCases: cases}) + "\n"); });
