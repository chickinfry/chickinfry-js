import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { Auth, AuthError } from "../dist/auth/runtime.js";

const url = process.env.CHIK_TEST_DATABASE_URL;
const rejected = (work, code, status) => assert.rejects(work,
  error => error instanceof AuthError && error.code === code && error.status === status);
const password = "correct horse battery staple";
// Rate limits are durable rows, so every run uses its own caller identity.
const callerId = () => "198.51." + Math.floor(Math.random() * 250) + "." + (1 + Math.floor(Math.random() * 250));

test("device approval issues one session only after browser approval", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  let clock = Date.now();
  const auth = new Auth(port, [], () => clock, {}, {deviceVerificationBase: "https://app.example.test"});
  const email = randomUUID() + "@example.test";
  const user = await auth.signup(email, password);

  const caller = callerId();
  const started = await auth.startDeviceAuthorization({deviceName: "agent-runner"}, caller);
  assert.equal(started.verificationUri, "https://app.example.test/auth/device");
  assert.match(started.userCode, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);

  // A pending request never yields a session.
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "authorization_pending", 400);

  // The browser approves with the code from the terminal.
  const approved = await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, caller);
  assert.equal(approved.status, "approved");

  clock += 5_000;
  const tokens = await auth.pollDeviceAuthorization(started.deviceCode);
  assert.equal(tokens.userId, user.userId);
  assert.match(tokens.accessToken, /^[A-Za-z0-9_-]{43}$/);
  const session = await auth.session(tokens.accessToken);
  assert.equal(session.id, user.userId);

  // The device code is single use.
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "access_denied", 400);

  // Approval after exchange cannot revive the request.
  await rejected(auth.approveDeviceAuthorization({id: user.userId}, started.userCode, callerId()), "device_code_used", 400);
});

test("anonymous code guesses without a client address cannot block other users' approvals", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const attacker = await auth.signup(randomUUID() + "@example.test", password);
  const victim = await auth.signup(randomUUID() + "@example.test", password);
  // The platform host does not pass callerIp. More wrong lookups than any shared
  // budget allowed must not reach the people approving their own devices.
  const wrong = () => randomUUID().replace(/[^A-HJ-NP-Z2-9]/gi, "").toUpperCase().padEnd(8, "A").slice(0, 8);
  for (let attempt = 0; attempt < 610; attempt++) {
    await assert.rejects(auth.describeDeviceAuthorization(wrong()), error => error instanceof AuthError && error.status === 400);
  }
  for (let attempt = 0; attempt < 10; attempt++) {
    await rejected(auth.approveDeviceAuthorization({id: attacker.userId}, "AAAA-AAAA"), "device_code_invalid", 400);
  }
  // The approving account carries its own guessing budget.
  await rejected(auth.approveDeviceAuthorization({id: attacker.userId}, "AAAA-AAAA"), "rate_limited", 429);

  const started = await auth.startDeviceAuthorization({deviceName: "victim-laptop"});
  const details = await auth.describeDeviceAuthorization(started.userCode);
  assert.equal(details.deviceName, "victim-laptop");
  await auth.approveDeviceAuthorization({id: victim.userId}, started.userCode);
  const tokens = await auth.pollDeviceAuthorization(started.deviceCode);
  assert.equal(tokens.userId, victim.userId);
});

test("malformed device codes are refused before they spend the caller budget", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const user = await auth.signup(randomUUID() + "@example.test", password);
  const caller = callerId();
  for (let attempt = 0; attempt < 12; attempt++) {
    await rejected(auth.describeDeviceAuthorization("not a code", caller), "invalid_input", 400);
    await rejected(auth.approveDeviceAuthorization({id: user.userId}, "0000-0000", caller), "invalid_input", 400);
  }
  const started = await auth.startDeviceAuthorization({}, caller);
  await auth.describeDeviceAuthorization(started.userCode, caller);
  const approved = await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, caller);
  assert.equal(approved.status, "approved");
});

test("expired device requests are removed by the bounded cleanup pass", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const {createDatabase} = await import("../dist/auth/private/database.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  let clock = Date.now();
  const tasks = [], logs = [], original = console.error;
  const context = {waitUntil(work) { tasks.push(work); }, createPort(signal) { return createPostgresPort(url, signal); }};
  const auth = new Auth(port, [], () => clock, {}, {deviceVerificationBase: "https://app.example.test"}, context);
  const user = await auth.signup(randomUUID() + "@example.test", password);
  const started = await auth.startDeviceAuthorization({}, callerId());
  // Signup and start already scheduled cleanup passes; finish them before the row
  // expires so the refusal below cannot race a deletion.
  await Promise.all(tasks.splice(0));
  const {hashToken} = await import("../dist/auth/core/crypto.js");
  const db = createDatabase(port);
  const row = await db.appAuthDeviceRequests.findById({id: (await db.appAuthDeviceRequests.findMany({
    where: c => c.deviceCodeHash.eq(hashToken(started.deviceCode)), limit: 1,
  }))[0].id});
  assert.equal(row.status, "pending");
  // Cleanup removes the oldest expired rows first, a page at a time; an expiry older
  // than anything earlier runs left keeps this row on the first page.
  await db.appAuthDeviceRequests.update({id: row.id}, {expiresAt: "2000-01-01T00:00:00.000Z"});
  console.error = message => logs.push(message);
  try {
    await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, callerId());
  } catch {
    // Approval of an expired request is rejected; the cleanup below still runs.
  } finally { console.error = original; }
  // An expired request must be gone, not merely refused.
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "expired_token", 400);
  clock += 60000;
  // Starting another request schedules the next cleanup pass on the fake host context.
  await auth.startDeviceAuthorization({}, callerId());
  assert.ok(tasks.length > 0);
  await Promise.all(tasks);
  const cleaned = createDatabase(port);
  const remaining = await cleaned.appAuthDeviceRequests.findMany({where: c => c.id.eq(row.id), limit: 1});
  assert.deepEqual(remaining, []);
});

test("the approval page can read the request before deciding", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const user = await auth.signup(randomUUID() + "@example.test", password);
  const caller = callerId();
  const started = await auth.startDeviceAuthorization({deviceName: "work laptop"}, caller);
  const details = await auth.describeDeviceAuthorization(started.userCode, caller);
  assert.equal(details.deviceName, "work laptop");
  assert.ok(Number.isFinite(Date.parse(details.createdAt)));
  assert.equal(details.expiresAt, started.expiresAt);
  // The preview must not consume the request.
  const approved = await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, caller);
  assert.equal(approved.status, "approved");
  await rejected(auth.describeDeviceAuthorization(started.userCode, caller), "device_code_used", 400);
  await rejected(auth.describeDeviceAuthorization("AAAA-AAAA", caller), "device_code_invalid", 400);
});

test("a denied request never issues a session and device names are bounded", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const user = await auth.signup(randomUUID() + "@example.test", password);
  const started = await auth.startDeviceAuthorization({}, callerId());
  const denied = await auth.denyDeviceAuthorization({id: user.userId}, started.userCode, callerId());
  assert.equal(denied.status, "denied");
  // A denied request is a finished request: polling must not mint a session.
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "access_denied", 400);
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "access_denied", 400);
  // Device names are display-only, so they are bounded and single line.
  await rejected(auth.startDeviceAuthorization({deviceName: "x".repeat(65)}, callerId()), "invalid_input", 400);
  await rejected(auth.startDeviceAuthorization({deviceName: "bad\u0000name"}, callerId()), "invalid_input", 400);
  await rejected(auth.startDeviceAuthorization({deviceName: 42}, callerId()), "invalid_input", 400);
  const exact = await auth.startDeviceAuthorization({deviceName: "x".repeat(64)}, callerId());
  assert.match(exact.userCode, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
});

test("the generated host routes device operations without a project-side filter", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const {invokeRuntime} = await import("../dist/auth/host.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const email = randomUUID() + "@example.test";
  const session = await auth.signup(email, password, "", "browser");
  const request = () => new Request("https://app.example.test/auth.start_device_authorization", {method: "POST"});
  const browser = {cookieName: "__Host-chik_session_test", credential: session.credential, headers: new Headers()};
  const started = await invokeRuntime(auth, "auth.start_device_authorization", {device_name: "laptop"}, request(), {
    protected: false, browser, callerIp: callerId(), async invoke() { throw new Error("device operations must not reach project code"); },
  });
  assert.equal(started.verification_uri, "https://app.example.test/auth/device");
  const approved = await invokeRuntime(auth, "auth.approve_device_authorization", {user_code: started.user_code}, request(), {
    protected: true, browser, callerIp: callerId(), async invoke() { throw new Error("device operations must not reach project code"); },
  });
  assert.equal(approved.status, "approved");
  const tokens = await invokeRuntime(auth, "auth.poll_device_authorization", {device_code: started.device_code}, request(), {
    protected: false, callerIp: callerId(), async invoke() { throw new Error("device operations must not reach project code"); },
  });
  assert.equal(tokens.user_id, session.id);
});

test("an account without a password can approve a device sign-in", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  // The provider identity creates the account; it never sets a password.
  const provider = {id: "github", async verify(credential) { return {subject: String(credential), verifiedEmail: String(credential)}; }};
  const auth = new Auth(port, [provider], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const email = randomUUID() + "@example.test";
  const account = await auth.signinIdentity("github", email);
  const started = await auth.startDeviceAuthorization({}, callerId());
  await auth.approveDeviceAuthorization({id: account.userId}, started.userCode, callerId());
  const tokens = await auth.pollDeviceAuthorization(started.deviceCode);
  assert.equal(tokens.userId, account.userId);
  const session = await auth.session(tokens.accessToken);
  assert.equal(session.email, email);
});

test("device polling enforces the interval and expiry", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  let clock = Date.now();
  const auth = new Auth(port, [], () => clock, {}, {deviceVerificationBase: "https://app.example.test"});
  const user = await auth.signup(randomUUID() + "@example.test", password);

  const caller = callerId();
  const started = await auth.startDeviceAuthorization({}, caller);
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "authorization_pending", 400);
  // Polling faster than the advertised interval must be reported, not silently accepted.
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "slow_down", 400);
  clock += 5_000;
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "authorization_pending", 400);

  // Expiry ends the request even when it was approved in time.
  await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, callerId());
  clock += 11 * 60_000;
  await rejected(auth.pollDeviceAuthorization(started.deviceCode), "expired_token", 400);
});

test("device codes are rejected after repeated wrong entries", {skip: !url, timeout: 120000}, async t => {
  const {createPostgresPort} = await import("../internal/database/dist/postgres.js");
  const port = createPostgresPort(url);
  t.after(async () => { await port.close(); });
  const auth = new Auth(port, [], Date.now, {}, {deviceVerificationBase: "https://app.example.test"});
  const user = await auth.signup(randomUUID() + "@example.test", password);
  // The caller budget is durable, so each run uses its own caller identity.
  const caller = callerId();
  const started = await auth.startDeviceAuthorization({}, caller);

  await rejected(auth.approveDeviceAuthorization({id: user.userId}, "AAAA-AAAA", caller), "device_code_invalid", 400);
  // The real code still works for the same approver within the attempt budget.
  const approved = await auth.approveDeviceAuthorization({id: user.userId}, started.userCode, caller);
  assert.equal(approved.status, "approved");

  const other = await auth.startDeviceAuthorization({}, caller);
  // Two attempts above already consumed part of the ten-attempt caller budget.
  for (let attempt = 0; attempt < 8; attempt++) {
    await rejected(auth.denyDeviceAuthorization({id: user.userId}, "AAAA-AAAA", caller), "device_code_invalid", 400);
  }
  // The per-caller budget stops further guessing before the code space matters.
  await rejected(auth.denyDeviceAuthorization({id: user.userId}, other.userCode, caller), "rate_limited", 429);
});

