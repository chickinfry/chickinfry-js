import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { Auth, AuthError, developmentAuthMailer } from "../dist/auth/runtime.js";
import * as rules from "../dist/auth/core/rules.js";

const noIO = {query() { throw new Error("Unexpected I/O"); }, transaction() { throw new Error("Unexpected I/O"); }};

test("verified email requires an injected mailer and a safe client link base at startup", () => {
  assert.throws(() => new Auth(noIO, [], Date.now, {}, {email: {verification: "required"}}), /mailer/i);
  const mailer = {async send() {}};
  for (const emailLinkBase of [undefined, "https://example.test/#redirect", "https://example.test/?redirect=1", "http://example.test", "https://user@example.test"]) {
    assert.throws(() => new Auth(noIO, [], Date.now, {}, {email: {verification: "required"}, mailer, emailLinkBase}), /link/i);
  }
  for (const emailLinkBase of [
    "https://@client.example/", "https://:@client.example/", "https://client.example/a%2Fb", "https://client.example/%7E", "https://client.example/\uD55C\uAE00",
    "http://[::1]/", "http://127.1/", "http://2130706433/", "https://client.example/a:b", "https://bad_host.example/", "https://-bad.example/",
    "https://127.1/", "https://client.example./", "https://[::ffff:127.0.0.1]/",
    "https://client.example/a?", "https://client.example/a#", "https://client.example/a\\b",
  ]) assert.throws(() => new Auth(noIO, [], Date.now, {}, {mailer, emailLinkBase}), /link/i);
  for (const emailLinkBase of ["https://client.example/a-Z_0.~/-", "http://localhost:8080/auth", "http://127.0.0.1:8080/", "HTTPS://CLIENT.EXAMPLE:443/path"]) {
    assert.doesNotThrow(() => new Auth(noIO, [], Date.now, {}, {mailer, emailLinkBase}));
  }
  assert.equal(rules.emailLinkBase("HTTPS://CLIENT.EXAMPLE:443/path"), "https://client.example/path");
  for (const verification of [true, false, "verified", "optional", null]) {
    assert.throws(() => new Auth(noIO, [], Date.now, {}, {email: {verification}}), /auth.email.verification/);
  }
  assert.doesNotThrow(() => new Auth(noIO));
  assert.doesNotThrow(() => new Auth(noIO, [], Date.now, {}, {
    email: {verification: "required"}, mailer, emailLinkBase: "https://example.test", projectName: "Example",
  }));
});

/** These invalid ACE cases follow compiler/testdata/auth-origins-idna.json in the pinned CLI. */
for (const vector of [
  {
    "name": "malformed ACE code point",
    "input": "https://xn--a.test"
  },
  {
    "name": "mapped ACE code points",
    "input": "https://xn--8i7caa.test"
  }
]) {
  test(`email link startup rejects ${vector.name}`, () => {
    assert.throws(() => new Auth(noIO, [], Date.now, {}, {
      email: {verification: "required"}, mailer: {async send() {}}, emailLinkBase: vector.input,
    }), /link/i, vector.name);
  });
}

test("fixed email templates escape project names and never put an action token in account notices", () => {
  const secret = randomUUID();
  const notice = rules.renderAuthMail("account_exists", "A & B", "https://example.test", secret);
  assert.equal(notice.subject, "You already have a A & B account");
  assert.equal(notice.text, "Someone tried to create a A & B account with this email address, but you already have one.\nSign in: https://example.test/auth/signin\nForgot your password? Reset it: https://example.test/auth/reset-password\nIf this wasn't you, you can ignore this email. No new account was created.");
  assert.equal(JSON.stringify(notice).includes(secret), false);
  assert.equal(notice.html.includes("A &amp; B"), true);
  const code = String(Math.floor(Math.random() * 10 ** 6)).padStart(6, "0");
  for (const signup of [false, true]) {
    const mail = rules.renderAuthMail("email_verification", "<Example>", "https://example.test/base", code, signup);
    assert.ok(mail.text.includes(code.slice(0, 3) + " " + code.slice(3)));
    assert.ok(mail.text.startsWith(signup ? "Your code is " : "Use this code to verify your email: "));
    assert.ok(mail.text.includes("It expires in 10 minutes."));
    assert.equal(mail.text.includes("#token="), false);
    assert.equal(mail.html.includes("<a "), false);
  }
  const reset = rules.renderAuthMail("password_reset", "<Example>", "https://example.test/base", secret);
  assert.equal(reset.html.includes("&lt;Example&gt;"), true);
  assert.equal(reset.html.includes('<a href="https://example.test/base/auth/reset-password'), true);
});

test("development mailer exposes verification text only to the explicitly supplied local console", async () => {
  const lines = [];
  const rendered = rules.renderAuthMail("email_verification", "Example", "http://127.0.0.1:3000", randomUUID());
  await developmentAuthMailer(line => lines.push(line)).send({to: "someone@example.test", kind: "email_verification", ...rendered});
  assert.equal(lines.length, 1);
  assert.equal(lines[0].includes("Use this code to verify your email"), true);
  assert.equal(lines[0].includes("someone@example.test"), false);
});

const url = process.env.CHIK_TEST_DATABASE_URL;
const invalidToken = work => assert.rejects(work, error => error instanceof AuthError && error.code === "invalid_token" && error.status === 400);
const invalid = work => rejected(work, "invalid_code", 400);
const rejected = (work, code, status) => assert.rejects(work, error => error instanceof AuthError && error.code === code && error.status === status);
const tick = () => new Promise(resolve => setImmediate(resolve));
const actionToken = mail => new URLSearchParams(new URL(mail.text.split("\n").find(line => line.startsWith("https://"))).hash.slice(1)).get("token");

test("two-step email authentication preserves privacy and atomic state on PostgreSQL", {skip: !url, timeout: 180000}, async t => {
  const {createPostgresPort} = await import("../dist/postgres.js");
  const {createDatabase} = await import("../dist/auth/private/database.js");
  const {createStore} = await import("../dist/auth/store.js");
  const {invokeAuth, browserRequest} = await import("../dist/auth/router.js");
  const port = createPostgresPort(url), other = createPostgresPort(url);
  t.after(async () => { await port.close(); await other.close(); });
  const db = createDatabase(port), mail = [], hooks = [];
  let clock = Date.now();
  const now = () => clock;
  const settings = {email: {verification: "required"}, projectName: "Application", emailLinkBase: "https://app.example.test", mailer: {
    async send(message) { mail.push(message); },
  }};
  const auth = new Auth(port, [], now, {
    async creating(tx, user) {
      assert.equal(typeof (await createDatabase(tx).appAuthUsers.findById({id: user.id})).emailVerifiedAt, "string");
      hooks.push("creating");
    },
    async committed() { hooks.push("committed"); },
  }, settings);
  const fresh = () => randomUUID() + "@example.test";
  const password = randomUUID(), replacement = randomUUID();
  const attempts = new Map();
  const acceptedSignup = result => {
    assert.deepEqual(Object.keys(result).sort(), ["accepted", "attempt"]);
    assert.equal(result.accepted, true);
    assert.match(result.attempt, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  };
  const signup = async (email, value = password, runtime = auth, invite = "") => {
    const result = await runtime.signup(email, value, invite);
    acceptedSignup(result);
    attempts.set(email, result.attempt);
    return result;
  };
  const verify = (verification, runtime = auth) => runtime.verifyEmail(
    verification.attempt ? {attempt: verification.attempt} : verification.email, verification.code);
  const pending = async email => (await db.appAuthSignupRequests.findMany({where: c => c.email.eq(email)}))[0];
  const users = email => db.appAuthUsers.findMany({where: c => c.email.eq(email)});
  const latest = async () => {
    await tick();
    const message = mail.at(-1);
    if (message.kind === "password_reset") return actionToken(message);
    const match = /\b([0-9]{3}) ([0-9]{3})\b/.exec(message.text);
    assert.ok(match, "Verification mail must contain a grouped six digit code");
    const code = match[1] + match[2];
    return {email: message.to, code, attempt: attempts.get(message.to)};
  };
  const request = (cookie = "") => new Request("https://api.example.test/auth.signup", {method: "POST", headers: {
    "content-type": "application/json", origin: "https://app.example.test", "x-chik-browser": "1", cookie,
  }});
  const projectId = randomUUID(), sessionName = `__Host-chik_session_${projectId}`;
  const callBrowser = async (runtime, operation, input, cookie = "") => {
    const req = request(cookie), headers = new Headers();
    const browser = {...browserRequest(req, projectId, new Set(["https://app.example.test"])), headers};
    const result = await invokeAuth(runtime, operation, input, req, browser);
    if (operation === "auth.signup") { acceptedSignup(result); attempts.set(input.email, result.attempt); }
    return {result, headers};
  };
  const email = fresh();
  let firstToken, session, userId;

  await t.test("interleaved signup attempts keep the owner's password and reject crossed codes", async () => {
    const started = performance.now();
    const first = await signup(email);
    assert.ok(performance.now() - started >= 990);
    firstToken = await latest();
    const before = await pending(email);
    const second = await signup(email, replacement), secondToken = await latest();
    assert.ok(first.attempt !== second.attempt);
    const preserved = await db.appAuthSignupRequests.findById({id: first.attempt});
    assert.ok(preserved.passwordHash === before.passwordHash && preserved.codeHash === before.codeHash);
    assert.equal((await users(email)).length, 0);
    assert.deepEqual(hooks, []);
    await invalid(auth.verifyEmail(email, firstToken.code));
    await invalid(verify({...firstToken, code: secondToken.code}));
    await invalid(verify({...secondToken, code: firstToken.code}));
    await invalid(verify({...firstToken, attempt: randomUUID()}));
    const foreignEmail = fresh();
    await signup(foreignEmail);
    let foreign = await latest();
    if (foreign.code === firstToken.code) {
      clock += 60000;
      await auth.sendVerificationEmail({attempt: foreign.attempt});
      foreign = await latest();
    }
    await invalid(verify({...foreign, code: firstToken.code}));
    await invalid(invokeAuth(auth, "auth.verify_email", {attempt: first.attempt, email: foreignEmail, code: firstToken.code}, request()));
    await rejected(auth.signin(email, password), "invalid_credentials", 401);
    await rejected(auth.signin(email, replacement), "invalid_credentials", 401);
    await rejected(auth.signin(fresh(), password), "invalid_credentials", 401);
    session = await verify(firstToken);
    userId = session.userId;
    assert.equal(session.emailVerified, true);
    assert.equal((await auth.session(session.accessToken)).emailVerified, true);
    assert.equal((await db.appAuthSignupRequests.findMany({where: c => c.email.eq(email)})).length, 0);
    assert.equal((await auth.signin(email, password)).userId, userId);
    await rejected(auth.signin(email, replacement), "invalid_credentials", 401);
    assert.deepEqual(hooks, ["creating", "committed"]);
    await invalid(verify(secondToken));
    await invalid(verify(firstToken));
  });

  await t.test("concurrent signups preserve at most three active attempts without evicting existing screens", async () => {
    clock += 3600001;
    const address = fresh();
    const first = await signup(address), second = await signup(address);
    clock += 3600001;
    const parallel = new Auth(other, [], now, {}, settings);
    const results = await Promise.all(Array.from({length: 8}, (_, index) =>
      (index % 2 ? auth : parallel).signup(address, randomUUID())));
    results.forEach(acceptedSignup);
    const rows = await db.appAuthSignupRequests.findMany({where: c => c.email.eq(address)});
    assert.equal(rows.length, 3);
    assert.ok(rows.some(row => row.id === first.attempt) && rows.some(row => row.id === second.attempt));
    const stored = new Set(rows.map(row => row.id));
    assert.equal(results.filter(result => stored.has(result.attempt)).length, 1);
    const remaining = await Promise.allSettled(Array.from({length: 4}, (_, index) =>
      (index % 2 ? auth : parallel).signup(address, randomUUID())));
    assert.equal(remaining.filter(result => result.status === "fulfilled").length, 2);
    for (const result of remaining) {
      if (result.status === "fulfilled") acceptedSignup(result.value);
      else assert.ok(result.reason instanceof AuthError && result.reason.code === "rate_limited" && result.reason.status === 429);
    }
    clock += 86400000;
    const next = await signup(address);
    const active = await db.appAuthSignupRequests.findMany({where: c => c.email.eq(address)});
    assert.equal(active.length, 1);
    assert.equal(active[0].id, next.attempt);
  });

  await t.test("browser signup is private and code confirmation issues only the session cookie", async () => {
    const browserEmail = fresh();
    let code;
    for (const address of [browserEmail, email, email, email, email]) {
      const started = performance.now(), before = mail.length;
      const {result, headers} = await callBrowser(auth, "auth.signup", {email: address, password});
      acceptedSignup(result);
      assert.ok(performance.now() - started >= 990);
      assert.equal(headers.has("set-cookie"), false);
      if (!code) code = await latest();
      await tick();
      if (address === email && mail.length > before) {
        assert.equal(mail.at(-1).kind, "account_exists");
        assert.equal(/\b[0-9]{3} [0-9]{3}\b/.test(mail.at(-1).text), false);
      }
    }
    const {result, headers} = await callBrowser(auth, "auth.verify_email", {attempt: code.attempt, code: code.code});
    assert.equal(result.email_verified, true);
    assert.ok(headers.get("set-cookie").startsWith(sessionName + "="));
    assert.equal("access_token" in result, false);
    const cookie = headers.get("set-cookie").split(";", 1)[0];
    assert.equal((await callBrowser(auth, "auth.session", {}, cookie)).result.id, result.id);
  });

  await t.test("signup policy runs without DB access and only explicit rejection exposes a reason", async () => {
    let seen;
    const policy = new Auth(noIO, [], now, {checkSignup(input) { seen = input; return {reject: "  Registration is closed.  "}; }}, settings);
    const headers = new Headers(), req = request(), browser = {...browserRequest(req, projectId, new Set(["https://app.example.test"])), headers};
    await assert.rejects(invokeAuth(policy, "auth.signup", {email: fresh(), password}, req, browser), error =>
      error.code === "signup_rejected" && error.status === 400 && error.message === "Registration is closed.");
    assert.deepEqual(Object.keys(seen), ["email"]);
    assert.equal(headers.has("set-cookie"), false);
    const slow = new Auth(noIO, [], now, {checkSignup() { return new Promise(() => {}); }}, settings);
    const start = performance.now();
    await rejected(signup(fresh(), password, slow), "signup_check_failed", 500);
    assert.ok(performance.now() - start >= 4900 && performance.now() - start < 7000);
    for (const result of [null, {reject: " "}, {reject: 1}, {reject: "x".repeat(201)}]) {
      const bad = new Auth(noIO, [], now, {checkSignup() { return result; }}, settings);
      await rejected(signup(fresh(), password, bad), "signup_check_failed", 500);
    }
  });

  await t.test("rate-limited repeated signup retains the current code and password", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const code = await latest(), before = await pending(address);
    await auth.requestPasswordReset(address);
    await auth.requestPasswordReset(address);
    const count = mail.length;
    acceptedSignup(await signup(address, replacement));
    await tick();
    assert.equal(mail.length, count);
    const after = await pending(address);
    assert.ok(before.codeHash === after.codeHash && before.passwordHash === after.passwordHash);
    assert.equal((await verify(code)).emailVerified, true);
  });

  await t.test("resend waits sixty seconds rotates the code and concurrent confirmation creates one user", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const oldToken = await latest(), before = await pending(address);
    const count = mail.length, start = performance.now();
    await auth.sendVerificationEmail({attempt: attempts.get(address)});
    await tick();
    assert.equal(mail.length, count);
    clock += 60000;
    await auth.sendVerificationEmail({attempt: attempts.get(address)});
    assert.ok(performance.now() - start >= 990);
    const token = await latest(), after = await pending(address);
    assert.ok(before.passwordHash === after.passwordHash && before.expiresAt === after.expiresAt);
    await invalid(verify(oldToken));
    const parallel = new Auth(other, [], now, {}, settings);
    const results = await Promise.allSettled([verify(token), verify(token, parallel)]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    assert.equal(results.filter(r => r.status === "rejected" && r.reason.code === "invalid_code").length, 1);
    assert.equal((await users(address)).length, 1);
  });

  await t.test("attempt resends rotate only that attempt and email-only requests leave signup codes untouched", async () => {
    clock += 3600001;
    const address = fresh(), first = await signup(address), firstCode = await latest();
    const second = await signup(address, replacement), secondCode = await latest();
    const before = await db.appAuthSignupRequests.findById({id: second.attempt});
    clock += 60000;
    const count = mail.length;
    await auth.sendVerificationEmail(address);
    await auth.sendVerificationEmail({attempt: randomUUID()});
    await tick();
    assert.equal(mail.length, count);
    await invokeAuth(auth, "auth.send_verification_email", {attempt: first.attempt}, request());
    const renewed = {...await latest(), attempt: first.attempt};
    assert.equal(mail.length, count + 1);
    const after = await db.appAuthSignupRequests.findById({id: second.attempt});
    assert.ok(before.codeHash === after.codeHash && before.passwordHash === after.passwordHash);
    await invalid(verify(firstCode));
    await invalid(verify({...secondCode, code: renewed.code}));
    assert.equal((await verify(renewed)).emailVerified, true);
    await invalid(verify(secondCode));
  });

  await t.test("native code wire requires an attempt and issues a usable verified session", async () => {
    clock += 3600001;
    const email = fresh(), req = new Request("https://api.example.test/auth.signup", {method: "POST"});
    const accepted = await invokeAuth(auth, "auth.signup", {email, password}, req);
    acceptedSignup(accepted);
    attempts.set(email, accepted.attempt);
    const code = await latest();
    await invalid(invokeAuth(auth, "auth.verify_email", {code: code.code}, req));
    const result = await invokeAuth(auth, "auth.verify_email", {attempt: code.attempt, code: code.code}, req);
    assert.equal(result.email_verified, true);
    assert.equal(typeof result.access_token, "string");
    assert.equal((await auth.session(result.access_token)).id, result.user_id);
  });

  await t.test("five wrong codes invalidate even the correct code and resend resets attempts", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const code = await latest();
    const wrong = String((Number(code.code) + 1) % 10 ** 6).padStart(6, "0");
    const parallel = new Auth(other, [], now, {}, settings);
    await Promise.all(Array.from({length: 5}, (_, index) => invalid((index % 2 ? auth : parallel).verifyEmail({attempt: code.attempt}, wrong))));
    assert.equal((await pending(address)).attempts, 5);
    await invalid(verify(code));
    assert.equal((await users(address)).length, 0);
    await invalid(auth.verifyEmail(fresh(), code.code));
    clock += 60000;
    await auth.sendVerificationEmail({attempt: attempts.get(address)});
    const next = await latest();
    assert.ok(next.code !== code.code);
    assert.equal((await pending(address)).attempts, 0);
    await invalid(verify(code));
    assert.equal((await verify(next)).emailVerified, true);
  });

  await t.test("codes expire after ten minutes without deleting the twenty four hour signup attempt", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const code = await latest(), row = await pending(address);
    assert.equal(Date.parse(row.codeExpiresAt) - clock, 10 * 60000);
    assert.equal(Date.parse(row.expiresAt) - clock, 24 * 60 * 60000);
    clock += 10 * 60000;
    await invalid(verify(code));
    assert.ok(await pending(address));
    assert.equal((await users(address)).length, 0);
  });

  await t.test("hook rejection exceptions and invalid returns roll back and retain the signup attempt", async () => {
    clock += 3600001;
    for (const [hook, code, status] of [
      [() => ({reject: " Registration is closed. "}), "user_creation_rejected", 422],
      [() => { throw new Error("Internal failure"); }, "user_creation_failed", 500],
      [() => ({reject: false}), "user_creation_failed", 500],
      [() => ({}), "user_creation_failed", 500],
    ]) {
      const address = fresh();
      let committed = 0, attemptedId;
      const failing = new Auth(port, [], now, {
        async creating(tx, user) { attemptedId = user.id; return hook(tx, user); },
        async committed() { committed++; },
      }, settings);
      await signup(address, password, failing);
      const token = await latest();
      await assert.rejects(verify(token, failing), error => error.code === code && error.status === status &&
        (status === 422 ? error.message === "Registration is closed." : error.message !== "Internal failure"));
      assert.equal((await users(address)).length, 0);
      assert.equal(typeof attemptedId, "string");
      assert.equal((await db.appAuthSessions.findMany({where: c => c.userId.eq(attemptedId)})).length, 0);
      assert.ok(await pending(address));
      assert.equal(committed, 0);
      assert.equal((await verify(token)).emailVerified, true);
    }
  });

  await t.test("invite stays unconsumed until verified and hook failure rolls back user invite and session", async () => {
    clock += 3600001;
    const legacy = new Auth(port, [], now), owner = await legacy.signup(fresh(), password);
    await db.appAuthUsers.update({id: owner.userId}, {emailVerifiedAt: new Date(clock).toISOString()});
    const options = {...settings, signup: "invite-only", projectId};
    const invited = new Auth(port, [], now, {async inviteManaging() {}}, options);
    const address = fresh(), invite = await invited.inviteIssue(owner.accessToken, randomUUID(), address);
    await signup(address, password, invited, invite.code);
    const token = await latest();
    assert.equal((await db.appAuthInvites.findById({id: invite.id})).redeemedAt, null);
    const failed = new Auth(port, [], now, {async creating() { return {reject: "Registration is closed."}; }}, options);
    await rejected(verify(token, failed), "user_creation_rejected", 422);
    assert.equal((await users(address)).length, 0);
    assert.equal((await db.appAuthInvites.findById({id: invite.id})).redeemedAt, null);
    const result = await verify(token, invited);
    assert.equal((await db.appAuthInvites.findById({id: invite.id})).redeemedBy, result.userId);
    for (const mutation of ["revoked", "expired", "redeemed"]) {
      const address = fresh(), invite = await invited.inviteIssue(owner.accessToken, randomUUID(), address);
      await signup(address, password, invited, invite.code);
      const token = await latest();
      await db.appAuthInvites.update({id: invite.id}, mutation === "revoked" ? {revokedAt: new Date(clock).toISOString()} :
        mutation === "expired" ? {expiresAt: new Date(clock - 1).toISOString()} : {redeemedAt: new Date(clock).toISOString(), redeemedBy: owner.userId});
      await rejected(verify(token, invited), "invite_invalid", 403);
      assert.equal((await users(address)).length, 0);
    }
  });

  await t.test("a user appearing after signup cannot replace credentials", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const token = await latest();
    await new Auth(port).signup(address, replacement);
    await invalid(verify(token));
    assert.ok(await pending(address));
  });

  await t.test("cleanup after verification is turned off removes expired signup references before invites", async () => {
    clock += 3600001;
    const ownerEmail = fresh(), legacy = new Auth(port, [], now);
    const owner = await legacy.signup(ownerEmail, password);
    await db.appAuthUsers.update({id: owner.userId}, {emailVerifiedAt: new Date(clock).toISOString()});
    const invited = new Auth(port, [], now, {async inviteManaging() {}}, {...settings, signup: "invite-only", projectId});
    const address = fresh(), invite = await invited.inviteIssue(owner.accessToken, randomUUID(), address);
    await signup(address, password, invited, invite.code);
    const row = await pending(address);
    const old = new Date(clock - 400 * 86400000).toISOString();
    await db.appAuthSignupRequests.update({id: row.id}, {expiresAt: old});
    await db.appAuthInvites.update({id: invite.id}, {expiresAt: old});
    const tasks = [], logs = [], original = console.error;
    const context = {waitUntil(work) { tasks.push(work); }, createPort(signal) { return createPostgresPort(url, signal); }};
    console.error = message => logs.push(message);
    try {
      await new Auth(port, [], now, {}, {}, context).signin(ownerEmail, password);
      await Promise.all(tasks);
    } finally { console.error = original; }
    assert.equal(await db.appAuthSignupRequests.findById({id: row.id}), null);
    assert.equal(await db.appAuthInvites.findById({id: invite.id}), null);
    assert.deepEqual(logs, []);
  });

  await t.test("reset requests ignore pending signups and share the address mail budget", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const before = mail.length, start = performance.now();
    assert.deepEqual(await auth.requestPasswordReset(address), {accepted: true});
    assert.ok(performance.now() - start >= 990);
    await tick();
    assert.equal(mail.length, before);
    clock += 60000;
    await auth.sendVerificationEmail({attempt: attempts.get(address)});
    await tick();
    assert.equal(mail.length, before + 1);
    await auth.sendVerificationEmail({attempt: attempts.get(address)});
    await tick();
    assert.equal(mail.length, before + 1);
  });

  await t.test("existing users require password-initiated codes and verified native or browser sessions", async () => {
    clock += 3600001;
    const legacy = new Auth(port, [], now), address = fresh();
    const result = await legacy.signup(address, password);
    const browser = await legacy.signin(address, password, "browser");
    assert.equal(result.emailVerified, false);
    await rejected(legacy.signup(address, password), "account_exists", 409);
    await db.appAuthUsers.update({id: result.userId}, {createdAt: new Date(clock - 86400000).toISOString()});
    const before = mail.length, started = performance.now();
    assert.deepEqual(await auth.sendVerificationEmail(address), {accepted: true});
    assert.ok(performance.now() - started >= 990);
    assert.deepEqual(await auth.sendVerificationEmail(fresh()), {accepted: true});
    await rejected(auth.signin(address, replacement), "invalid_credentials", 401);
    await tick();
    assert.equal(mail.length, before);
    assert.equal((await db.appAuthActionTokens.findMany({where: c => c.userId.eq(result.userId)})).length, 0);
    await rejected(auth.session(result.accessToken), "invalid_token", 401);
    await rejected(auth.revalidateSession(result.sessionId, result.userId), "invalid_token", 401);
    await rejected(auth.session(browser.credential, "browser"), "invalid_token", 401);
    assert.equal((await legacy.session(result.accessToken)).emailVerified, false);
    await rejected(auth.refresh(result.refreshToken), "session_revoked", 401);
    const loginStart = performance.now();
    await rejected(auth.signin(address, password), "email_not_verified", 403);
    assert.ok(performance.now() - loginStart >= 990);
    const first = await latest(), count = mail.length;
    assert.equal((await db.appAuthSessions.findMany({where: c => c.userId.eq(result.userId)})).length, 2);
    await rejected(auth.signin(address, password, "browser"), "email_not_verified", 403);
    await auth.sendVerificationEmail(address);
    await tick();
    assert.equal(mail.length, count);
    clock += 60000;
    await auth.sendVerificationEmail(address);
    const second = await latest();
    assert.ok(first.code !== second.code);
    await invalid(auth.verifyEmail(address, first.code));
    const wrong = String((Number(second.code) + 1) % 10 ** 6).padStart(6, "0");
    for (let i = 0; i < 5; i++) await invalid(auth.verifyEmail(address, wrong));
    await invalid(auth.verifyEmail(address, second.code));
    clock += 60000;
    await auth.sendVerificationEmail(address);
    await tick();
    assert.equal(mail.length, count + 1);
    await rejected(auth.signin(address, password), "email_not_verified", 403);
    const third = await latest();
    await invalid(auth.verifyEmail(address, second.code));
    clock += 60000;
    await rejected(auth.signin(address, password), "email_not_verified", 403);
    await tick();
    assert.equal(mail.length, count + 2);
    const verified = await auth.verifyEmail(address, third.code);
    assert.equal(verified.emailVerified, true);
    assert.equal((await auth.session(verified.accessToken)).id, result.userId);
    await invalid(auth.verifyEmail(address, third.code));
    assert.equal((await auth.signin(address, password)).emailVerified, true);
    const wire = await invokeAuth(auth, "auth.signin", {email: address, password}, request());
    assert.equal(wire.email_verified, true);

    clock += 3600001;
    const browserAddress = fresh(), unverified = await legacy.signup(browserAddress, password);
    const headers = new Headers(), req = request();
    await rejected(invokeAuth(auth, "auth.signin", {email: browserAddress, password}, req,
      {...browserRequest(req, projectId, new Set([req.headers.get("origin")])), headers}), "email_not_verified", 403);
    assert.equal(headers.has("set-cookie"), false);
    const code = await latest();
    clock += 10 * 60000;
    await invalid(auth.verifyEmail(browserAddress, code.code));
    const expiredCount = mail.length;
    await auth.sendVerificationEmail(browserAddress);
    await tick();
    assert.equal(mail.length, expiredCount);
    await rejected(auth.signin(browserAddress, password, "browser"), "email_not_verified", 403);
    const renewed = await latest();
    assert.equal(mail.length, expiredCount + 1);
    const {result: confirmed, headers: confirmedHeaders} = await callBrowser(auth, "auth.verify_email", {email: browserAddress, code: renewed.code});
    assert.equal(confirmed.id, unverified.userId);
    assert.equal(confirmed.email_verified, true);
    const cookie = confirmedHeaders.get("set-cookie").split(";", 1)[0];
    assert.equal((await callBrowser(auth, "auth.session", {}, cookie)).result.id, unverified.userId);
  });

  await t.test("password reset remains single-use and invalidates native and browser sessions", async () => {
    clock += 3600001;
    const browser = await auth.signin(email, password, "browser");
    await auth.requestPasswordReset(email);
    const old = await latest();
    await auth.requestPasswordReset(email);
    const token = await latest();
    await invalidToken(auth.resetPassword(old, password));
    await rejected(auth.resetPassword(token, randomUUID().slice(0, 5)), "invalid_input", 400);
    await auth.resetPassword(token, password);
    await invalidToken(auth.resetPassword(token, password));
    await rejected(auth.session(session.accessToken), "invalid_token", 401);
    await rejected(auth.refresh(session.refreshToken), "session_revoked", 401);
    await rejected(auth.session(browser.credential, "browser"), "invalid_token", 401);
    assert.equal((await auth.signin(email, password)).emailVerified, true);
    const legacy = await new Auth(port).signup(fresh(), replacement);
    const user = await db.appAuthUsers.findById({id: legacy.userId});
    await auth.requestPasswordReset(user.email);
    await auth.resetPassword(await latest(), password);
    const resetUser = await db.appAuthUsers.findById({id: user.id});
    assert.equal(typeof resetUser.emailVerifiedAt, "string");
    assert.equal(resetUser.sessionVersion, user.sessionVersion + 1);
    await rejected(auth.session(legacy.accessToken), "invalid_token", 401);
    await rejected(auth.refresh(legacy.refreshToken), "session_revoked", 401);
    assert.equal((await auth.signin(user.email, password)).emailVerified, true);
  });

  await t.test("expired attempts and action tokens reject consumption and cleanup uses bounded expiry order", async () => {
    clock += 3600001;
    const address = fresh();
    await signup(address);
    const token = await latest();
    clock += 86400000;
    await invalid(verify(token));
    const store = createStore(port), cutoff = new Date(clock).toISOString();
    const rows = await store.expiredSignupRequests(cutoff, 2);
    assert.ok(rows.length > 0 && rows.length <= 2);
    for (const row of rows) await store.transaction(tx => tx.deleteExpiredSignupRequest(row, cutoff));
    for (const row of rows) assert.equal(await db.appAuthSignupRequests.findById({id: row.id}), null);
    for (const row of [...await store.consumedActionTokens(1000), ...await store.expiredActionTokens(cutoff, 1000)]) {
      await store.transaction(tx => tx.deleteExpiredActionToken(row, cutoff));
    }
    assert.equal((await store.expiredActionTokens(cutoff, 1)).length, 0);
    await invalid(auth.verifyEmail(fresh(), randomUUID()));
    await invalid(invokeAuth(auth, "auth.verify_email", {}, request()));
  });

  await t.test("caller IP budget includes missing accounts and ignores forged forwarding headers", async () => {
    clock += 3600001;
    const before = mail.length;
    for (let i = 0; i < 30; i++) await auth.requestPasswordReset(fresh(), "192.0.2.10");
    await auth.requestPasswordReset(email, "192.0.2.10");
    await tick();
    assert.equal(mail.length, before);
    const forged = new Request("https://api.example.test/auth.request_password_reset", {method: "POST", headers: {
      "x-forwarded-for": "192.0.2.10", "cf-connecting-ip": "192.0.2.10",
    }});
    assert.deepEqual(await invokeAuth(auth, "auth.request_password_reset", {email}, forged), {accepted: true});
    await tick();
    assert.equal(mail.length, before + 1);
  });

  await t.test("mail transport failures do not expose recipient or action links", async () => {
    clock += 3600001;
    const logs = [], original = console.error;
    const failure = new Auth(port, [], now, {}, {...settings, mailer: {async send(message) { throw new Error(message.to + message.text); }}});
    console.error = message => logs.push(message);
    try { assert.deepEqual(await failure.requestPasswordReset(email), {accepted: true}); await tick(); }
    finally { console.error = original; }
    assert.deepEqual(logs.map(line => JSON.parse(line)), [{cause: "auth_mail_failed", kind: "password_reset"}]);
    assert.equal(logs.some(line => line.includes(email) || line.includes("https://")), false);
  });

  await t.test("action expiry is checked again after waiting for a locked user", async () => {
    clock += 3600001;
    assert.equal(typeof userId, "string");
    await auth.requestPasswordReset(email);
    const token = await latest(), entered = Promise.withResolvers(), release = Promise.withResolvers();
    const locked = other.transaction(async tx => {
      const user = await createDatabase(tx).appAuthUsers.findById({id: userId});
      await createDatabase(tx).appAuthUsers.update({id: userId}, {sessionVersion: user.sessionVersion});
      entered.resolve();
      await release.promise;
    });
    await entered.promise;
    const result = invalidToken(auth.resetPassword(token, replacement));
    await new Promise(resolve => setTimeout(resolve, 250));
    clock += 3600000;
    release.resolve();
    await locked;
    await result;
  });

  await t.test("required signup shares the ten-attempt identity limit without exposing account existence", async () => {
    const legacy = new Auth(port, [], now), existing = fresh();
    await legacy.signup(existing, password);
    for (const address of [fresh(), existing]) {
      clock += 3600001;
      for (let i = 0; i < 10; i++) {
        await signup(i % 2 ? address : ` ${address.toUpperCase()} `);
      }
      await rejected(auth.signup(address, password), "rate_limited", 429);
      await rejected(legacy.signup(address, password), "rate_limited", 429);
      clock += 15 * 60_000;
      await signup(address);
    }
  });

  await t.test("mail without a trusted caller IP keeps independent addresses and the address budget", async () => {
    clock += 3600001;
    const runtime = new Auth(port, [], now, {}, settings);
    for (let i = 0; i < 30; i++) await runtime.requestPasswordReset(fresh());
    const address = fresh(), before = mail.length;
    await signup(address, password, runtime);
    await tick();
    assert.equal(mail.length, before + 1);
    const confirmation = await latest();
    assert.equal((await verify(confirmation, runtime)).emailVerified, true);
    for (const sent of [2, 3, 3]) {
      assert.deepEqual(await runtime.requestPasswordReset(address), {accepted: true});
      await tick();
      assert.equal(mail.length, before + sent);
    }
  });
});
