import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { Auth, AuthError, invokeAuth, normalizeEmail, browserRequest } from "../dist/auth/index.js";
import { hashToken } from "../dist/auth/crypto.js";
import { createDatabase } from "../dist/auth/private/database.js";
import { createPostgresPort } from "../dist/postgres.js";

const port = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL);
const other = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL);
const db = createDatabase(port);
const password = "correct horse battery staple";
let clock = Date.parse("2030-01-01T00:00:00Z");
const now = () => clock;
const options = {signup: "invite-only", projectId: randomUUID()};
const rejects = (promise, code) => assert.rejects(promise, error => error instanceof AuthError && error.code === code);
const observe = (base, before, after, committed) => ({
  async query(sql, args) { await before?.(sql, args); const rows = await base.query(sql, args); await after?.(sql, args, rows); return rows; },
  async transaction(work) { const result = await base.transaction(tx => work(observe(tx, before, after))); await committed?.(); return result; },
});
const logs = [];
const originalLog = console.error;
console.error = (...args) => logs.push(args);
try {
  const open = new Auth(port, [], now);
  const browser = await open.signup("browser@example.test", password, "", "browser");
  const storedBrowser = await db.appAuthSessions.findById({id: browser.sessionId});
  assert.ok(storedBrowser.transport === "browser" && storedBrowser.tokenHash === hashToken(browser.credential));
  assert.equal((await db.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(browser.sessionId)})).length, 0);
  assert.ok(Date.parse(storedBrowser.createdAt) === clock);
  assert.equal(Date.parse(browser.expiresAt) - Date.parse(storedBrowser.createdAt), 2592000000);
  await rejects(open.session(browser.credential), "invalid_token");
  await rejects(open.refresh(browser.credential), "invalid_token");
  const browserRequestHeaders = {"origin": "https://web.example.test", "x-chik-browser": "1", "content-type": "application/json"};
  const origins = new Set([browserRequestHeaders.origin]);
  const req = headers => new Request("https://api.example.test/auth.session", {method: "POST", headers});
  assert.ok(browserRequest(req({authorization:"Bearer "+browser.credential}), "", origins) === undefined);
  const parsed = browserRequest(req(browserRequestHeaders), options.projectId, origins);
  const cookie = `${parsed.cookieName}=${browser.credential}`;
  const authenticatedRequest = req({...browserRequestHeaders, cookie});
  const context = {...browserRequest(authenticatedRequest, options.projectId, origins), headers: new Headers()};
  const wireBrowser = await invokeAuth(open, "auth.session", {}, authenticatedRequest, context);
  assert.deepEqual(Object.keys(wireBrowser).sort(), ["email", "email_verified", "expires_at", "id", "session_id"]);
  assert.ok(!JSON.stringify(wireBrowser).includes(browser.credential));
  assert.equal(context.headers.has("set-cookie"), false);
  for (const headers of [ {...browserRequestHeaders, origin: "https://evil.example.test", cookie},
    {...browserRequestHeaders, authorization: "Bearer " + browser.credential, cookie},
    {...browserRequestHeaders, cookie: cookie + "; " + cookie}, {...browserRequestHeaders, "sec-fetch-site": "cross-site"}]) {
    assert.throws(() => browserRequest(req(headers), options.projectId, origins), AuthError);
  }
  clock = Date.parse(browser.expiresAt) - 1;
  assert.ok((await open.session(browser.credential, "browser")).sessionId === browser.sessionId);
  const renewedBrowser = await db.appAuthSessions.findById({id: browser.sessionId});
  assert.equal(Date.parse(renewedBrowser.expiresAt), clock + 2592000000);
  clock = Date.parse(renewedBrowser.expiresAt);
  await rejects(open.session(browser.credential, "browser"), "invalid_token");
  await open.logout(browser.credential, "browser");
  await open.logout(browser.credential, "browser");
  clock = Date.parse("2030-01-01T00:00:00Z");
  const owner = await open.signup("owner@example.test", password);
  const outsider = await open.signup("outsider@example.test", password);
  let authorizations = 0;
  const hooks = {async inviteManaging(transaction, actor, projectId) {
    assert.ok(transaction !== port, "management must use a transaction");
    assert.ok(projectId === options.projectId, "project must come from server options");
    if (actor.user.id !== owner.userId) throw new AuthError("permission_denied", 403);
    authorizations++;
  }};
  const closed = new Auth(port, [], now, hooks, options);
  await rejects(closed.inviteList(owner.accessToken, "", "browser"), "invalid_input");
  const issue = email => closed.inviteIssue(owner.accessToken, randomUUID(), email);
  await rejects(new Auth(port, [], now, {}, options).inviteList(owner.accessToken, ""), "permission_denied");
  await rejects(new Auth(port, [], now, hooks, {signup: "invite-only"}).inviteList(owner.accessToken, ""), "service_unavailable");
  await rejects(closed.inviteList(outsider.accessToken, ""), "permission_denied");
  await rejects(open.inviteList(owner.accessToken, ""), "not_found");
  const request = token => new Request("https://example.test/auth.invite_list", {headers: token ? {authorization: "Bearer " + token} : {}});
  await rejects(invokeAuth(closed, "auth.invite_list", {cursor: ""}, request()), "unauthenticated");
  await rejects(invokeAuth(closed, "auth.invite_list", {cursor: ""}, request("x".repeat(43))), "invalid_token");
  assert.equal((await closed.inviteList(owner.accessToken, "")).items.length, 0);
  await rejects(closed.inviteList(owner.accessToken, "not-a-cursor"), "invalid_input");

  const beforeExpiry = clock;
  const expiresDuringIssue = new Auth(port, [], now, {async inviteManaging(...args) {
    await hooks.inviteManaging(...args);
    clock = Date.parse(owner.expiresAt);
  }}, options);
  const expiryID = randomUUID();
  const issuedAtExpiry = await invokeAuth(expiresDuringIssue, "auth.invite_issue",
    {id: expiryID, email: "authorized-before-expiry@example.test"}, request(owner.accessToken));
  assert.equal(issuedAtExpiry.status, "issued");
  await rejects(closed.inviteIssue(owner.accessToken, expiryID, "authorized-before-expiry@example.test"), "invalid_token");
  assert.equal((await db.appAuthInvites.findMany({where: c => c.id.equals(expiryID)})).length, 1);
  clock = beforeExpiry;

  const invitation = await issue(" Recipient@Example.test ");
  assert.ok(/^[A-Za-z0-9_-]{43}$/.test(invitation.code));
  assert.equal(invitation.email, "recipient@example.test");
  assert.equal(Date.parse(invitation.expiresAt) - Date.parse(invitation.createdAt), 7 * 86400000);
  const stored = await db.appAuthInvites.findById({id: invitation.id});
  assert.ok(stored.codeHash === hashToken(invitation.code));
  assert.ok(!Object.values(stored).includes(invitation.code));
  await rejects(closed.inviteIssue(owner.accessToken, invitation.id, invitation.email), "invite_issue_replayed");
  const wire = await invokeAuth(closed, "auth.invite_list", {cursor: ""}, request(owner.accessToken));
  assert.deepEqual(Object.keys(wire.items[0]).sort(), ["created_at", "email", "expires_at", "id", "status"]);
  await rejects(closed.signup("recipient@example.test", password), "invite_required");
  await rejects(closed.signup("different@example.test", password, invitation.code), "invite_invalid");
  await rejects(closed.signup("recipient+tag@example.test", password, invitation.code), "invite_invalid");
  const last = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(invitation.code.at(-1));
  const noncanonical = invitation.code.slice(0, -1) + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last + 1];
  await rejects(closed.signup(invitation.email, password, noncanonical), "invite_invalid");
  await rejects(invokeAuth(closed, "auth.signup", {email: invitation.email, password, invite_code: null}, request()), "invalid_input");

  const rollback = new Auth(port, [], now, {...hooks, async creating() { throw new Error("private hook failure"); }}, options);
  await rejects(rollback.signup(invitation.email, password, invitation.code), "user_creation_failed");
  assert.deepEqual(logs.splice(0), [[JSON.stringify({cause: "user_creation_failed"})]]);
  assert.ok((await db.appAuthInvites.findById({id: invitation.id})).redeemedAt === null);
  const recipient = await closed.signup(" RECIPIENT@example.test ", password, invitation.code);
  await rejects(closed.signup(invitation.email, password, invitation.code), "invite_invalid");
  await rejects(closed.inviteRevoke(owner.accessToken, invitation.id), "invite_already_redeemed");
  assert.ok((await closed.session(recipient.accessToken)).id === recipient.userId);
  assert.equal((await db.appAuthUsers.findById({id: recipient.userId})).email, invitation.email);
  assert.equal((await db.appAuthUsers.findById({id: recipient.userId})).emailVerifiedAt, null);

  const revoked = await issue("revoked@example.test");
  assert.equal((await closed.inviteRevoke(owner.accessToken, revoked.id)).status, "revoked");
  assert.equal((await closed.inviteRevoke(owner.accessToken, revoked.id)).status, "revoked");
  await rejects(closed.signup(revoked.email, password, revoked.code), "invite_invalid");
  for (let i = 0; i < 10; i++) await rejects(closed.signup("limited-invite@example.test", password), "invite_required");
  await rejects(closed.signup("limited-invite@example.test", password, invitation.code), "rate_limited");

  const concurrent = await issue("concurrent@example.test");
  let arrivals = 0;
  const barrier = Promise.withResolvers();
  const before = async sql => {
    if (sql.startsWith('update "public"."app_auth_invites"')) {
      if (++arrivals === 2) barrier.resolve();
      await barrier.promise;
    }
  };
  const race = await Promise.allSettled([port, other].map(base =>
    new Auth(observe(base, before), [], now, {}, options).signup(concurrent.email, password, concurrent.code)));
  assert.equal(race.filter(result => result.status === "fulfilled").length, 1);
  assert.equal(race.find(result => result.status === "rejected").reason.code, "invite_invalid");
  assert.ok((await closed.session(race.find(result => result.status === "fulfilled").value.accessToken)).id);

  for (const revokeFirst of [false, true]) {
    const invitation = await issue(`revoke-race-${revokeFirst}@example.test`);
    const locked = Promise.withResolvers(), attempted = Promise.withResolvers();
    const winnerPort = observe(port, undefined, async (sql, args, rows) => {
      if (sql.startsWith('update "public"."app_auth_invites"') && rows[0]?.id === invitation.id) {
        locked.resolve();
        await attempted.promise;
      }
    });
    const loserPort = observe(other, async (sql, args) => {
      if (sql.startsWith('update "public"."app_auth_invites"') && args.includes(invitation.id)) attempted.resolve();
    });
    const winner = new Auth(winnerPort, [], now, hooks, options);
    const loser = new Auth(loserPort, [], now, hooks, options);
    const winning = revokeFirst ? winner.inviteRevoke(owner.accessToken, invitation.id)
      : winner.signup(invitation.email, password, invitation.code);
    await locked.promise;
    const losing = revokeFirst ? loser.signup(invitation.email, password, invitation.code)
      : loser.inviteRevoke(owner.accessToken, invitation.id);
    await rejects(losing, revokeFirst ? "invite_invalid" : "invite_already_redeemed");
    const result = await winning;
    if (!revokeFirst) assert.ok((await closed.session(result.accessToken)).id);
  }

  const duplicate = await issue("outsider@example.test");
  await rejects(closed.signup(duplicate.email, password, duplicate.code), "account_exists");
  assert.ok((await db.appAuthInvites.findById({id: duplicate.id})).redeemedAt === null);
  const failedSession = await issue("session-failure@example.test");
  const broken = observe(port, async sql => {
    if (sql.startsWith('insert into "public"."app_auth_sessions"')) throw new Error("private session failure");
  });
  await assert.rejects(new Auth(broken, [], now, {}, options).signup(failedSession.email, password, failedSession.code));
  assert.ok((await db.appAuthInvites.findById({id: failedSession.id})).redeemedAt === null);
  assert.equal((await db.appAuthUsers.findMany({where: c => c.email.equals(failedSession.email)})).length, 0);

  const ackID = randomUUID();
  const uncertain = new Auth(observe(port, undefined, undefined, async () => { throw new Error("private commit acknowledgement"); }), [], now, hooks, options);
  await assert.rejects(uncertain.inviteIssue(owner.accessToken, ackID, "issue-ack@example.test"));
  assert.ok(await db.appAuthInvites.findById({id: ackID}));
  await rejects(closed.inviteIssue(owner.accessToken, ackID, "issue-ack@example.test"), "invite_issue_replayed");
  const ackSignup = await issue("signup-ack@example.test");
  await assert.rejects(uncertain.signup(ackSignup.email, password, ackSignup.code));
  assert.ok((await db.appAuthInvites.findById({id: ackSignup.id})).redeemedAt !== null);
  assert.ok((await open.signin(ackSignup.email, password)).userId);

  const effect = await issue("effect@example.test");
  await rejects(new Auth(port, [], now, {async committed() { throw new Error("private committed failure"); }}, options)
    .signup(effect.email, password, effect.code), "user_created_effect_failed");
  assert.ok((await db.appAuthInvites.findById({id: effect.id})).redeemedAt !== null);
  assert.ok((await open.signin(effect.email, password)).userId);

  const identityInvite = await issue("identity@example.test");
  const providers = [{id: "company", async verify(credential) {
    if (credential !== "valid") throw new Error("private verifier detail");
    return {subject: "employee", verifiedEmail: " IDENTITY@example.test "};
  }}];
  const identity = new Auth(port, providers, now, {}, options);
  await rejects(identity.signinIdentity("company", "invalid", identityInvite.code), "invalid_credentials");
  await rejects(identity.signinIdentity("company", "valid"), "invite_required");
  const employee = await identity.signinIdentity("company", "valid", identityInvite.code);
  assert.ok((await identity.signinIdentity("company", "valid")).userId === employee.userId);
  const conflict = await issue("identity@example.test");
  const conflicting = new Auth(port, [{id: "another", async verify() { return {subject: "other", verifiedEmail: conflict.email}; }}], now, {}, options);
  await rejects(conflicting.signinIdentity("another", "valid", conflict.code), "identity_conflict");
  assert.ok((await db.appAuthInvites.findById({id: conflict.id})).redeemedAt === null);

  for (let i = 0; i < 65; i++) await issue(`page-${i}@example.test`);
  const first = await closed.inviteList(owner.accessToken, "");
  assert.equal(first.items.length, 50);
  assert.ok(first.nextCursor.length > 0);
  const second = await closed.inviteList(owner.accessToken, first.nextCursor);
  assert.equal(second.nextCursor, "");
  assert.ok(second.items.every(item => !first.items.some(previous => previous.id === item.id)));
  assert.ok(authorizations > 50);

  const expiring = await issue("expiry@example.test");
  const expiry = Date.parse(expiring.expiresAt);
  const afterLock = async (sql, args, rows) => {
    if (sql.startsWith('update "public"."app_auth_invites"') && rows[0]?.id === expiring.id) clock = expiry;
  };
  clock = expiry - 1;
  await rejects(new Auth(observe(port, undefined, afterLock), [], now, {}, options)
    .signup(expiring.email, password, expiring.code), "invite_invalid");
  assert.ok((await db.appAuthInvites.findById({id: expiring.id})).redeemedAt === null);
  await rejects(closed.signup(expiring.email, password, expiring.code), "invite_invalid");
  clock = expiry + 1;
  const relogin = await open.signin("owner@example.test", password);
  assert.equal((await closed.inviteRevoke(relogin.accessToken, expiring.id)).status, "expired");
  const beforeCleanup = (await db.appAuthInvites.findMany()).length;
  clock = expiry + 30 * 86400000;
  const cleanupLogin = await open.signin("owner@example.test", password);
  assert.equal((await db.appAuthInvites.findMany()).length, beforeCleanup);
  const pending = [];
  const cleanup = {
    waitUntil(work) { pending.push(work); },
    createPort(signal) { return createPostgresPort(process.env.CHIK_TEST_DATABASE_URL, signal); },
  };
  await new Auth(port, [], now, {}, {}, cleanup).signin("owner@example.test", password);
  await Promise.all(pending.splice(0));
  const afterCleanup = (await db.appAuthInvites.findMany()).length;
  assert.equal(beforeCleanup - afterCleanup, 2);
  assert.ok(afterCleanup > 0);
  let deleteFailures = 0;
  const fault = { ...cleanup, createPort(signal) {
    const base = createPostgresPort(process.env.CHIK_TEST_DATABASE_URL, signal);
    return {...observe(base, async sql => {
      if (sql.startsWith('delete from "public"."app_auth_invites"') && ++deleteFailures === 1) {
        throw new Error(`private cleanup error ${invitation.code} ${stored.codeHash}`);
      }
    }), close: () => base.close()};
  }};
  const cleanupIssue = await new Auth(port, [], now, hooks, options, fault)
    .inviteIssue(cleanupLogin.accessToken, randomUUID(), "cleanup-failure@example.test");
  await Promise.all(pending.splice(0));
  assert.equal(cleanupIssue.status, "issued");
  assert.ok(await db.appAuthInvites.findById({id: cleanupIssue.id}));
  assert.equal(deleteFailures, 1);
  assert.deepEqual(logs, [["Authentication cleanup failed (invite)."]]);
  assert.equal(normalizeEmail(" User.Name+tag@Example.test "), "user.name+tag@example.test");
  assert.ok(logs.flat().every(value => typeof value === "string" && !value.includes(invitation.code) &&
    !value.includes(stored.codeHash) && !value.includes("private cleanup error")));
  console.log("PostgreSQL invitations: authorization, canonical code, address binding, rollback, replay, concurrent use, identity, pagination, expiry and bounded retention passed.");
} finally {
  console.error = originalLog;
  await other.close();
  await port.close();
}

await import("./verify-cleanup.js");
