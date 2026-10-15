import { Buffer } from "node:buffer";
import { hashPassword, verifyPassword, randomToken, hashToken } from "./crypto.js";
import { sessionPolicy, sessionExpiry, sessionState, cookieMaxAge, accessLifetimeMillis, normalizeEmail, validatePassword, nextRateLimit, type SessionPolicy } from "./rules.js";
import { AuthError } from "./errors.js";
import type { Store, AppAuthUsersRow, AppAuthInvitesRow, AppAuthSessionsRow, AppAuthRefreshTokensRow, AppAuthRateLimitsRow } from "./store.js";
import type { Tokens, BrowserSession, IdentityProvider, AuthUser, AuthOptions, SessionTransport, InviteSummary, AuthActor } from "./types.js";

const day = 24 * 60 * 60_000;

export class Flows {
  private readonly providers = new Map<string, IdentityProvider>();
  readonly policy: Required<SessionPolicy>;

  constructor(private readonly db: Store, providers: readonly IdentityProvider[], private readonly now: () => number,
    private readonly options: AuthOptions) {
    if (options.signup !== undefined && options.signup !== "open" && options.signup !== "invite-only") {
      throw new Error("Invalid signup policy.");
    }
    this.policy = sessionPolicy(options.session);
    for (const provider of providers) {
      if (!/^[a-z][a-z0-9_-]{0,62}$/.test(provider.id) || provider.id === "password" || this.providers.has(provider.id)) {
        throw new Error("Invalid or duplicate identity provider.");
      }
      this.providers.set(provider.id, provider);
    }
  }

  async prepareSignup(email: string, password: string, inviteCode: string) {
    email = normalizeEmail(email);
    validatePassword(password);
    if (typeof inviteCode !== "string") throw new AuthError("invalid_input", 400);
    await this.rateLimit("signup", email);
    if (this.options.signup === "invite-only") await this.checkInvite(this.db, email, inviteCode);
    return {email, passwordHash: await hashPassword(password)};
  }

  async commitSignup(tx: Store, input: {email: string; passwordHash: string}, inviteCode: string,
    transport: SessionTransport, previousCredential: string, creating: (user: AuthUser) => Promise<void>) {
    const {email, passwordHash} = input;
    const invite = await this.lockInvite(tx, email, inviteCode);
    const user = await tx.createUser(email, passwordHash);
    if (invite) await tx.updateInvite(invite.id, {redeemedAt: this.timestamp(), redeemedBy: user.id});
    await creating(publicUser(user));
    return this.issue(tx, user, transport, previousCredential);
  }

  async prepareSignin(email: string, password: string) {
    email = normalizeEmail(email);
    validatePassword(password);
    await this.rateLimit("signin", email);
    const user = await this.db.userByEmail(email);
    const matched = await verifyPassword(password, user?.passwordHash ?? null);
    if (!matched || !user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
    return user;
  }

  commitSignin(tx: Store, user: AppAuthUsersRow, transport: SessionTransport, previousCredential: string) {
    return this.issue(tx, user, transport, previousCredential);
  }

  async prepareIdentity(providerID: string, credential: unknown, inviteCode: string) {
    if (typeof inviteCode !== "string") throw new AuthError("invalid_input", 400);
    const provider = this.providers.get(providerID);
    if (!provider) throw new AuthError("unsupported_identity_provider", 400);
    await this.rateLimit("identity_attempt", providerID, 100, 60_000);
    let identity: Awaited<ReturnType<IdentityProvider["verify"]>>;
    try { identity = await provider.verify(credential); }
    catch { throw new AuthError("invalid_credentials", 401); }
    const email = normalizeEmail(identity.verifiedEmail);
    if (typeof identity.subject !== "string" || identity.subject.length === 0 || identity.subject.length > 2048) {
      throw new AuthError("invalid_credentials", 401);
    }
    await this.rateLimit("identity", providerID + ":" + identity.subject);
    if (this.options.signup === "invite-only" &&
        !await this.db.identity(providerID, identity.subject)) {
      await this.rateLimit("signup", email);
      await this.checkInvite(this.db, email, inviteCode);
    }
    return {providerID, identity, email};
  }

  async commitIdentity(tx: Store, input: Awaited<ReturnType<Flows["prepareIdentity"]>>, inviteCode: string,
    transport: SessionTransport, previousCredential: string, creating: (user: AuthUser) => Promise<void>) {
    const {providerID, identity, email} = input;
    const stored = await tx.identity(providerID, identity.subject);
    const invite = stored ? undefined : await this.lockInvite(tx, email, inviteCode);
    const user = stored
      ? await tx.user(stored.userId)
      : await tx.createUser(email, null);
    if (!user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
    if (!stored) {
      if (invite) await tx.updateInvite(invite.id, {redeemedAt: this.timestamp(), redeemedBy: user.id});
      await tx.createIdentity(providerID, identity.subject, user.id);
      await creating(publicUser(user));
    }
    return this.issue(tx, user, transport, previousCredential);
  }

  async prepareRefresh(refreshToken: string) {
    const stored = await this.db.refreshByToken(hashToken(refreshToken));
    if (!stored) throw new AuthError("invalid_token", 401);
    return stored;
  }

  async commitRefresh(tx: Store, stored: AppAuthRefreshTokensRow) {
    const session = await tx.lockSession(stored.sessionId);
    if (!session || session.transport !== "native") return undefined;
    const current = await tx.refresh(stored.id);
    const issuedAt = this.now();
    const state = await this.familyState(tx, session, issuedAt);
    const user = await tx.user(session.userId);
    if (!current || current.consumedAt !== null || state.expired || Date.parse(current.expiresAt) <= issuedAt ||
        !user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) {
      await tx.updateSession(session.id, {revokedAt: this.timestamp()});
      return undefined;
    }
    const timestamp = new Date(issuedAt).toISOString();
    const consumed = await tx.consumeRefresh(current.id, timestamp);
    if (!consumed) {
      await tx.updateSession(session.id, {revokedAt: this.timestamp()});
      return undefined;
    }
    const accessToken = randomToken();
    const nextRefresh = randomToken();
    const expiresAt = new Date(issuedAt + accessLifetimeMillis).toISOString();
    const refreshExpiresAt = new Date(sessionExpiry(this.policy, state.firstLoginAt, issuedAt)).toISOString();
    await tx.updateSession(session.id, {tokenHash: hashToken(accessToken), expiresAt,
      firstLoginAt: new Date(state.firstLoginAt).toISOString(), lastRenewedAt: timestamp});
    await tx.createRefresh({sessionId: session.id, tokenHash: hashToken(nextRefresh), expiresAt: refreshExpiresAt, createdAt: timestamp});
    return {accessToken, refreshToken: nextRefresh, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id};
  }

  async commitSession(tx: Store, accessToken: string, transport: SessionTransport) {
    const candidate = await tx.sessionByToken(hashToken(accessToken));
    if (candidate && candidate.transport !== transport) throw new AuthError(transport === "browser" ? "invalid_input" : "invalid_token", transport === "browser" ? 400 : 401);
    const session = await this.lockSession(tx, candidate, hashToken(accessToken));
    return session && this.validateSession(tx, session);
  }

  async commitRevalidateSession(tx: Store, sessionId: string, userId: string) {
    const candidate = await tx.session(sessionId);
    if (candidate?.userId !== userId || candidate.transport !== "native") return undefined;
    const session = await this.lockSession(tx, candidate);
    return session && this.validateSession(tx, session);
  }

  async commitBrowserLogout(tx: Store, accessToken: string) {
    const session = await tx.sessionByToken(hashToken(accessToken));
    if (!session) return;
    if (session.transport !== "browser") throw new AuthError("invalid_input", 400);
    await tx.revokeSession(session.id, this.timestamp(), hashToken(accessToken));
  }

  async commitInviteActor(db: Store, accessToken: string, transport: SessionTransport,
    managing: (actor: AuthActor, projectId: string) => Promise<void>) {
    const candidate = await db.sessionByToken(hashToken(accessToken));
    if (candidate && candidate.transport !== transport) {
      throw new AuthError(transport === "browser" ? "invalid_input" : "invalid_token", transport === "browser" ? 400 : 401);
    }
    const session = await this.lockSession(db, candidate, hashToken(accessToken));
    if (!session) return undefined;
    const authenticated = await this.validateSession(db, session);
    if (!authenticated) return undefined;
    const user = await db.lockUser(authenticated.id, session.userSessionVersion);
    if (!user) return undefined;
    const actor = Object.freeze({id: session.id, user: Object.freeze({id: user.id, email: user.email})});
    await managing(actor, this.options.projectId ?? "");
    return actor;
  }

  async commitInviteIssue(db: Store, actor: AuthActor, id: string, email: string) {
    if (await db.invite(id)) throw new AuthError("invite_issue_replayed", 409);
    const code = randomToken();
    const createdAt = this.timestamp();
    const row = await db.createInvite({id, email, codeHash: hashToken(code), issuedBy: actor.user.id,
      createdAt, expiresAt: new Date(Date.parse(createdAt) + 7 * day).toISOString()});
    return {...inviteSummary(row, this.now()), code};
  }

  async commitInviteList(db: Store, after: [string, string] | undefined) {
    const rows = await db.listInvites(after);
    const page = rows.slice(0, 50);
    const last = page.at(-1);
    return {items: page.map(row => inviteSummary(row, this.now())), nextCursor: rows.length > 50 && last
      ? Buffer.from(JSON.stringify([last.createdAt, last.id])).toString("base64url") : ""};
  }

  async commitInviteRevoke(db: Store, id: string) {
    const candidate = await db.invite(id);
    if (!candidate) throw new AuthError("not_found", 404);
    const row = await db.lockInviteExpiry(candidate);
    if (!row) throw new AuthError("not_found", 404);
    const summary = inviteSummary(row, this.now());
    if (summary.status === "redeemed") throw new AuthError("invite_already_redeemed", 409);
    if (summary.status === "issued") await db.updateInvite(id, {revokedAt: this.timestamp()});
    return {id, status: summary.status === "issued" ? "revoked" as const : summary.status};
  }

  async commitCleanupSession(tx: Store, candidate: AppAuthSessionsRow, refreshBudget: number) {
    // Candidate timestamps never authorize deletion; recheck the locked family under Q1.
    const locked = await tx.lockCleanupSession(candidate);
    if (!locked || !(await this.familyState(tx, locked, this.now())).expired) return 0;
    const children = await tx.refreshChildren(locked.id, refreshBudget + 1);
    const deleting = children.slice(0, refreshBudget);
    for (const child of deleting) await tx.deleteRefresh(child.id);
    if (children.length === deleting.length) await tx.deleteSession(locked.id);
    return deleting.length;
  }

  async commitCleanupRateLimit(tx: Store, candidate: AppAuthRateLimitsRow, cutoff: string) {
    const locked = await tx.lockRateLimit(candidate, cutoff);
    if (locked) await tx.deleteRateLimit({action: candidate.action, keyHash: candidate.keyHash});
  }

  async commitCleanupInvite(tx: Store, row: AppAuthInvitesRow, cutoff: string) {
    const locked = await tx.lockInviteExpiry(row, cutoff);
    if (locked) await tx.deleteInvite(row.id);
  }

  private async checkInvite(db: Store, email: string, code: string): Promise<AppAuthInvitesRow> {
    if (!code) throw new AuthError("invite_required", 403);
    if (!/^[A-Za-z0-9_-]{43}$/.test(code) || Buffer.from(code, "base64url").toString("base64url") !== code) {
      throw new AuthError("invite_invalid", 403);
    }
    const row = await db.inviteByCode(hashToken(code));
    if (!row || row.email !== email || row.redeemedAt !== null || row.redeemedBy !== null ||
        row.revokedAt !== null || Date.parse(row.expiresAt) <= this.now()) throw new AuthError("invite_invalid", 403);
    return row;
  }

  private async lockInvite(db: Store, email: string, code: string): Promise<AppAuthInvitesRow | undefined> {
    if (this.options.signup !== "invite-only") return undefined;
    const candidate = await this.checkInvite(db, email, code);
    const row = await db.lockInvite(candidate, email, hashToken(code), this.timestamp());
    if (!row || Date.parse(row.expiresAt) <= this.now()) throw new AuthError("invite_invalid", 403);
    return row;
  }

  private lockSession(tx: Store, candidate: AppAuthSessionsRow | undefined, tokenHash?: string): Promise<AppAuthSessionsRow | undefined> {
    if (!candidate) return Promise.resolve(undefined);
    return tx.lockSession(candidate.id, tokenHash);
  }

  private async familyState(tx: Store, session: AppAuthSessionsRow, now: number) {
    const latest = session.transport === "native" ? await tx.latestRefresh(session.id) : undefined;
    return sessionState(session, latest, this.policy, now);
  }

  private async validateSession(tx: Store, session: AppAuthSessionsRow) {
    const now = this.now();
    const state = await this.familyState(tx, session, now);
    if (state.expired) {
      await tx.updateSession(session.id, {revokedAt: new Date(now).toISOString()});
      return undefined;
    }
    const user = await tx.user(session.userId);
    if (!user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) return undefined;
    let expiresAt = session.expiresAt;
    if (state.renew) {
      expiresAt = new Date(sessionExpiry(this.policy, state.firstLoginAt, now)).toISOString();
      await tx.updateSession(session.id, {expiresAt,
        firstLoginAt: new Date(state.firstLoginAt).toISOString(), lastRenewedAt: new Date(now).toISOString()});
    } else if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now) return undefined;
    else if (state.expiresAt < Date.parse(expiresAt)) expiresAt = new Date(state.expiresAt).toISOString();
    return {id: user.id, email: user.email, sessionId: session.id, expiresAt};
  }

  private async issue(tx: Store, user: AppAuthUsersRow, transport: SessionTransport, previousCredential = ""): Promise<Tokens | BrowserSession> {
    if (transport === "browser" && /^[A-Za-z0-9_-]{43}$/.test(previousCredential)) {
      const previous = await tx.sessionByToken(hashToken(previousCredential));
      if (previous) {
        if (previous.transport !== "browser") throw new AuthError("invalid_input", 400);
        await tx.revokeSession(previous.id, this.timestamp());
      }
    }
    const accessToken = randomToken();
    const issuedAt = this.now();
    const timestamp = new Date(issuedAt).toISOString();
    const refreshExpiresAt = new Date(sessionExpiry(this.policy, issuedAt, issuedAt)).toISOString();
    const expiresAt = transport === "browser" ? refreshExpiresAt : new Date(issuedAt + accessLifetimeMillis).toISOString();
    const session = await tx.createSession({userId: user.id, tokenHash: hashToken(accessToken), userSessionVersion: user.sessionVersion, expiresAt, transport,
      createdAt: timestamp, firstLoginAt: timestamp, lastRenewedAt: timestamp});
    if (transport === "browser") return {credential: accessToken, cookieMaxAge: cookieMaxAge(this.policy, issuedAt, issuedAt),
      id: user.id, email: user.email, sessionId: session.id, expiresAt};
    const refreshToken = randomToken();
    await tx.createRefresh({sessionId: session.id, tokenHash: hashToken(refreshToken), expiresAt: refreshExpiresAt, createdAt: timestamp});
    return {accessToken, refreshToken, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id};
  }

  private timestamp(): string { return new Date(this.now()).toISOString(); }

  private async rateLimit(action: string, value: string, maximum = 10, windowMillis = 15 * 60_000): Promise<void> {
    const key = {action, keyHash: hashToken(value)};
    for (let attempt = 0; attempt < 4; attempt++) {
      const row = await this.db.rateLimit(key);
      const expiresAt = new Date(this.now() + windowMillis).toISOString();
      if (!row) {
        try { await this.db.createRateLimit({...key, attemptCount: 1, expiresAt}); return; }
        catch (error) { if (!uniqueViolation(error)) throw error; }
        continue;
      }
      const next = nextRateLimit(row, expiresAt, maximum, this.now());
      const updated = await this.db.updateRateLimit(row, next);
      if (updated) return;
    }
    throw new AuthError("rate_limited", 429);
  }
}

function publicUser(user: AppAuthUsersRow): AuthUser {
  return Object.freeze({id:user.id, email:user.email, createdAt:user.createdAt});
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

function inviteSummary(row: AppAuthInvitesRow, now: number): InviteSummary {
  if ((row.redeemedAt === null) !== (row.redeemedBy === null) || row.redeemedAt !== null && row.revokedAt !== null) {
    throw new AuthError("operation_failed", 500);
  }
  const status = row.redeemedAt !== null ? "redeemed" : row.revokedAt !== null ? "revoked"
    : Date.parse(row.expiresAt) <= now ? "expired" : "issued";
  return {id: row.id, email: row.email, status, createdAt: row.createdAt, expiresAt: row.expiresAt};
}
