import { Buffer } from "node:buffer";
import { cleanupBudgetMillis } from "../postgres.js";
import { and, or, createDatabase, type Database, type DatabasePort, type AppAuthUsersRow, type AppAuthInvitesRow, type AppAuthSessionsRow } from "./private/database.js";
import { encodeTimestampValue } from "../orm.js";
import { hashPassword, verifyPassword, randomToken, hashToken } from "./crypto.js";
import { sessionPolicy, sessionExpiry, sessionState, cleanupCandidates, cookieMaxAge, accessLifetimeMillis, type SessionPolicy } from "./policy.js";

export type { SessionPolicy } from "./policy.js";

export class AuthError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`Authentication failed (${code}).`);
    this.name = "AuthError";
  }
}

export interface Tokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: string;
  readonly refreshExpiresAt: string;
  readonly userId: string;
  readonly sessionId: string;
}

export type SessionTransport = "native" | "browser";

export interface BrowserSession {
  readonly credential: string;
  readonly cookieMaxAge: number;
  readonly id: string;
  readonly email: string;
  readonly sessionId: string;
  readonly expiresAt: string;
}

export interface IdentityProvider {
  readonly id: string;
  verify(credential: unknown): Promise<{ readonly subject: string; readonly verifiedEmail: string }>;
}

export interface AuthUser {
  readonly id: string;
  readonly email: string;
  readonly createdAt: string;
}

export interface UserCreationHooks {
  creating?(transaction: DatabasePort, user: AuthUser): Promise<void>;
  committed?(user: AuthUser): Promise<void>;
  inviteManaging?(transaction: DatabasePort, actor: AuthActor, projectId: string): Promise<void>;
}

export interface AuthActor {
  readonly id: string;
  readonly user: { readonly id: string; readonly email: string };
}

export interface AuthOptions {
  readonly signup?: "open" | "invite-only";
  readonly projectId?: string;
  readonly session?: SessionPolicy;
}

/** The generated server's runtime context owns cleanup completion and dedicated port shutdown. */
export interface AuthCleanupContext {
  waitUntil(work: Promise<void>): void;
  createPort(signal: AbortSignal): DatabasePort & { close(): Promise<void> };
}

export interface InviteSummary {
  readonly id: string;
  readonly email: string;
  readonly status: "issued" | "redeemed" | "revoked" | "expired";
  readonly createdAt: string;
  readonly expiresAt: string;
}

const day = 24 * 60 * 60_000;
const cleanupLimit = 2;

export class Auth {
  private readonly providers = new Map<string, IdentityProvider>();
  private readonly db: Database;
  private readonly policy: Required<SessionPolicy>;

  constructor(
    private readonly port: DatabasePort,
    providers: readonly IdentityProvider[] = [],
    private readonly now = Date.now,
    private readonly hooks: UserCreationHooks = {},
    private readonly options: AuthOptions = {},
    private readonly cleanupContext?: AuthCleanupContext,
  ) {
    if (options.signup !== undefined && options.signup !== "open" && options.signup !== "invite-only") {
      throw new Error("Invalid signup policy.");
    }
    this.db = createDatabase(port);
    this.policy = sessionPolicy(options.session);
    for (const provider of providers) {
      if (!/^[a-z][a-z0-9_-]{0,62}$/.test(provider.id) || provider.id === "password" || this.providers.has(provider.id)) {
        throw new Error("Invalid or duplicate identity provider.");
      }
      this.providers.set(provider.id, provider);
    }
  }

  async signup(email: string, password: string, inviteCode?: string, transport?: "native"): Promise<Tokens>;
  async signup(email: string, password: string, inviteCode: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async signup(email: string, password: string, inviteCode = "", transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
    email = normalizeEmail(email);
    validatePassword(password);
    if (typeof inviteCode !== "string") throw new AuthError("invalid_input", 400);
    await this.rateLimit("signup", email);
    if (this.options.signup === "invite-only") await this.checkInvite(this.db, email, inviteCode);
    const passwordHash = await hashPassword(password);
    let created: AuthUser | undefined;
    let tokens: Tokens | BrowserSession;
    try {
      tokens = await this.port.transaction(async port => {
        const tx = createDatabase(port);
        const invite = await this.lockInvite(tx, email, inviteCode);
        const user = await tx.appAuthUsers.insert({ email, passwordHash });
        if (invite) await tx.appAuthInvites.update({id: invite.id}, {redeemedAt: this.timestamp(), redeemedBy: user.id});
        created = publicUser(user);
        await this.creating(port, created);
        return this.issue(tx, user, transport, previousCredential);
      });
    } catch (error) {
      if (uniqueViolation(error)) throw new AuthError("account_exists", 409);
      throw error;
    }
    await this.created(created!);
    this.scheduleCleanup();
    return tokens;
  }

  async signin(email: string, password: string, transport?: "native"): Promise<Tokens>;
  async signin(email: string, password: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async signin(email: string, password: string, transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
    email = normalizeEmail(email);
    validatePassword(password);
    await this.rateLimit("signin", email);
    const user = (await this.db.appAuthUsers.findMany({ where: c => c.email.equals(email), limit: 1 }))[0];
    const matched = await verifyPassword(password, user?.passwordHash ?? null);
    if (!matched || !user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
    const tokens = await this.db.transaction(tx => this.issue(tx, user, transport, previousCredential));
    this.scheduleCleanup();
    return tokens;
  }

  async signinIdentity(providerID: string, credential: unknown, inviteCode?: string, transport?: "native"): Promise<Tokens>;
  async signinIdentity(providerID: string, credential: unknown, inviteCode: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async signinIdentity(providerID: string, credential: unknown, inviteCode = "", transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
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
        !await this.db.appAuthIdentities.findById({provider: providerID, subject: identity.subject})) {
      await this.rateLimit("signup", email);
      await this.checkInvite(this.db, email, inviteCode);
    }
    let created: AuthUser | undefined;
    let tokens: Tokens | BrowserSession;
    try {
      tokens = await this.port.transaction(async port => {
        const tx = createDatabase(port);
        const stored = await tx.appAuthIdentities.findById({provider: providerID, subject: identity.subject});
        const invite = stored ? undefined : await this.lockInvite(tx, email, inviteCode);
        const user = stored
          ? await tx.appAuthUsers.findById({id: stored.userId})
          : await tx.appAuthUsers.insert({email, passwordHash: null});
        if (!user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
        if (!stored) {
          if (invite) await tx.appAuthInvites.update({id: invite.id}, {redeemedAt: this.timestamp(), redeemedBy: user.id});
          await tx.appAuthIdentities.insert({provider: providerID, subject: identity.subject, userId: user.id});
          created = publicUser(user);
          await this.creating(port, created);
        }
        return this.issue(tx, user, transport, previousCredential);
      });
    } catch (error) {
      if (uniqueViolation(error)) throw new AuthError("identity_conflict", 409);
      throw error;
    }
    if (created) await this.created(created);
    this.scheduleCleanup();
    return tokens;
  }

  async inviteIssue(accessToken: string, id: string, email: string, transport: SessionTransport = "native"): Promise<InviteSummary & {code: string}> {
    id = inviteID(id);
    email = normalizeEmail(email);
    let result: InviteSummary & {code: string};
    try {
      result = await this.manageInvites(accessToken, async tx => {
        if (await tx.db.appAuthInvites.findById({id})) throw new AuthError("invite_issue_replayed", 409);
        const code = randomToken();
        const createdAt = this.timestamp();
        const row = await tx.db.appAuthInvites.insert({id, email, codeHash: hashToken(code), issuedBy: tx.actor.user.id,
          createdAt, expiresAt: new Date(Date.parse(createdAt) + 7 * day).toISOString()});
        return {...inviteSummary(row, this.now()), code};
      }, transport);
    } catch (error) {
      if (uniqueViolation(error) && await this.db.appAuthInvites.findById({id})) {
        throw new AuthError("invite_issue_replayed", 409);
      }
      throw error;
    }
    this.scheduleCleanup(true);
    return result;
  }

  async inviteList(accessToken: string, cursor: string, transport: SessionTransport = "native"): Promise<{items: InviteSummary[]; nextCursor: string}> {
    const after = inviteCursor(cursor);
    const result = await this.manageInvites(accessToken, async tx => {
      const rows = await tx.db.appAuthInvites.findMany({
        where: after ? c => or(c.createdAt.greaterThan(after[0]),
          and(c.createdAt.equals(after[0]), c.id.greaterThan(after[1]))) : undefined,
        orderBy: c => [c.createdAt.asc(), c.id.asc()], limit: 51,
      });
      const page = rows.slice(0, 50);
      const last = page.at(-1);
      return {items: page.map(row => inviteSummary(row, this.now())), nextCursor: rows.length > 50 && last
        ? Buffer.from(JSON.stringify([last.createdAt, last.id])).toString("base64url") : ""};
    }, transport);
    this.scheduleCleanup(true);
    return result;
  }

  async inviteRevoke(accessToken: string, id: string, transport: SessionTransport = "native"): Promise<{id: string; status: InviteSummary["status"]}> {
    id = inviteID(id);
    const result = await this.manageInvites(accessToken, async tx => {
      const candidate = await tx.db.appAuthInvites.findById({id});
      if (!candidate) throw new AuthError("not_found", 404);
      const row = await tx.db.appAuthInvites.updateIf({id}, c => c.expiresAt.equals(candidate.expiresAt),
        {expiresAt: candidate.expiresAt});
      if (!row) throw new AuthError("not_found", 404);
      const summary = inviteSummary(row, this.now());
      if (summary.status === "redeemed") throw new AuthError("invite_already_redeemed", 409);
      if (summary.status === "issued") await tx.db.appAuthInvites.update({id}, {revokedAt: this.timestamp()});
      return {id, status: summary.status === "issued" ? "revoked" as const : summary.status};
    }, transport);
    this.scheduleCleanup(true);
    return result;
  }

  private async manageInvites<T>(accessToken: string,
    work: (context: {db: Database; actor: AuthActor}) => Promise<T>, transport: SessionTransport): Promise<T> {
    if (this.options.signup !== "invite-only") throw new AuthError("not_found", 404);
    validateToken(accessToken);
    const result = await this.port.transaction(async port => {
      const db = createDatabase(port);
      const candidate = (await db.appAuthSessions.findMany({where: c => c.tokenHash.equals(hashToken(accessToken)), limit: 1}))[0];
      if (candidate && candidate.transport !== transport) {
        throw new AuthError(transport === "browser" ? "invalid_input" : "invalid_token", transport === "browser" ? 400 : 401);
      }
      const session = await this.lockSession(db, candidate, hashToken(accessToken));
      if (!session) return undefined;
      const authenticated = await this.validateSession(db, session);
      if (!authenticated) return undefined;
      const user = await db.appAuthUsers.updateIf({id: authenticated.id}, c => and(c.disabledAt.isNull(),
        c.sessionVersion.equals(session.userSessionVersion)), {sessionVersion: session.userSessionVersion});
      if (!user) return undefined;
      if (!this.hooks.inviteManaging) throw new AuthError("permission_denied", 403);
      const projectId = this.options.projectId;
      if (!projectId || !uuidPattern.test(projectId)) throw new AuthError("service_unavailable", 503);
      const actor = Object.freeze({id: session.id, user: Object.freeze({id: user.id, email: user.email})});
      try { await this.hooks.inviteManaging(port, actor, projectId); }
      catch (error) {
        if (error instanceof AuthError) throw error;
        throw new AuthError("permission_denied", 403);
      }
      return {value: await work({db, actor})};
    });
    if (!result) throw new AuthError("invalid_token", 401);
    return result.value;
  }

  private async checkInvite(db: Database, email: string, code: string): Promise<AppAuthInvitesRow> {
    if (!code) throw new AuthError("invite_required", 403);
    if (!/^[A-Za-z0-9_-]{43}$/.test(code) || Buffer.from(code, "base64url").toString("base64url") !== code) {
      throw new AuthError("invite_invalid", 403);
    }
    const row = (await db.appAuthInvites.findMany({where: c => c.codeHash.equals(hashToken(code)), limit: 1}))[0];
    if (!row || row.email !== email || row.redeemedAt !== null || row.redeemedBy !== null ||
        row.revokedAt !== null || Date.parse(row.expiresAt) <= this.now()) throw new AuthError("invite_invalid", 403);
    return row;
  }

  private async lockInvite(db: Database, email: string, code: string): Promise<AppAuthInvitesRow | undefined> {
    if (this.options.signup !== "invite-only") return undefined;
    const candidate = await this.checkInvite(db, email, code);
    const row = await db.appAuthInvites.updateIf({id: candidate.id}, c => and(c.codeHash.equals(hashToken(code)),
      c.email.equals(email), c.redeemedAt.isNull(), c.redeemedBy.isNull(), c.revokedAt.isNull(),
      c.expiresAt.equals(candidate.expiresAt), c.expiresAt.greaterThan(this.timestamp())), {expiresAt: candidate.expiresAt});
    if (!row || Date.parse(row.expiresAt) <= this.now()) throw new AuthError("invite_invalid", 403);
    return row;
  }

  private async created(user: AuthUser): Promise<void> {
    try { await this.hooks.committed?.(user); }
    catch { throw new AuthError("user_created_effect_failed", 500); }
  }

  private async creating(port: DatabasePort, user: AuthUser): Promise<void> {
    try { await this.hooks.creating?.(port, user); }
    catch { throw new AuthError("user_creation_failed", 500); }
  }

  async session(accessToken: string, transport: SessionTransport = "native"): Promise<{ id: string; email: string; sessionId: string; expiresAt: string }> {
    validateToken(accessToken);
    const result = await this.db.transaction(async tx => {
      const candidate = (await tx.appAuthSessions.findMany({where: c => c.tokenHash.equals(hashToken(accessToken)), limit: 1}))[0];
      if (candidate && candidate.transport !== transport) throw new AuthError(transport === "browser" ? "invalid_input" : "invalid_token", transport === "browser" ? 400 : 401);
      const session = await this.lockSession(tx, candidate, hashToken(accessToken));
      return session && this.validateSession(tx, session);
    });
    if (!result) throw new AuthError("invalid_token", 401);
    return result;
  }

  /** Revalidates an already authenticated native connection; session IDs cannot establish a login. */
  async revalidateSession(sessionId: string, userId: string): Promise<{ id: string; email: string; sessionId: string; expiresAt: string }> {
    const result = await this.db.transaction(async tx => {
      const candidate = await tx.appAuthSessions.findById({id: sessionId});
      if (candidate?.userId !== userId || candidate.transport !== "native") return undefined;
      const session = await this.lockSession(tx, candidate);
      return session && this.validateSession(tx, session);
    });
    if (!result) throw new AuthError("invalid_token", 401);
    return result;
  }

  private lockSession(tx: Database, candidate: AppAuthSessionsRow | undefined, tokenHash?: string): Promise<AppAuthSessionsRow | undefined> {
    if (!candidate) return Promise.resolve(undefined);
    return tx.appAuthSessions.updateIf({id: candidate.id}, c => tokenHash
      ? and(c.revokedAt.isNull(), c.tokenHash.equals(tokenHash)) : c.revokedAt.isNull(), {revokedAt: null});
  }

  private async familyState(tx: Database, session: AppAuthSessionsRow, now: number) {
    const latest = session.transport === "native" ? (await tx.appAuthRefreshTokens.findMany({
      where: c => and(c.sessionId.equals(session.id), c.consumedAt.isNull()), orderBy: c => [c.createdAt.desc(), c.id.desc()], limit: 1,
    }))[0] : undefined;
    return sessionState(session, latest, this.policy, now);
  }

  private async validateSession(tx: Database, session: AppAuthSessionsRow) {
    const now = this.now();
    const state = await this.familyState(tx, session, now);
    if (state.expired) {
      await tx.appAuthSessions.update({id: session.id}, {revokedAt: new Date(now).toISOString()});
      return undefined;
    }
    const user = await tx.appAuthUsers.findById({id: session.userId});
    if (!user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) return undefined;
    let expiresAt = session.expiresAt;
    if (state.renew) {
      expiresAt = new Date(sessionExpiry(this.policy, state.firstLoginAt, now)).toISOString();
      await tx.appAuthSessions.update({id: session.id}, {expiresAt,
        firstLoginAt: new Date(state.firstLoginAt).toISOString(), lastRenewedAt: new Date(now).toISOString()});
    } else if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now) return undefined;
    return {id: user.id, email: user.email, sessionId: session.id, expiresAt};
  }

  async logout(accessToken: string, transport: SessionTransport = "native"): Promise<void> {
    if (transport === "native") {
      const session = await this.session(accessToken);
      await this.db.appAuthSessions.updateIf({id: session.sessionId}, c => c.revokedAt.isNull(), {revokedAt: this.timestamp()});
      return;
    }
    // Missing or malformed browser credentials still allow trusted cookie cleanup.
    if (!/^[A-Za-z0-9_-]{43}$/.test(accessToken)) return;
    await this.db.transaction(async tx => {
      const session = (await tx.appAuthSessions.findMany({where: c => c.tokenHash.equals(hashToken(accessToken)), limit: 1}))[0];
      if (!session) return;
      if (session.transport !== "browser") throw new AuthError("invalid_input", 400);
      await tx.appAuthSessions.updateIf({id: session.id}, c => and(c.tokenHash.equals(hashToken(accessToken)),
        c.transport.equals("browser"), c.revokedAt.isNull()), {revokedAt: this.timestamp()});
    });
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    validateToken(refreshToken);
    const stored = (await this.db.appAuthRefreshTokens.findMany({where: c => c.tokenHash.equals(hashToken(refreshToken)), limit: 1}))[0];
    if (!stored) throw new AuthError("invalid_token", 401);
    const outcome = await this.db.transaction(async tx => {
      const session = await tx.appAuthSessions.updateIf({id: stored.sessionId}, c => c.revokedAt.isNull(), {revokedAt: null});
      if (!session || session.transport !== "native") return undefined;
      const current = await tx.appAuthRefreshTokens.findById({id: stored.id});
      const issuedAt = this.now();
      const state = await this.familyState(tx, session, issuedAt);
      const user = await tx.appAuthUsers.findById({id: session.userId});
      if (!current || current.consumedAt !== null || state.expired || Date.parse(current.expiresAt) <= issuedAt ||
          !user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) {
        await tx.appAuthSessions.update({id: session.id}, {revokedAt: this.timestamp()});
        return undefined;
      }
      const timestamp = new Date(issuedAt).toISOString();
      const consumed = await tx.appAuthRefreshTokens.updateIf({id: current.id}, c => c.consumedAt.isNull(), {consumedAt: timestamp});
      if (!consumed) {
        await tx.appAuthSessions.update({id: session.id}, {revokedAt: this.timestamp()});
        return undefined;
      }
      const accessToken = randomToken();
      const nextRefresh = randomToken();
      const expiresAt = new Date(issuedAt + accessLifetimeMillis).toISOString();
      const refreshExpiresAt = new Date(sessionExpiry(this.policy, state.firstLoginAt, issuedAt)).toISOString();
      await tx.appAuthSessions.update({id: session.id}, {tokenHash: hashToken(accessToken), expiresAt,
        firstLoginAt: new Date(state.firstLoginAt).toISOString(), lastRenewedAt: timestamp});
      await tx.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(nextRefresh), expiresAt: refreshExpiresAt, createdAt: timestamp});
      return {accessToken, refreshToken: nextRefresh, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id};
    });
    if (!outcome) throw new AuthError("session_revoked", 401);
    this.scheduleCleanup();
    return outcome;
  }

  private scheduleCleanup(invitesOnly = false): void {
    const context = this.cleanupContext;
    // Without a runtime owner, only physical cleanup is skipped; expiry checks remain each auth path's responsibility.
    if (!context) return;
    let accepted = false;
    const work = Promise.resolve().then(async () => {
      if (!accepted) return;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), cleanupBudgetMillis);
      let port: ReturnType<AuthCleanupContext["createPort"]> | undefined;
      try {
        port = context.createPort(controller.signal);
        const db = createDatabase(port);
        if (invitesOnly) await this.cleanupInvites(db, controller.signal);
        else await this.cleanup(db, controller.signal);
      } finally {
        try { await port?.close(); }
        finally { clearTimeout(timeout); }
      }
    }).catch(() => cleanupFailure("port"));
    try {
      context.waitUntil(work);
      accepted = true;
    } catch { cleanupFailure("schedule"); }
  }

  private async cleanup(db: Database, signal: AbortSignal): Promise<void> {
    let stage = "session";
    try {
      const cutoff = this.timestamp();
      let refreshBudget = cleanupLimit;
      const sessions = await db.appAuthSessions.findMany({
        where: cleanupCandidates(this.policy, Date.parse(cutoff)),
        orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit: cleanupLimit,
      });
      for (const candidate of sessions) {
        signal.throwIfAborted();
        const deleted = await db.transaction(async tx => {
          // Candidate timestamps never authorize deletion; recheck the locked family under Q1.
          const locked = await tx.appAuthSessions.updateIf({id: candidate.id},
            c => c.expiresAt.equals(candidate.expiresAt),
            {expiresAt: candidate.expiresAt});
          if (!locked || !(await this.familyState(tx, locked, this.now())).expired) return 0;
          const children = await tx.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(locked.id),
            orderBy: c => [c.createdAt.asc(), c.id.asc()], limit: refreshBudget + 1});
          const deleting = children.slice(0, refreshBudget);
          for (const child of deleting) await tx.appAuthRefreshTokens.delete({id: child.id});
          if (children.length === deleting.length) await tx.appAuthSessions.delete({id: locked.id});
          return deleting.length;
        });
        refreshBudget -= deleted;
      }

      stage = "rate_limit";
      signal.throwIfAborted();
      const limits = await db.appAuthRateLimits.findMany({
        where: c => c.expiresAt.lessThanOrEquals(cutoff),
        orderBy: c => [c.expiresAt.asc(), c.action.asc(), c.keyHash.asc()], limit: cleanupLimit,
      });
      for (const candidate of limits) await db.transaction(async tx => {
        const key = {action: candidate.action, keyHash: candidate.keyHash};
        const locked = await tx.appAuthRateLimits.updateIf(key,
          c => and(c.expiresAt.equals(candidate.expiresAt), c.attemptCount.equals(candidate.attemptCount),
            c.expiresAt.lessThanOrEquals(cutoff)),
          {attemptCount: candidate.attemptCount});
        if (locked) await tx.appAuthRateLimits.delete(key);
      });
    } catch {
      cleanupFailure(stage);
    }
    if (!signal.aborted) await this.cleanupInvites(db, signal);
  }

  private async cleanupInvites(db: Database, signal: AbortSignal): Promise<void> {
    try {
      signal.throwIfAborted();
      const cutoff = new Date(this.now() - 30 * day).toISOString();
      const candidates = await db.appAuthInvites.findMany({where: c => c.expiresAt.lessThanOrEquals(cutoff),
        orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit: cleanupLimit});
      for (const row of candidates) await db.transaction(async tx => {
        const locked = await tx.appAuthInvites.updateIf({id: row.id},
          c => and(c.expiresAt.equals(row.expiresAt), c.expiresAt.lessThanOrEquals(cutoff)), {expiresAt: row.expiresAt});
        if (locked) await tx.appAuthInvites.delete({id: row.id});
      });
    } catch {
      cleanupFailure("invite");
    }
  }

  private async issue(tx: Database, user: AppAuthUsersRow, transport: SessionTransport, previousCredential = ""): Promise<Tokens | BrowserSession> {
    if (transport === "browser" && /^[A-Za-z0-9_-]{43}$/.test(previousCredential)) {
      const previous = (await tx.appAuthSessions.findMany({where: c => c.tokenHash.equals(hashToken(previousCredential)), limit: 1}))[0];
      if (previous) {
        if (previous.transport !== "browser") throw new AuthError("invalid_input", 400);
        await tx.appAuthSessions.updateIf({id: previous.id}, c => c.revokedAt.isNull(), {revokedAt: this.timestamp()});
      }
    }
    const accessToken = randomToken();
    const issuedAt = this.now();
    const timestamp = new Date(issuedAt).toISOString();
    const refreshExpiresAt = new Date(sessionExpiry(this.policy, issuedAt, issuedAt)).toISOString();
    const expiresAt = transport === "browser" ? refreshExpiresAt : new Date(issuedAt + accessLifetimeMillis).toISOString();
    const session = await tx.appAuthSessions.insert({userId: user.id, tokenHash: hashToken(accessToken), userSessionVersion: user.sessionVersion, expiresAt, transport,
      createdAt: timestamp, firstLoginAt: timestamp, lastRenewedAt: timestamp});
    if (transport === "browser") return {credential: accessToken, cookieMaxAge: cookieMaxAge(this.policy, issuedAt, issuedAt),
      id: user.id, email: user.email, sessionId: session.id, expiresAt};
    const refreshToken = randomToken();
    await tx.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(refreshToken), expiresAt: refreshExpiresAt, createdAt: timestamp});
    return {accessToken, refreshToken, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id};
  }

  private timestamp(): string { return new Date(this.now()).toISOString(); }

  private async rateLimit(action: string, value: string, maximum = 10, windowMillis = 15 * 60_000): Promise<void> {
    const key = {action, keyHash: hashToken(value)};
    for (let attempt = 0; attempt < 4; attempt++) {
      const row = await this.db.appAuthRateLimits.findById(key);
      const expiresAt = new Date(this.now() + windowMillis).toISOString();
      if (!row) {
        try { await this.db.appAuthRateLimits.insert({...key, attemptCount: 1, expiresAt}); return; }
        catch (error) { if (!uniqueViolation(error)) throw error; }
        continue;
      }
      const expired = Date.parse(row.expiresAt) <= this.now();
      if (!expired && row.attemptCount >= maximum) throw new AuthError("rate_limited", 429);
      const updated = await this.db.appAuthRateLimits.updateIf(key,
        c => and(c.attemptCount.equals(row.attemptCount), c.expiresAt.equals(row.expiresAt)),
        {attemptCount: expired ? 1 : row.attemptCount + 1, expiresAt: expired ? expiresAt : row.expiresAt});
      if (updated) return;
    }
    throw new AuthError("rate_limited", 429);
  }
}

function cleanupFailure(stage: string): void {
  try { console.error(`Authentication cleanup failed (${stage}).`); } catch {}
}

function publicUser(user: AppAuthUsersRow): AuthUser {
  return Object.freeze({id:user.id, email:user.email, createdAt:user.createdAt});
}

export function normalizeEmail(value: string): string {
  if (typeof value !== "string") throw new AuthError("invalid_input", 400);
  const email = value.trim().toLowerCase();
  if (email.includes("\0") || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new AuthError("invalid_input", 400);
  return email;
}

function validatePassword(value: string): void {
  if (typeof value !== "string" || [...value].length < 15 || new TextEncoder().encode(value).byteLength > 1024) {
    throw new AuthError("invalid_input", 400);
  }
}

function validateToken(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new AuthError("invalid_token", 401);
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function inviteID(value: string): string {
  if (typeof value !== "string" || !uuidPattern.test(value)) throw new AuthError("invalid_input", 400);
  return value.toLowerCase();
}

function inviteSummary(row: AppAuthInvitesRow, now: number): InviteSummary {
  if ((row.redeemedAt === null) !== (row.redeemedBy === null) || row.redeemedAt !== null && row.revokedAt !== null) {
    throw new AuthError("operation_failed", 500);
  }
  const status = row.redeemedAt !== null ? "redeemed" : row.revokedAt !== null ? "revoked"
    : Date.parse(row.expiresAt) <= now ? "expired" : "issued";
  return {id: row.id, email: row.email, status, createdAt: row.createdAt, expiresAt: row.expiresAt};
}

function inviteCursor(value: string): [string, string] | undefined {
  if (typeof value !== "string") throw new AuthError("invalid_input", 400);
  if (value === "") return undefined;
  try {
    if (value.length > 512 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error();
    const bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) throw new Error();
    const parsed: unknown = JSON.parse(bytes.toString("utf8"));
    if (!Array.isArray(parsed) || parsed.length !== 2 || typeof parsed[0] !== "string" ||
        typeof parsed[1] !== "string" || !uuidPattern.test(parsed[1]) ||
        encodeTimestampValue(parsed[0]) !== parsed[0]) throw new Error();
    return [parsed[0], parsed[1].toLowerCase()];
  } catch { throw new AuthError("invalid_input", 400); }
}
