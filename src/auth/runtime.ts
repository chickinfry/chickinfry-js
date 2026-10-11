import { and, createDatabase, type Database, type DatabasePort, type AppAuthUsersRow } from "./private/database.js";
import { hashPassword, verifyPassword, randomToken, hashToken } from "./crypto.js";

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
}

export class Auth {
  private readonly providers = new Map<string, IdentityProvider>();
  private readonly db: Database;

  constructor(
    private readonly port: DatabasePort,
    providers: readonly IdentityProvider[] = [],
    private readonly now = Date.now,
    private readonly hooks: UserCreationHooks = {},
  ) {
    this.db = createDatabase(port);
    for (const provider of providers) {
      if (!/^[a-z][a-z0-9_-]{0,62}$/.test(provider.id) || provider.id === "password" || this.providers.has(provider.id)) {
        throw new Error("Invalid or duplicate identity provider.");
      }
      this.providers.set(provider.id, provider);
    }
  }

  async signup(email: string, password: string): Promise<Tokens> {
    email = normalizeEmail(email);
    validatePassword(password);
    await this.rateLimit("signup", email);
    const passwordHash = await hashPassword(password);
    let created: AuthUser | undefined;
    let tokens: Tokens;
    try {
      tokens = await this.port.transaction(async port => {
        const tx = createDatabase(port);
        const user = await tx.appAuthUsers.insert({ email, passwordHash });
        created = publicUser(user);
        await this.creating(port, created);
        return this.issue(tx, user);
      });
    } catch (error) {
      if (uniqueViolation(error)) throw new AuthError("account_exists", 409);
      throw error;
    }
    await this.created(created!);
    await this.cleanup();
    return tokens;
  }

  async signin(email: string, password: string): Promise<Tokens> {
    email = normalizeEmail(email);
    validatePassword(password);
    await this.rateLimit("signin", email);
    const user = (await this.db.appAuthUsers.findMany({ where: c => c.email.equals(email), limit: 1 }))[0];
    const matched = await verifyPassword(password, user?.passwordHash ?? null);
    if (!matched || !user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
    const tokens = await this.db.transaction(tx => this.issue(tx, user));
    await this.cleanup();
    return tokens;
  }

  async signinIdentity(providerID: string, credential: unknown): Promise<Tokens> {
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
    let created: AuthUser | undefined;
    let tokens: Tokens;
    try {
      tokens = await this.port.transaction(async port => {
        const tx = createDatabase(port);
        const stored = await tx.appAuthIdentities.findById({provider: providerID, subject: identity.subject});
        const user = stored
          ? await tx.appAuthUsers.findById({id: stored.userId})
          : await tx.appAuthUsers.insert({email, passwordHash: null});
        if (!user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
        if (!stored) {
          await tx.appAuthIdentities.insert({provider: providerID, subject: identity.subject, userId: user.id});
          created = publicUser(user);
          await this.creating(port, created);
        }
        return this.issue(tx, user);
      });
    } catch (error) {
      if (uniqueViolation(error)) throw new AuthError("identity_conflict", 409);
      throw error;
    }
    if (created) await this.created(created);
    await this.cleanup();
    return tokens;
  }

  private async created(user: AuthUser): Promise<void> {
    try { await this.hooks.committed?.(user); }
    catch { throw new AuthError("user_created_effect_failed", 500); }
  }

  private async creating(port: DatabasePort, user: AuthUser): Promise<void> {
    try { await this.hooks.creating?.(port, user); }
    catch { throw new AuthError("user_creation_failed", 500); }
  }

  async session(accessToken: string): Promise<{ id: string; email: string; sessionId: string }> {
    validateToken(accessToken);
    const session = (await this.db.appAuthSessions.findMany({where: c => c.tokenHash.equals(hashToken(accessToken)), limit: 1}))[0];
    if (!session || session.revokedAt !== null || Date.parse(session.expiresAt) <= this.now()) {
      throw new AuthError("invalid_token", 401);
    }
    const user = await this.db.appAuthUsers.findById({id: session.userId});
    if (!user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) {
      throw new AuthError("invalid_token", 401);
    }
    return {id: user.id, email: user.email, sessionId: session.id};
  }

  async logout(accessToken: string): Promise<void> {
    const session = await this.session(accessToken);
    await this.db.appAuthSessions.updateIf({id: session.sessionId}, c => c.revokedAt.isNull(), {revokedAt: this.timestamp()});
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    validateToken(refreshToken);
    const stored = (await this.db.appAuthRefreshTokens.findMany({where: c => c.tokenHash.equals(hashToken(refreshToken)), limit: 1}))[0];
    if (!stored) throw new AuthError("invalid_token", 401);
    const outcome = await this.db.transaction(async tx => {
      const session = await tx.appAuthSessions.updateIf({id: stored.sessionId}, c => c.revokedAt.isNull(), {revokedAt: null});
      if (!session) return undefined;
      const current = await tx.appAuthRefreshTokens.findById({id: stored.id});
      const user = await tx.appAuthUsers.findById({id: session.userId});
      if (!current || current.consumedAt !== null || Date.parse(current.expiresAt) <= this.now() ||
          !user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion) {
        await tx.appAuthSessions.update({id: session.id}, {revokedAt: this.timestamp()});
        return undefined;
      }
      const consumed = await tx.appAuthRefreshTokens.updateIf({id: current.id}, c => c.consumedAt.isNull(), {consumedAt: this.timestamp()});
      if (!consumed) {
        await tx.appAuthSessions.update({id: session.id}, {revokedAt: this.timestamp()});
        return undefined;
      }
      const accessToken = randomToken();
      const nextRefresh = randomToken();
      const expiresAt = new Date(this.now() + 15 * 60_000).toISOString();
      await tx.appAuthSessions.update({id: session.id}, {tokenHash: hashToken(accessToken), expiresAt});
      await tx.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(nextRefresh), expiresAt: current.expiresAt});
      return {accessToken, refreshToken: nextRefresh, expiresAt, refreshExpiresAt: current.expiresAt, userId: user.id, sessionId: session.id};
    });
    if (!outcome) throw new AuthError("session_revoked", 401);
    await this.cleanup();
    return outcome;
  }

  private async cleanup(): Promise<void> {
    let stage = "refresh";
    try {
      const cutoff = this.timestamp();
      const refresh = await this.db.appAuthRefreshTokens.findMany({
        where: c => c.expiresAt.lessThanOrEquals(cutoff),
        orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit: 32,
      });
      if (refresh.length) await this.db.transaction(async tx => {
        for (const candidate of refresh) {
          const current = await tx.appAuthRefreshTokens.findById({id: candidate.id});
          if (current && Date.parse(current.expiresAt) <= Date.parse(cutoff)) {
            await tx.appAuthRefreshTokens.delete({id: current.id});
          }
        }
      });

      stage = "session";
      const sessions = await this.db.appAuthSessions.findMany({
        where: c => c.expiresAt.lessThanOrEquals(cutoff),
        orderBy: c => [c.expiresAt.asc(), c.id.asc()], limit: 32,
      });
      for (const candidate of sessions) await this.db.transaction(async tx => {
        // Lock the parent before checking children, in the same order as refresh.
        const locked = await tx.appAuthSessions.updateIf({id: candidate.id},
          c => and(c.expiresAt.equals(candidate.expiresAt), c.expiresAt.lessThanOrEquals(cutoff)),
          {expiresAt: candidate.expiresAt});
        if (!locked) return;
        const children = await tx.appAuthRefreshTokens.findMany({where: c => c.sessionId.equals(locked.id), limit: 1});
        if (!children.length) await tx.appAuthSessions.delete({id: locked.id});
      });

      stage = "rate_limit";
      const limits = await this.db.appAuthRateLimits.findMany({
        where: c => c.expiresAt.lessThanOrEquals(cutoff),
        orderBy: c => [c.expiresAt.asc(), c.action.asc(), c.keyHash.asc()], limit: 32,
      });
      for (const candidate of limits) await this.db.transaction(async tx => {
        const key = {action: candidate.action, keyHash: candidate.keyHash};
        const locked = await tx.appAuthRateLimits.updateIf(key,
          c => and(c.expiresAt.equals(candidate.expiresAt), c.attemptCount.equals(candidate.attemptCount),
            c.expiresAt.lessThanOrEquals(cutoff)),
          {attemptCount: candidate.attemptCount});
        if (locked) await tx.appAuthRateLimits.delete(key);
      });
    } catch {
      // Cleanup must never replace a committed issuance result or expose DB errors.
      try { console.error(`Authentication cleanup failed (${stage}).`); } catch {}
    }
  }

  private async issue(tx: Database, user: AppAuthUsersRow): Promise<Tokens> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const expiresAt = new Date(this.now() + 15 * 60_000).toISOString();
    const refreshExpiresAt = new Date(this.now() + 7 * 24 * 60 * 60_000).toISOString();
    const session = await tx.appAuthSessions.insert({userId: user.id, tokenHash: hashToken(accessToken), userSessionVersion: user.sessionVersion, expiresAt});
    await tx.appAuthRefreshTokens.insert({sessionId: session.id, tokenHash: hashToken(refreshToken), expiresAt: refreshExpiresAt});
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

function publicUser(user: AppAuthUsersRow): AuthUser {
  return Object.freeze({id:user.id, email:user.email, createdAt:user.createdAt});
}

function normalizeEmail(value: string): string {
  if (typeof value !== "string") throw new AuthError("invalid_input", 400);
  const email = value.trim().toLowerCase();
  if (email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new AuthError("invalid_input", 400);
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
