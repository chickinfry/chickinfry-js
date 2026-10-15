import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import { createStore, encodeTimestampValue, cleanupBudgetMillis, type DatabasePort, type RuntimeStore } from "./store.js";
import type { Store } from "./core/store.js";
import { Flows } from "./core/flows.js";
import { AuthError } from "./core/errors.js";
import { normalizeEmail, validateToken, cleanupCandidates, cleanupPage, type SessionPolicy } from "./core/rules.js";
import { coreVersion } from "./core/version.js";
import type { Tokens, BrowserSession, IdentityProvider, AuthUser, AuthActor, AuthOptions, SessionTransport, InviteSummary } from "./core/types.js";

export { AuthError, normalizeEmail };
export type { SessionPolicy, Tokens, BrowserSession, IdentityProvider, AuthUser, AuthActor, AuthOptions, SessionTransport, InviteSummary };

export interface UserCreationHooks {
  creating?(transaction: DatabasePort, user: AuthUser): Promise<void>;
  committed?(user: AuthUser): Promise<void>;
  inviteManaging?(transaction: DatabasePort, actor: AuthActor, projectId: string): Promise<void>;
}

/** The generated server's runtime context owns cleanup completion and dedicated port shutdown. */
export interface AuthCleanupContext {
  waitUntil(work: Promise<void>): void;
  createPort(signal: AbortSignal): DatabasePort & { close(): Promise<void> };
}

const day = 24 * 60 * 60_000;
const cleanupLimit = 2;

export class Auth {
  private readonly db: RuntimeStore;
  private readonly flows: Flows;
  private readonly policy: Required<SessionPolicy>;
  private readonly coreVersion = coreVersion;

  constructor(
    private readonly port: DatabasePort,
    providers: readonly IdentityProvider[] = [],
    private readonly now = Date.now,
    private readonly hooks: UserCreationHooks = {},
    private readonly options: AuthOptions = {},
    private readonly cleanupContext?: AuthCleanupContext,
  ) {
    this.db = createStore(port);
    this.flows = new Flows(this.db, providers, () => this.now(), options);
    this.policy = this.flows.policy;
  }

  async signup(email: string, password: string, inviteCode?: string, transport?: "native"): Promise<Tokens>;
  async signup(email: string, password: string, inviteCode: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async signup(email: string, password: string, inviteCode = "", transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
    const prepared = await this.flows.prepareSignup(email, password, inviteCode);
    let created: AuthUser | undefined;
    let tokens: Tokens | BrowserSession;
    try {
      tokens = await this.port.transaction(async port => {
        return this.flows.commitSignup(createStore(port), prepared, inviteCode, transport, previousCredential, async user => {
          created = user;
          await this.creating(port, user);
        });
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
    const user = await this.flows.prepareSignin(email, password);
    const tokens = await this.port.transaction(port => this.flows.commitSignin(createStore(port), user, transport, previousCredential));
    this.scheduleCleanup();
    return tokens;
  }

  async signinIdentity(providerID: string, credential: unknown, inviteCode?: string, transport?: "native"): Promise<Tokens>;
  async signinIdentity(providerID: string, credential: unknown, inviteCode: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async signinIdentity(providerID: string, credential: unknown, inviteCode = "", transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
    const prepared = await this.flows.prepareIdentity(providerID, credential, inviteCode);
    let created: AuthUser | undefined;
    let tokens: Tokens | BrowserSession;
    try {
      tokens = await this.port.transaction(async port => {
        return this.flows.commitIdentity(createStore(port), prepared, inviteCode, transport, previousCredential, async user => {
          created = user;
          await this.creating(port, user);
        });
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
      result = await this.manageInvites(accessToken, tx => this.flows.commitInviteIssue(tx.db, tx.actor, id, email), transport);
    } catch (error) {
      if (uniqueViolation(error) && await this.db.invite(id)) {
        throw new AuthError("invite_issue_replayed", 409);
      }
      throw error;
    }
    this.scheduleCleanup(true);
    return result;
  }

  async inviteList(accessToken: string, cursor: string, transport: SessionTransport = "native"): Promise<{items: InviteSummary[]; nextCursor: string}> {
    const after = inviteCursor(cursor);
    const result = await this.manageInvites(accessToken, tx => this.flows.commitInviteList(tx.db, after), transport);
    this.scheduleCleanup(true);
    return result;
  }

  async inviteRevoke(accessToken: string, id: string, transport: SessionTransport = "native"): Promise<{id: string; status: InviteSummary["status"]}> {
    id = inviteID(id);
    const result = await this.manageInvites(accessToken, tx => this.flows.commitInviteRevoke(tx.db, id), transport);
    this.scheduleCleanup(true);
    return result;
  }

  private async manageInvites<T>(accessToken: string,
    work: (context: {db: Store; actor: AuthActor}) => Promise<T>, transport: SessionTransport): Promise<T> {
    if (this.options.signup !== "invite-only") throw new AuthError("not_found", 404);
    validateToken(accessToken);
    const result = await this.port.transaction(async port => {
      const db = createStore(port);
      const actor = await this.flows.commitInviteActor(db, accessToken, transport, async (actor, projectId) => {
        if (!this.hooks.inviteManaging) throw new AuthError("permission_denied", 403);
        if (!projectId || !uuidPattern.test(projectId)) throw new AuthError("service_unavailable", 503);
        try { await this.hooks.inviteManaging(port, actor, projectId); }
        catch (error) {
          if (error instanceof AuthError) throw error;
          throw new AuthError("permission_denied", 403);
        }
      });
      if (!actor) return undefined;
      return {value: await work({db, actor})};
    });
    if (!result) throw new AuthError("invalid_token", 401);
    return result.value;
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
    const result = await this.port.transaction(port => this.flows.commitSession(createStore(port), accessToken, transport));
    if (!result) throw new AuthError("invalid_token", 401);
    return result;
  }

  /** Revalidates an already authenticated native connection; session IDs cannot establish a login. */
  async revalidateSession(sessionId: string, userId: string): Promise<{ id: string; email: string; sessionId: string; expiresAt: string }> {
    const result = await this.port.transaction(port => this.flows.commitRevalidateSession(createStore(port), sessionId, userId));
    if (!result) throw new AuthError("invalid_token", 401);
    return result;
  }

  async logout(accessToken: string, transport: SessionTransport = "native"): Promise<void> {
    if (transport === "native") {
      const session = await this.session(accessToken);
      await this.db.revokeSession(session.sessionId, this.timestamp());
      return;
    }
    // Missing or malformed browser credentials still allow trusted cookie cleanup.
    if (!/^[A-Za-z0-9_-]{43}$/.test(accessToken)) return;
    await this.port.transaction(port => this.flows.commitBrowserLogout(createStore(port), accessToken));
  }

  async refresh(refreshToken: string): Promise<Tokens> {
    validateToken(refreshToken);
    const stored = await this.flows.prepareRefresh(refreshToken);
    const outcome = await this.port.transaction(port => this.flows.commitRefresh(createStore(port), stored));
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
        const db = createStore(port);
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

  private cleanupStart(): string { return randomUUID(); }

  private async cleanup(db: RuntimeStore, signal: AbortSignal): Promise<void> {
    let stage = "session";
    try {
      const cutoff = this.timestamp();
      let refreshBudget = cleanupLimit;
      const start = this.cleanupStart();
      const eligible = cleanupCandidates(this.policy, Date.parse(cutoff));
      const page = cleanupPage(start, false, 0, cleanupLimit);
      const sessions = await db.cleanupSessions(eligible, page.start, page.wrap, page.limit);
      if (sessions.length < cleanupLimit) {
        const page = cleanupPage(start, true, sessions.length, cleanupLimit);
        sessions.push(...await db.cleanupSessions(eligible, page.start, page.wrap, page.limit));
      }
      for (const candidate of sessions) {
        signal.throwIfAborted();
        const deleted = await db.transaction(tx => this.flows.commitCleanupSession(tx, candidate, refreshBudget));
        refreshBudget -= deleted;
      }

      stage = "rate_limit";
      signal.throwIfAborted();
      const limits = await db.expiredRateLimits(cutoff, cleanupLimit);
      for (const candidate of limits) await db.transaction(tx => this.flows.commitCleanupRateLimit(tx, candidate, cutoff));
    } catch {
      cleanupFailure(stage);
    }
    if (!signal.aborted) await this.cleanupInvites(db, signal);
  }

  private async cleanupInvites(db: RuntimeStore, signal: AbortSignal): Promise<void> {
    try {
      signal.throwIfAborted();
      const cutoff = new Date(this.now() - 30 * day).toISOString();
      const candidates = await db.expiredInvites(cutoff, cleanupLimit);
      for (const row of candidates) await db.transaction(tx => this.flows.commitCleanupInvite(tx, row, cutoff));
    } catch {
      cleanupFailure("invite");
    }
  }

  private timestamp(): string { return new Date(this.now()).toISOString(); }
}

function cleanupFailure(stage: string): void {
  try { console.error(`Authentication cleanup failed (${stage}).`); } catch {}
}

function uniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "23505";
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function inviteID(value: string): string {
  if (typeof value !== "string" || !uuidPattern.test(value)) throw new AuthError("invalid_input", 400);
  return value.toLowerCase();
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
