import { Buffer } from "node:buffer";
import { randomUUID } from "node:crypto";
import { createStore, encodeTimestampValue, cleanupBudgetMillis, type DatabasePort, type RuntimeStore } from "./store.js";
import type { Store } from "./core/store.js";
import { Flows } from "./core/flows.js";
import { AuthError } from "./core/errors.js";
import { normalizeEmail, validateToken, cleanupCandidates, cleanupPage, emailPolicy, signupPolicy, emailLinkBase, renderAuthMail, type SessionPolicy } from "./core/rules.js";
import { coreVersion } from "./core/version.js";
import type { Tokens, BrowserSession, IdentityProvider, AuthUser, AuthActor, AuthOptions, SessionTransport, InviteSummary,
  AuthMailer, AuthMail, ActionTokenKind, Accepted, SignupAttempt, SignupHookResult } from "./core/types.js";

export { AuthError, normalizeEmail };
export type { SessionPolicy, Tokens, BrowserSession, IdentityProvider, AuthUser, AuthActor, AuthOptions, SessionTransport, InviteSummary,
  AuthMailer, AuthMail, ActionTokenKind, Accepted, SignupAttempt, SignupHookResult };

export interface UserCreationHooks {
  checkSignup?(input: Readonly<{email: string}>): SignupHookResult | Promise<SignupHookResult>;
  creating?(transaction: DatabasePort, user: AuthUser): Promise<SignupHookResult>;
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
const signupHookBudgetMillis = 5_000;

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
    if (options.email !== undefined && (options.email === null || typeof options.email !== "object" ||
      (options.email.verification !== "required" && options.email.verification !== "off"))) {
      throw new Error("auth.email.verification must be required or off.");
    }
    if (options.email?.verification === "required" && !options.mailer) throw new Error("Verified email requires an AuthMailer.");
    if (options.mailer) {
      if (typeof options.mailer.send !== "function") throw new Error("AuthMailer must implement send.");
      emailLinkBase(options.emailLinkBase);
    }
    if (options.projectName !== undefined && (typeof options.projectName !== "string" ||
      !options.projectName.trim() || options.projectName.length > 200 || /[\r\n\0]/.test(options.projectName))) {
      throw new Error("Auth project name must be a nonempty single line.");
    }
    this.db = createStore(port);
    this.flows = new Flows(this.db, providers, () => this.now(), options);
    this.policy = this.flows.policy;
  }

  async signup(email: string, password: string, inviteCode?: string, transport?: "native", previousCredential?: string, callerIp?: string): Promise<Tokens | SignupAttempt>;
  async signup(email: string, password: string, inviteCode: string, transport: "browser", previousCredential?: string, callerIp?: string): Promise<BrowserSession | SignupAttempt>;
  async signup(email: string, password: string, inviteCode = "", transport: SessionTransport = "native", previousCredential = "", callerIp?: string): Promise<Tokens | BrowserSession | SignupAttempt> {
    const started = performance.now();
    if (this.options.email?.verification === "required") {
      email = normalizeEmail(email);
      await this.checkSignup(email);
    }
    const prepared = await this.flows.prepareSignup(email, password, inviteCode, callerIp);
    if (this.options.email?.verification === "required") {
      const result = await this.signupWithEmail(prepared);
      await this.acceptedAfter(started);
      return result;
    }
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

  private async signupWithEmail(prepared: Awaited<ReturnType<Flows["prepareSignup"]>>): Promise<SignupAttempt> {
    const attempt = randomUUID();
    const mail = await this.port.transaction(port => this.flows.commitEmailSignup(createStore(port), {...prepared, attempt}));
    this.sendMail(mail);
    this.scheduleCleanup();
    return {accepted: true, attempt};
  }

  async sendVerificationEmail(target: string | {readonly attempt: string}, callerIp?: string): Promise<Accepted> {
    if (typeof target === "string") return this.requestMail(target, "email_verification", callerIp);
    const started = performance.now();
    if (!this.options.mailer) throw new AuthError("not_found", 404);
    const attempt = target?.attempt;
    const row = this.options.email?.verification === "required" && typeof attempt === "string" && uuidPattern.test(attempt) &&
      Object.keys(target).every(key => key === "attempt") ? await this.db.signup(attempt) : undefined;
    if (!row) return this.acceptedAfter(started);
    return this.requestMail(row.email, "email_verification", callerIp, row.id, started);
  }

  async requestPasswordReset(email: string, callerIp?: string): Promise<Accepted> {
    return this.requestMail(email, "password_reset", callerIp);
  }

  private async requestMail(email: string, kind: ActionTokenKind, callerIp?: string, attempt?: string, started = performance.now()): Promise<Accepted> {
    if (!this.options.mailer) throw new AuthError("not_found", 404);
    const prepared = await this.flows.prepareMail(email, kind, callerIp, attempt);
    const mail = await this.port.transaction(port => this.flows.commitMail(createStore(port), prepared, kind));
    this.sendMail(mail);
    this.scheduleCleanup();
    return this.acceptedAfter(started);
  }

  async verifyEmail(target: string | {readonly attempt: string}, code: string, transport?: "native", previousCredential?: string): Promise<Tokens>;
  async verifyEmail(target: string | {readonly attempt: string}, code: string, transport: "browser", previousCredential?: string): Promise<BrowserSession>;
  async verifyEmail(target: string | {readonly attempt: string}, code: string, transport: SessionTransport = "native", previousCredential = ""): Promise<Tokens | BrowserSession> {
    if (!this.options.mailer) throw new AuthError("not_found", 404);
    let email = "";
    const attempt = typeof target === "object" && target !== null ? target.attempt : undefined;
    if (typeof target === "string") {
      try { email = normalizeEmail(target); }
      catch { throw new AuthError(emailPolicy.invalidCode, 400); }
    } else if (typeof attempt !== "string" || !uuidPattern.test(attempt) || Object.keys(target).some(key => key !== "attempt")) {
      throw new AuthError(emailPolicy.invalidCode, 400);
    }
    if (typeof code !== "string" || !/^[0-9]{6}$/.test(code)) throw new AuthError(emailPolicy.invalidCode, 400);
    const signup = attempt !== undefined && this.options.email?.verification === "required" ? await this.db.signup(attempt) : undefined;
    if (attempt !== undefined && !signup) throw new AuthError(emailPolicy.invalidCode, 400);
    let created: AuthUser | undefined;
    let result;
    try {
      result = await this.port.transaction(async port => {
        const tx = createStore(port);
        if (!signup) return this.flows.commitVerifyEmail(tx, email, code, transport, previousCredential);
        return this.flows.commitSignupVerification(tx, signup, code, transport, previousCredential, async user => {
          await this.creating(port, user);
          created = user;
        });
      });
    } catch (error) {
      if (uniqueViolation(error)) throw new AuthError(emailPolicy.invalidCode, 400);
      throw error;
    }
    // An invalid code must commit its failed attempt before returning an error.
    if (!result) throw new AuthError(emailPolicy.invalidCode, 400);
    if (created) await this.created(created);
    this.scheduleCleanup();
    return result;
  }

  private async acceptedAfter(started: number): Promise<Accepted> {
    const remaining = 1000 - (performance.now() - started);
    if (remaining > 0) await new Promise(resolve => setTimeout(resolve, Math.ceil(remaining)));
    return emailPolicy.accepted;
  }

  private async checkSignup(email: string): Promise<void> {
    const hook = this.hooks.checkSignup;
    if (!hook) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let message;
    const started = performance.now();
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => hook.call(this.hooks, Object.freeze({email}))),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error()), signupHookBudgetMillis); }),
      ]);
      if (performance.now() - started >= signupHookBudgetMillis) throw new Error();
      message = signupRejection(result);
    } catch {
      try { console.error(JSON.stringify({cause: "signup_check_failed"})); } catch {}
      throw new AuthError(signupPolicy.checkFailedCode, 500);
    }
    finally { clearTimeout(timer); }
    if (message !== undefined) throw publicRejection(signupPolicy.rejectedCode, 400, message);
  }

  async resetPassword(token: string, password: string): Promise<Accepted> {
    if (!this.options.mailer) throw new AuthError("not_found", 404);
    const prepared = await this.flows.preparePasswordReset(token, password);
    await this.port.transaction(port => this.flows.commitPasswordReset(createStore(port), prepared));
    this.scheduleCleanup();
    return emailPolicy.accepted;
  }

  private sendMail(pending: {to: string; kind: AuthMail["kind"]; token: string; signup?: boolean} | undefined): void {
    if (!pending) return;
    const mailer = this.options.mailer!;
    const work = Promise.resolve().then(() => mailer.send({to: pending.to, kind: pending.kind,
      ...renderAuthMail(pending.kind, this.options.projectName ?? "Application", emailLinkBase(this.options.emailLinkBase), pending.token, pending.signup),
    })).catch(() => {
      try { console.error(JSON.stringify({cause: "auth_mail_failed", kind: pending.kind})); } catch {}
    });
    try { this.cleanupContext?.waitUntil(work); } catch {}
  }

  async signin(email: string, password: string, transport?: "native", previousCredential?: string, callerIp?: string): Promise<Tokens>;
  async signin(email: string, password: string, transport: "browser", previousCredential?: string, callerIp?: string): Promise<BrowserSession>;
  async signin(email: string, password: string, transport: SessionTransport = "native", previousCredential = "", callerIp?: string): Promise<Tokens | BrowserSession> {
    const started = performance.now();
    const prepared = await this.flows.prepareSignin(email, password, callerIp);
    const {tokens, mail} = await this.port.transaction(port => this.flows.commitSignin(createStore(port), prepared, transport, previousCredential));
    this.sendMail(mail);
    this.scheduleCleanup();
    if (!tokens) {
      await this.acceptedAfter(started);
      throw new AuthError(emailPolicy.unverifiedCode, emailPolicy.unverifiedStatus);
    }
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
    const hook = this.hooks.creating;
    if (!hook) return;
    const started = performance.now();
    let active = true, timedOut = false;
    let pending: Promise<unknown> = Promise.resolve();
    const expire = () => {
      active = false;
      if (!timedOut) {
        timedOut = true;
        try { console.error(JSON.stringify({cause: "signup_hook_timeout", elapsedMillis: Math.round(performance.now() - started)})); } catch {}
      }
      return new AuthError("user_creation_failed", 500);
    };
    const remaining = () => {
      if (!active) throw new Error("The transaction is no longer active.");
      const milliseconds = Math.floor(signupHookBudgetMillis - (performance.now() - started));
      if (milliseconds <= 0) throw expire();
      return milliseconds;
    };
    const limits = () => {
      const milliseconds = remaining();
      return port.query(`set local lock_timeout = '${milliseconds}ms'; set local statement_timeout = '${milliseconds}ms'`, []);
    };
    const lease: DatabasePort = {
      query(sql, parameters) {
        try { remaining(); } catch (error) { return Promise.reject(error); }
        // Serialize settings with their statement; queued work must recheck the expired lease.
        const result = pending.then(async () => {
          await limits();
          remaining();
          try { return await port.query(sql, parameters); }
          catch (error) {
            if (error && typeof error === "object" && "code" in error && ["57014", "55P03"].includes(String(error.code))) throw expire();
            throw error;
          }
        });
        pending = result.catch(() => {});
        return result;
      },
      transaction() { throw new Error("Nested transactions are not supported."); },
    };
    let timer: ReturnType<typeof setTimeout> | undefined;
    let rejection: string | undefined;
    try {
      const original = await Promise.race([
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(expire()), signupHookBudgetMillis); }),
        (async () => {
          const [settings] = await port.query("select current_setting('lock_timeout') as lock_timeout, current_setting('statement_timeout') as statement_timeout", []);
          await limits();
          remaining();
          rejection = signupRejection(await hook.call(this.hooks, lease, user));
          await pending;
          remaining();
          return settings;
        })(),
      ]);
      active = false;
      clearTimeout(timer);
      await port.query("select set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
        [original.lock_timeout, original.statement_timeout]);
    } catch {
      if (!timedOut) {
        try { console.error(JSON.stringify({cause: "user_creation_failed"})); } catch {}
      }
      throw new AuthError("user_creation_failed", 500);
    }
    finally { active = false; clearTimeout(timer); }
    if (rejection !== undefined) throw publicRejection(signupPolicy.creationRejectedCode, 422, rejection);
  }

  async session(accessToken: string, transport: SessionTransport = "native"): Promise<{ id: string; email: string; sessionId: string; expiresAt: string; emailVerified: boolean }> {
    validateToken(accessToken);
    const result = await this.port.transaction(port => this.flows.commitSession(createStore(port), accessToken, transport));
    if (!result) throw new AuthError("invalid_token", 401);
    return result;
  }

  /** Revalidates an already authenticated connection; session IDs cannot establish a login. */
  async revalidateSession(sessionId: string, userId: string, transport: SessionTransport = "native"): Promise<{ id: string; email: string; sessionId: string; expiresAt: string; emailVerified: boolean }> {
    const result = await this.port.transaction(port => this.flows.commitRevalidateSession(createStore(port), sessionId, userId, transport));
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
        if (invitesOnly) {
          await this.cleanupSignupRequests(db, controller.signal);
          if (!controller.signal.aborted) await this.cleanupInvites(db, controller.signal);
        }
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
    if (!signal.aborted) await this.cleanupSignupRequests(db, signal);
    if (!signal.aborted) await this.cleanupInvites(db, signal);
    if (!signal.aborted && this.options.mailer) {
      try {
        const cutoff = this.timestamp();
        for (const consumed of [true, false]) {
          const rows = consumed ? await db.consumedActionTokens(cleanupLimit) : await db.expiredActionTokens(cutoff, cleanupLimit);
          for (const row of rows) {
            signal.throwIfAborted();
            await db.transaction(tx => tx.deleteExpiredActionToken(row, cutoff));
          }
        }
      } catch { cleanupFailure("action_token"); }
    }
  }

  private async cleanupInvites(db: RuntimeStore, signal: AbortSignal): Promise<void> {
    try {
      signal.throwIfAborted();
      const cutoff = new Date(this.now() - 30 * day).toISOString();
      const candidates = await db.expiredInvites(cutoff, cleanupLimit);
      for (const row of candidates) await db.transaction(tx => this.flows.commitCleanupInvite(tx, row, cutoff));
    } catch (error) {
      // A bounded signup pass may not yet have reached every invite reference.
      if (typeof error === "object" && error !== null && "code" in error && error.code === "23503") return;
      cleanupFailure("invite");
    }
  }

  private async cleanupSignupRequests(db: RuntimeStore, signal: AbortSignal): Promise<void> {
    try {
      signal.throwIfAborted();
      const cutoff = this.timestamp();
      for (const row of await db.expiredSignupRequests(cutoff, cleanupLimit)) {
        signal.throwIfAborted();
        await db.transaction(tx => tx.deleteExpiredSignupRequest(row, cutoff));
      }
    } catch (error) {
      // Off mode may still use the earlier email schema without pending signup storage.
      if (this.options.email?.verification !== "required" && typeof error === "object" && error !== null &&
        "code" in error && error.code === "42P01") return;
      cleanupFailure("signup_request");
    }
  }

  private timestamp(): string { return new Date(this.now()).toISOString(); }
}

function signupRejection(result: unknown): string | undefined {
  if (result === undefined) return undefined;
  if (typeof result !== "object" || result === null || Array.isArray(result) || !Object.hasOwn(result, "reject")) throw new Error();
  const message = (result as {reject: unknown}).reject;
  if (typeof message !== "string") throw new Error();
  const trimmed = message.trim();
  if (trimmed.length === 0 || [...trimmed].length > 200) throw new Error();
  return trimmed;
}

function publicRejection(code: string, status: number, message: string): AuthError {
  const error = new AuthError(code, status);
  error.message = message;
  return error;
}

/** Prints authentication mail locally; never use this mailer in production. */
export function developmentAuthMailer(log: (text: string) => void = console.info): AuthMailer {
  return {async send(message) { log(message.text); }};
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
