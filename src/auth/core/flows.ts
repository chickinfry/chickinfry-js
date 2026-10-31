import { Buffer } from "node:buffer";
import { hashPassword, verifyPassword, randomToken, hashToken, randomCode, hashCode, verifyCode } from "./crypto.js";
import { sessionPolicy, sessionExpiry, sessionState, cookieMaxAge, accessLifetimeMillis, normalizeEmail, validatePassword, nextRateLimit,
  emailPolicy, signupPolicy, emailSigninAllowed, mailRateKeys, actionTokenExpiry, type SessionPolicy } from "./rules.js";
import { AuthError } from "./errors.js";
import type { Store, AppAuthUsersRow, AppAuthInvitesRow, AppAuthSessionsRow, AppAuthRefreshTokensRow, AppAuthRateLimitsRow, AppAuthSignupRequestsRow } from "./store.js";
import type { Tokens, BrowserSession, IdentityProvider, AuthUser, AuthOptions, SessionTransport, InviteSummary, AuthActor, ActionTokenKind } from "./types.js";

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

  async prepareSignup(email: string, password: string, inviteCode: string, callerIp?: string) {
    email = normalizeEmail(email);
    validatePassword(password);
    if (typeof inviteCode !== "string") throw new AuthError("invalid_input", 400);
    await this.rateLimit("signup", email);
    const invite = this.options.signup === "invite-only" ? await this.checkInvite(this.db, email, inviteCode) : undefined;
    const passwordHash = await hashPassword(password);
    const mailAllowed = this.options.email?.verification === "required" && await this.allowMail(email, callerIp);
    return {email, passwordHash, mailAllowed, inviteId: invite?.id ?? null};
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

  async prepareSignin(email: string, password: string, callerIp?: string) {
    email = normalizeEmail(email);
    validatePassword(password);
    await this.rateLimit("signin", email);
    const user = await this.db.userByEmail(email);
    const matched = await verifyPassword(password, user?.passwordHash ?? null);
    if (!matched || !user || user.disabledAt !== null) throw new AuthError("invalid_credentials", 401);
    const unverified = this.options.email?.verification === "required" && !emailSigninAllowed(user.emailVerifiedAt);
    const previous = unverified ? await this.db.liveActionToken(user.id, "email_verification", this.timestamp()) : undefined;
    const mailAllowed = unverified && (!previous || this.now() - Date.parse(previous.createdAt) >= emailPolicy.codeResendMillis) &&
      await this.allowMail(user.email, callerIp);
    return {user, mailAllowed};
  }

  async commitSignin(tx: Store, prepared: Awaited<ReturnType<Flows["prepareSignin"]>>, transport: SessionTransport, previousCredential: string) {
    const user = await tx.lockUser(prepared.user.id, prepared.user.sessionVersion);
    if (!user) throw new AuthError("invalid_credentials", 401);
    if (this.options.email?.verification === "required" && !emailSigninAllowed(user.emailVerifiedAt)) {
      const previous = await tx.liveActionToken(user.id, "email_verification", this.timestamp());
      const mail = prepared.mailAllowed && (!previous || this.now() - Date.parse(previous.createdAt) >= emailPolicy.codeResendMillis)
        ? await this.issueActionToken(tx, user.id, user.email, "email_verification") : undefined;
      return {mail};
    }
    return {tokens: await this.issue(tx, user, transport, previousCredential)};
  }

  async commitEmailSignup(tx: Store, input: Awaited<ReturnType<Flows["prepareSignup"]>> & {attempt: string}) {
    await this.lockSignupEmail(tx, input.email);
    if (await tx.userByEmail(input.email)) {
      return input.mailAllowed ? {kind: "account_exists" as const, to: input.email, token: ""} : undefined;
    }
    const previous = await tx.signupsByEmail(input.email);
    const active = [];
    for (const row of previous) {
      if (Date.parse(row.expiresAt) <= this.now()) await tx.deleteSignup(row.id);
      else active.push(row);
    }
    if (active.length >= signupPolicy.maximumActiveRequests) return undefined;
    const token = await this.newCode(tx, input.email, ...active.map(row => row.codeHash)), at = this.timestamp();
    await tx.saveSignup({id: input.attempt, email: input.email, passwordHash: input.passwordHash, codeHash: hashCode(input.email, token),
      codeExpiresAt: actionTokenExpiry("email_verification", this.now()), inviteId: input.inviteId,
      expiresAt: new Date(this.now() + signupPolicy.requestLifetimeMillis).toISOString(),
      attempts: 0, createdAt: at, updatedAt: at});
    return input.mailAllowed ? {kind: "email_verification" as const, to: input.email, token, signup: true} : undefined;
  }

  private async lockSignupEmail(tx: Store, email: string) {
    await tx.lockSignupEmail(hashToken(email), new Date(this.now() + signupPolicy.requestLifetimeMillis).toISOString());
  }

  async commitSignupVerification(tx: Store, candidate: AppAuthSignupRequestsRow, code: string,
    transport: SessionTransport, previousCredential: string, creating: (user: AuthUser) => Promise<void>) {
    await this.lockSignupEmail(tx, candidate.email);
    const row = await tx.lockSignup(candidate, this.timestamp());
    if (!row || Date.parse(row.expiresAt) <= this.now() || Date.parse(row.codeExpiresAt) <= this.now() ||
        row.attempts >= emailPolicy.codeMaximumAttempts) return undefined;
    if (!verifyCode(row.email, code, row.codeHash)) {
      await tx.failSignupCode(row);
      return undefined;
    }
    if (await tx.userByEmail(row.email)) return undefined;
    let invite;
    if (row.inviteId !== null) {
      const candidate = await tx.invite(row.inviteId);
      if (!candidate) throw new AuthError("invite_invalid", 403);
      invite = await tx.lockInvite(candidate, row.email, candidate.codeHash, this.timestamp());
      if (!invite || Date.parse(invite.expiresAt) <= this.now()) throw new AuthError("invite_invalid", 403);
    } else if (this.options.signup === "invite-only") throw new AuthError("invite_required", 403);
    if (Date.parse(row.codeExpiresAt) <= this.now() || Date.parse(row.expiresAt) <= this.now()) return undefined;
    const created = await tx.createUser(row.email, row.passwordHash);
    const verifiedAt = this.timestamp();
    await tx.markEmailVerified(created.id, verifiedAt);
    if (invite) await tx.updateInvite(invite.id, {redeemedAt: verifiedAt, redeemedBy: created.id});
    await creating(publicUser(created));
    const result = await this.issue(tx, {...created, emailVerifiedAt: verifiedAt}, transport, previousCredential);
    for (const attempt of await tx.signupsByEmail(row.email)) await tx.deleteSignup(attempt.id);
    return result;
  }

  async prepareMail(email: string, kind: ActionTokenKind, callerIp?: string, attempt?: string) {
    email = normalizeEmail(email);
    if (kind === "email_verification") {
      const signup = attempt === undefined ? undefined : await this.db.signup(attempt);
      const user = attempt === undefined ? await this.db.userByEmail(email) : undefined;
      const previous = user ? await this.db.liveActionToken(user.id, kind, this.timestamp()) : undefined;
      if ((attempt !== undefined && (!signup || Date.parse(signup.expiresAt) <= this.now())) ||
          !signup && (!previous || previous.attempts >= emailPolicy.codeMaximumAttempts)) return {email, attempt, allowed: false};
      if (this.now() - Date.parse(signup?.updatedAt ?? previous?.createdAt ?? "") < emailPolicy.codeResendMillis) {
        return {email, attempt, allowed: false};
      }
    }
    return {email, attempt, allowed: await this.allowMail(email, callerIp)};
  }

  async commitMail(tx: Store, input: Awaited<ReturnType<Flows["prepareMail"]>>, kind: ActionTokenKind) {
    if (!input.allowed) return undefined;
    if (input.attempt !== undefined) {
      await this.lockSignupEmail(tx, input.email);
      const signup = await tx.signup(input.attempt);
      if (!signup || signup.email !== input.email) return undefined;
      const previous = await tx.signupsByEmail(input.email);
      const token = await this.newCode(tx, input.email, ...previous.map(row => row.codeHash));
      const row = await tx.renewSignup(signup, hashCode(input.email, token), actionTokenExpiry(kind, this.now()), this.timestamp());
      return row ? {kind, to: input.email, token, signup: true} : undefined;
    }
    const candidate = await tx.userByEmail(input.email);
    if (!candidate) return undefined;
    const user = await tx.lockUser(candidate.id, candidate.sessionVersion);
    if (!user) return undefined;
    if (kind === "email_verification") {
      if (user.emailVerifiedAt !== null) return undefined;
      const previous = await tx.liveActionToken(user.id, kind, this.timestamp());
      if (!previous || previous.attempts >= emailPolicy.codeMaximumAttempts ||
          this.now() - Date.parse(previous.createdAt) < emailPolicy.codeResendMillis) return undefined;
    }
    return this.issueActionToken(tx, user.id, user.email, kind);
  }

  async prepareAction(token: string, kind: ActionTokenKind) {
    if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw invalidActionToken();
    const row = await this.db.actionByToken(hashToken(token), kind);
    if (!row) throw invalidActionToken();
    return row;
  }

  async preparePasswordReset(token: string, password: string) {
    validatePassword(password);
    const row = await this.prepareAction(token, "password_reset");
    return {row, passwordHash: await hashPassword(password)};
  }

  async commitVerifyEmail(tx: Store, email: string, code: string, transport: SessionTransport, previousCredential: string) {
    const candidate = await tx.userByEmail(email);
    if (!candidate) return undefined;
    const user = await tx.lockUser(candidate.id, candidate.sessionVersion);
    if (!user || user.emailVerifiedAt !== null) return undefined;
    const row = await tx.liveActionToken(user.id, "email_verification", this.timestamp());
    if (!row || Date.parse(row.expiresAt) <= this.now() || row.attempts >= emailPolicy.codeMaximumAttempts) return undefined;
    if (!verifyCode(email, code, row.tokenHash)) {
      await tx.failActionCode(row);
      return undefined;
    }
    if (!await tx.consumeActionToken(row.id, "email_verification", this.timestamp())) return undefined;
    const verifiedAt = this.timestamp();
    await tx.markEmailVerified(user.id, verifiedAt);
    return this.issue(tx, {...user, emailVerifiedAt: verifiedAt}, transport, previousCredential);
  }

  async commitPasswordReset(tx: Store, input: Awaited<ReturnType<Flows["preparePasswordReset"]>>) {
    await this.consumeActionToken(tx, input.row, "password_reset");
    await tx.resetPassword(input.row.userId, input.passwordHash);
    const user = await tx.user(input.row.userId);
    if (user?.emailVerifiedAt === null) await tx.markEmailVerified(user.id, this.timestamp());
  }

  private async consumeActionToken(tx: Store, row: Awaited<ReturnType<Flows["prepareAction"]>>, kind: ActionTokenKind) {
    const user = await tx.user(row.userId);
    if (!user || !await tx.lockUser(user.id, user.sessionVersion)) throw invalidActionToken();
    const consumed = await tx.consumeActionToken(row.id, kind, this.timestamp());
    if (!consumed || Date.parse(consumed.expiresAt) <= this.now()) throw invalidActionToken();
  }

  private async issueActionToken(tx: Store, userId: string, to: string, kind: ActionTokenKind) {
    const token = kind === "email_verification" ? await this.newCode(tx, to) : randomToken();
    const now = this.now();
    const createdAt = new Date(now).toISOString();
    await tx.invalidateActionTokens(userId, kind, createdAt);
    await tx.createActionToken({userId, kind, tokenHash: kind === "email_verification" ? hashCode(to, token) : hashToken(token),
      expiresAt: actionTokenExpiry(kind, now), createdAt});
    return {kind, to, token};
  }

  private async newCode(tx: Store, email: string, ...previousHashes: string[]): Promise<string> {
    let code: string;
    do { code = randomCode(); }
    while (previousHashes.includes(hashCode(email, code)) || await tx.actionByToken(hashCode(email, code), "email_verification"));
    return code;
  }

  private async allowMail(email: string, callerIp?: string): Promise<boolean> {
    const keys = mailRateKeys(email, callerIp);
    try {
      if (keys.ip) await this.rateLimit("auth_mail_ip", keys.ip, emailPolicy.ipMaximum, emailPolicy.rateWindowMillis);
      await this.rateLimit("auth_mail_address", keys.address, emailPolicy.addressMaximum, emailPolicy.rateWindowMillis);
      return true;
    } catch (error) {
      if (error instanceof AuthError && error.code === "rate_limited") return false;
      throw error;
    }
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
        !user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion ||
        this.options.email?.verification === "required" && !emailSigninAllowed(user.emailVerifiedAt)) {
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
    return {accessToken, refreshToken: nextRefresh, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id, emailVerified: user.emailVerifiedAt !== null};
  }

  async commitSession(tx: Store, accessToken: string, transport: SessionTransport) {
    const candidate = await tx.sessionByToken(hashToken(accessToken));
    if (candidate && candidate.transport !== transport) throw new AuthError(transport === "browser" ? "invalid_input" : "invalid_token", transport === "browser" ? 400 : 401);
    const session = await this.lockSession(tx, candidate, hashToken(accessToken));
    return session && this.validateSession(tx, session);
  }

  async commitRevalidateSession(tx: Store, sessionId: string, userId: string, transport: SessionTransport = "native") {
    const candidate = await tx.session(sessionId);
    if (candidate?.userId !== userId || candidate.transport !== transport) return undefined;
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

  private lockSession(tx: Store, candidate: AppAuthSessionsRow | null | undefined, tokenHash?: string): Promise<AppAuthSessionsRow | undefined> {
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
    if (!user || user.disabledAt !== null || user.sessionVersion !== session.userSessionVersion ||
        this.options.email?.verification === "required" && !emailSigninAllowed(user.emailVerifiedAt)) return undefined;
    let expiresAt = session.expiresAt;
    if (state.renew) {
      expiresAt = new Date(sessionExpiry(this.policy, state.firstLoginAt, now)).toISOString();
      await tx.updateSession(session.id, {expiresAt,
        firstLoginAt: new Date(state.firstLoginAt).toISOString(), lastRenewedAt: new Date(now).toISOString()});
    } else if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= now) return undefined;
    else if (state.expiresAt < Date.parse(expiresAt)) expiresAt = new Date(state.expiresAt).toISOString();
    return {id: user.id, email: user.email, sessionId: session.id, expiresAt, emailVerified: user.emailVerifiedAt !== null};
  }

  private async issue(tx: Store, user: AppAuthUsersRow, transport: SessionTransport, previousCredential = ""): Promise<Tokens | BrowserSession> {
    if (this.options.email?.verification === "required" && !emailSigninAllowed(user.emailVerifiedAt)) {
      throw new AuthError(emailPolicy.unverifiedCode, emailPolicy.unverifiedStatus);
    }
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
      id: user.id, email: user.email, sessionId: session.id, expiresAt, emailVerified: user.emailVerifiedAt !== null};
    const refreshToken = randomToken();
    await tx.createRefresh({sessionId: session.id, tokenHash: hashToken(refreshToken), expiresAt: refreshExpiresAt, createdAt: timestamp});
    return {accessToken, refreshToken, expiresAt, refreshExpiresAt, userId: user.id, sessionId: session.id, emailVerified: user.emailVerifiedAt !== null};
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
      const updated = await this.db.updateRateLimit(row, next, maximum);
      if (updated) return;
    }
    throw new AuthError("rate_limited", 429);
  }
}

function publicUser(user: AppAuthUsersRow): AuthUser {
  return Object.freeze({id:user.id, email:user.email, createdAt:user.createdAt});
}

function invalidActionToken(): AuthError {
  return new AuthError(emailPolicy.invalidTokenCode, emailPolicy.invalidTokenStatus);
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
