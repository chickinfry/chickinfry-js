export interface AppAuthIdentitiesRow {
  readonly createdAt: string;
  readonly provider: string;
  readonly subject: string;
  readonly userId: string;
}

export interface AppAuthInvitesRow {
  readonly codeHash: string;
  readonly createdAt: string;
  readonly email: string;
  readonly expiresAt: string;
  readonly id: string;
  readonly issuedBy: string;
  readonly redeemedAt: string | null;
  readonly redeemedBy: string | null;
  readonly revokedAt: string | null;
}

export interface AppAuthRateLimitsRow {
  readonly action: string;
  readonly attemptCount: number;
  readonly expiresAt: string;
  readonly keyHash: string;
}

export interface AppAuthRefreshTokensRow {
  readonly consumedAt: string | null;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly id: string;
  readonly sessionId: string;
  readonly tokenHash: string;
}

export interface AppAuthSessionsRow {
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly firstLoginAt: string | null;
  readonly id: string;
  readonly lastRenewedAt: string | null;
  readonly revokedAt: string | null;
  readonly tokenHash: string;
  readonly transport: string;
  readonly userId: string;
  readonly userSessionVersion: number;
}

export interface AppAuthUsersRow {
  readonly createdAt: string;
  readonly disabledAt: string | null;
  readonly emailVerifiedAt: string | null;
  readonly email: string;
  readonly id: string;
  readonly passwordHash: string | null;
  readonly sessionVersion: number;
}

export interface AppAuthActionTokensRow {
  readonly id: string;
  readonly userId: string;
  readonly kind: string;
  readonly tokenHash: string;
  readonly expiresAt: string;
  readonly consumedAt: string | null;
  readonly createdAt: string;
  readonly attempts: number;
}

export interface AppAuthSignupRequestsRow {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly codeHash: string;
  readonly codeExpiresAt: string;
  readonly inviteId: string | null;
  readonly expiresAt: string;
  readonly attempts: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Store {
  signup(id: string): Promise<AppAuthSignupRequestsRow | undefined>;
  signupsByEmail(email: string): Promise<AppAuthSignupRequestsRow[]>;
  lockSignupEmail(keyHash: string, expiresAt: string): Promise<void>;
  saveSignup(values: AppAuthSignupRequestsRow): Promise<void>;
  lockSignup(row: AppAuthSignupRequestsRow, at: string): Promise<AppAuthSignupRequestsRow | undefined>;
  renewSignup(row: AppAuthSignupRequestsRow, codeHash: string, codeExpiresAt: string, at: string): Promise<AppAuthSignupRequestsRow | undefined>;
  failSignupCode(row: AppAuthSignupRequestsRow): Promise<void>;
  deleteSignup(id: string): Promise<void>;
  expiredSignupRequests(cutoff: string, limit: number): Promise<AppAuthSignupRequestsRow[]>;
  deleteExpiredSignupRequest(row: AppAuthSignupRequestsRow, cutoff: string): Promise<void>;
  user(id: string): Promise<AppAuthUsersRow | undefined>;
  userByEmail(email: string): Promise<AppAuthUsersRow | undefined>;
  createUser(email: string, passwordHash: string | null): Promise<AppAuthUsersRow>;
  lockUser(id: string, version: number): Promise<AppAuthUsersRow | undefined>;
  markEmailVerified(userId: string, at: string): Promise<void>;
  resetPassword(userId: string, passwordHash: string): Promise<void>;
  actionByToken(hash: string, kind: string): Promise<AppAuthActionTokensRow | undefined>;
  failActionCode(row: AppAuthActionTokensRow): Promise<void>;
  liveActionToken(userId: string, kind: string, at: string): Promise<AppAuthActionTokensRow | undefined>;
  createActionToken(values: Omit<AppAuthActionTokensRow, "id" | "consumedAt" | "attempts">): Promise<AppAuthActionTokensRow>;
  invalidateActionTokens(userId: string, kind: string, at: string): Promise<void>;
  consumeActionToken(id: string, kind: string, at: string): Promise<AppAuthActionTokensRow | undefined>;
  consumedActionTokens(limit: number): Promise<AppAuthActionTokensRow[]>;
  expiredActionTokens(cutoff: string, limit: number): Promise<AppAuthActionTokensRow[]>;
  deleteExpiredActionToken(row: AppAuthActionTokensRow, cutoff: string): Promise<void>;
  identity(provider: string, subject: string): Promise<AppAuthIdentitiesRow | undefined>;
  createIdentity(provider: string, subject: string, userId: string): Promise<AppAuthIdentitiesRow>;
  session(id: string): Promise<AppAuthSessionsRow | undefined>;
  sessionByToken(hash: string): Promise<AppAuthSessionsRow | undefined>;
  lockSession(id: string, hash?: string): Promise<AppAuthSessionsRow | undefined>;
  lockCleanupSession(row: AppAuthSessionsRow): Promise<AppAuthSessionsRow | undefined>;
  updateSession(id: string, values: Partial<Pick<AppAuthSessionsRow, "tokenHash" | "expiresAt" | "firstLoginAt" | "lastRenewedAt" | "revokedAt">>): Promise<AppAuthSessionsRow>;
  createSession(values: Omit<AppAuthSessionsRow, "id" | "revokedAt">): Promise<AppAuthSessionsRow>;
  revokeSession(id: string, at: string, browserHash?: string): Promise<AppAuthSessionsRow | undefined>;
  deleteSession(id: string): Promise<void>;
  cleanupSessions(condition: import("./rules.js").CleanupCondition, start: string, wrap: boolean, limit: number): Promise<AppAuthSessionsRow[]>;
  refresh(id: string): Promise<AppAuthRefreshTokensRow | undefined>;
  refreshByToken(hash: string): Promise<AppAuthRefreshTokensRow | undefined>;
  latestRefresh(sessionId: string): Promise<AppAuthRefreshTokensRow | undefined>;
  refreshChildren(sessionId: string, limit: number): Promise<AppAuthRefreshTokensRow[]>;
  createRefresh(values: Omit<AppAuthRefreshTokensRow, "id" | "consumedAt">): Promise<AppAuthRefreshTokensRow>;
  consumeRefresh(id: string, at: string): Promise<AppAuthRefreshTokensRow | undefined>;
  deleteRefresh(id: string): Promise<void>;
  invite(id: string): Promise<AppAuthInvitesRow | undefined>;
  inviteByCode(hash: string): Promise<AppAuthInvitesRow | undefined>;
  createInvite(values: Omit<AppAuthInvitesRow, "redeemedAt" | "redeemedBy" | "revokedAt">): Promise<AppAuthInvitesRow>;
  updateInvite(id: string, values: Partial<Pick<AppAuthInvitesRow, "redeemedAt" | "redeemedBy" | "revokedAt">>): Promise<AppAuthInvitesRow>;
  lockInvite(row: AppAuthInvitesRow, email: string, hash: string, now: string): Promise<AppAuthInvitesRow | undefined>;
  lockInviteExpiry(row: AppAuthInvitesRow, cutoff?: string): Promise<AppAuthInvitesRow | undefined>;
  listInvites(after: [string, string] | undefined): Promise<AppAuthInvitesRow[]>;
  expiredInvites(cutoff: string, limit: number): Promise<AppAuthInvitesRow[]>;
  deleteInvite(id: string): Promise<void>;
  rateLimit(key: RateKey): Promise<AppAuthRateLimitsRow | undefined>;
  createRateLimit(values: AppAuthRateLimitsRow): Promise<AppAuthRateLimitsRow>;
  updateRateLimit(row: AppAuthRateLimitsRow, values: RateState, maximum: number): Promise<AppAuthRateLimitsRow | undefined>;
  expiredRateLimits(cutoff: string, limit: number): Promise<AppAuthRateLimitsRow[]>;
  lockRateLimit(row: AppAuthRateLimitsRow, cutoff: string): Promise<AppAuthRateLimitsRow | undefined>;
  deleteRateLimit(key: RateKey): Promise<void>;
}

export type RateKey = Pick<AppAuthRateLimitsRow, "action" | "keyHash">;
export type RateState = Pick<AppAuthRateLimitsRow, "attemptCount" | "expiresAt">;
