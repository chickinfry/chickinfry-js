import type { AppAuthSessionsRow, AppAuthRefreshTokensRow, RateState } from "./store.js";
import { AuthError } from "./errors.js";

export interface SessionPolicy {
  readonly idleTimeoutSeconds?: number;
  readonly absoluteLifetimeSeconds?: number;
}

type Policy = Required<SessionPolicy>;
type Family = Pick<AppAuthSessionsRow, "createdAt" | "firstLoginAt" | "lastRenewedAt" | "expiresAt" | "revokedAt" | "transport">;
type Refresh = Pick<AppAuthRefreshTokensRow, "createdAt" | "expiresAt">;

export const accessLifetimeMillis = 900000;
const legacyLifetimeMillis = 604800000;

export function sessionPolicy(value: SessionPolicy = {}): Policy {
  if (typeof value !== "object" || value === null || Array.isArray(value) ||
      Object.keys(value).some(key => key !== "idleTimeoutSeconds" && key !== "absoluteLifetimeSeconds")) {
    throw new Error("auth.session must contain idleTimeoutSeconds and absoluteLifetimeSeconds only.");
  }
  const idleTimeoutSeconds = value.idleTimeoutSeconds === undefined ? 2592000 : value.idleTimeoutSeconds;
  const absoluteLifetimeSeconds = value.absoluteLifetimeSeconds === undefined ? 0 : value.absoluteLifetimeSeconds;
  if (!Number.isInteger(idleTimeoutSeconds) || idleTimeoutSeconds < 3600 || idleTimeoutSeconds > 31536000) {
    throw new Error("auth.session.idle_timeout_seconds must be an integer between 3600 and 31536000 seconds.");
  }
  if (!Number.isInteger(absoluteLifetimeSeconds) ||
      absoluteLifetimeSeconds !== 0 && (absoluteLifetimeSeconds < 3600 || absoluteLifetimeSeconds > 31536000)) {
    throw new Error("auth.session.absolute_lifetime_seconds must be 0 (disabled) or an integer between 3600 and 31536000 seconds.");
  }
  return Object.freeze({idleTimeoutSeconds, absoluteLifetimeSeconds});
}

export function sessionExpiry(policy: Policy, firstLoginAt: number, lastRenewedAt: number): number {
  return Math.min(lastRenewedAt + policy.idleTimeoutSeconds * 1000,
    policy.absoluteLifetimeSeconds === 0 ? Infinity : firstLoginAt + policy.absoluteLifetimeSeconds * 1000);
}

export function sessionState(session: Family, latest: Refresh | undefined, policy: Policy, now: number) {
  const firstLoginAt = Date.parse(session.firstLoginAt ?? session.createdAt);
  // Legacy native families use their latest normal refresh issuance, never access expiry arithmetic.
  const lastRenewedAt = Date.parse(session.lastRenewedAt ?? (session.transport === "browser" ? session.createdAt : latest?.createdAt ?? ""));
  const storedExpiry = Date.parse(session.transport === "browser" ? session.expiresAt : latest?.expiresAt ?? "");
  const expiresAt = Math.min(storedExpiry, sessionExpiry(policy, firstLoginAt, lastRenewedAt));
  const expired = session.revokedAt !== null || !Number.isFinite(expiresAt) || now >= expiresAt;
  return {firstLoginAt, expiresAt, expired, renew: !expired && session.transport === "browser"};
}

export function cookieMaxAge(policy: Policy, firstLoginAt: number, now: number): number {
  return policy.absoluteLifetimeSeconds === 0 ? 34560000
    : Math.max(0, Math.floor((firstLoginAt + policy.absoluteLifetimeSeconds * 1000 - now) / 1000));
}

export interface CleanupCondition {
  readonly cutoff: string;
  readonly idleCutoff: string;
  readonly legacyCutoff: string;
  readonly absoluteCutoff?: string;
}

export function cleanupCandidates(policy: Policy, now: number): CleanupCondition {
  return {
    cutoff: new Date(now).toISOString(),
    idleCutoff: new Date(now - policy.idleTimeoutSeconds * 1000).toISOString(),
    legacyCutoff: new Date(now - legacyLifetimeMillis).toISOString(),
    ...(policy.absoluteLifetimeSeconds === 0 ? {} : {
      absoluteCutoff: new Date(now - policy.absoluteLifetimeSeconds * 1000).toISOString(),
    }),
  };
}

export function cleanupPage(start: string, wrap: boolean, count: number, limit: number) {
  return {start, wrap, limit: limit - count};
}

export function normalizeEmail(value: string): string {
  if (typeof value !== "string") throw new AuthError("invalid_input", 400);
  const email = value.trim().toLowerCase();
  if (email.includes("\0") || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new AuthError("invalid_input", 400);
  return email;
}

export function validatePassword(value: string): void {
  if (typeof value !== "string" || [...value].length < 15 || new TextEncoder().encode(value).byteLength > 1024) {
    throw new AuthError("invalid_input", 400);
  }
}

export function validateToken(value: string): void {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new AuthError("invalid_token", 401);
}

export function nextRateLimit(row: RateState, expiresAt: string, maximum: number, now: number): RateState {
  const expired = Date.parse(row.expiresAt) <= now;
  if (!expired && row.attemptCount >= maximum) throw new AuthError("rate_limited", 429);
  return {attemptCount: expired ? 1 : row.attemptCount + 1, expiresAt: expired ? expiresAt : row.expiresAt};
}
