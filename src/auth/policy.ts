import { and, or, appAuthSessionsTable, type AppAuthSessionsRow, type AppAuthRefreshTokensRow } from "./private/database.js";
import type { Filter } from "../orm.js";

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

export function cleanupCandidates(policy: Policy, now: number): Filter {
  const c = appAuthSessionsTable.columns;
  const cutoff = new Date(now).toISOString();
  const idleCutoff = new Date(now - policy.idleTimeoutSeconds * 1000).toISOString();
  const filters = [c.revokedAt.isNotNull(),
    and(c.transport.equals("browser"), c.expiresAt.lessThanOrEquals(cutoff)),
    c.lastRenewedAt.lessThanOrEquals(idleCutoff),
    and(c.lastRenewedAt.isNull(), or(c.expiresAt.lessThanOrEquals(idleCutoff),
      c.createdAt.lessThanOrEquals(new Date(now - legacyLifetimeMillis).toISOString())))];
  if (policy.absoluteLifetimeSeconds !== 0) {
    const absoluteCutoff = new Date(now - policy.absoluteLifetimeSeconds * 1000).toISOString();
    filters.push(c.firstLoginAt.lessThanOrEquals(absoluteCutoff),
      and(c.firstLoginAt.isNull(), c.createdAt.lessThanOrEquals(absoluteCutoff)));
  }
  return or(...filters);
}
