import { domainToASCII, domainToUnicode } from "node:url";
import type { AppAuthSessionsRow, AppAuthRefreshTokensRow, RateState } from "./store.js";
import { AuthError } from "./errors.js";
import type { ActionTokenKind, AuthMailKind, AuthMail } from "./types.js";

export const emailPolicy = Object.freeze({
  verificationLifetimeMillis: 10 * 60_000,
  codeMaximumAttempts: 5,
  codeResendMillis: 60_000,
  invalidCode: "invalid_code",
  resetLifetimeMillis: 3600000,
  rateWindowMillis: 3600000,
  addressMaximum: 3,
  ipMaximum: 30,
  unverifiedCode: "email_not_verified",
  unverifiedStatus: 403,
  invalidTokenCode: "invalid_token",
  invalidTokenStatus: 400,
  accepted: Object.freeze({accepted: true as const}),
});

export const signupPolicy = Object.freeze({
  rejectedCode: "signup_rejected",
  checkFailedCode: "signup_check_failed",
  creationRejectedCode: "user_creation_rejected",
  requestLifetimeMillis: 24 * 60 * 60_000,
  maximumActiveRequests: 3,
});

export function actionTokenExpiry(kind: ActionTokenKind, now: number): string {
  return new Date(now + (kind === "email_verification"
    ? emailPolicy.verificationLifetimeMillis : emailPolicy.resetLifetimeMillis)).toISOString();
}

export function emailSigninAllowed(verifiedAt: string | null): boolean {
  return verifiedAt !== null;
}

export function mailRateKeys(email: string, callerIp?: string | null) {
  return {address: email, ip: callerIp || null};
}

export function emailLinkBase(value: unknown): string {
  try {
    if (typeof value !== "string" || value.includes("#")) throw new Error();
    const raw = /^(https?):\/\/([^/?@\\\s%]+)(\/[A-Za-z0-9._~/-]*)?$/i.exec(value);
    if (!raw) throw new Error();
    const url = new URL(value);
    const host = url.hostname, rawHost = raw[2]!.replace(/:[0-9]*$/, "").toLowerCase();
    for (const label of rawHost.split(/[.\u3002\uff0e\uff61]/)) {
      const mapped = domainToASCII("x" + label);
      if (!mapped.startsWith("xxn--")) continue;
      const decoded = domainToUnicode(label);
      if (!decoded || decoded === domainToASCII(label) || domainToASCII(decoded) !== mapped.slice(1)) throw new Error();
    }
    if (host.startsWith("[::ffff:") || !host.startsWith("[") && (host.length > 253 ||
      host.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) ||
      /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host) && rawHost !== host) throw new Error();
    if (url.username || url.password || url.search || url.hash ||
      url.protocol === "http:" && !/^(localhost|127\.0\.0\.1)(:[0-9]+)?$/i.test(raw[2]!)) throw new Error();
    return url.href.replace(/\/$/, "");
  } catch { throw new Error("Auth email link base must be an HTTPS client URL with only / and ASCII unreserved path characters, without credentials, query, or fragment (HTTP localhost and 127.0.0.1 are allowed)."); }
}

export function actionTokenLink(base: string, kind: "password_reset", token: string): string {
  return `${base.replace(/\/$/, "")}/auth/reset-password#token=${encodeURIComponent(token)}`;
}

export function renderAuthMail(kind: AuthMailKind, project: string, base: string, token: string, signup = false): Pick<AuthMail, "subject" | "text" | "html"> {
  const link = kind === "password_reset" ? actionTokenLink(base, kind, token) : "";
  const code = token.slice(0, 3) + " " + token.slice(3);
  const subject = kind === "account_exists" ? `You already have a ${project} account`
    : kind === "email_verification" ? `Verify your ${project} email address` : `Reset your ${project} password`;
  const text = kind === "account_exists"
    ? `Someone tried to create a ${project} account with this email address, but you already have one.\nSign in: ${base.replace(/\/$/, "")}/auth/signin\nForgot your password? Reset it: ${base.replace(/\/$/, "")}/auth/reset-password\nIf this wasn't you, you can ignore this email. No new account was created.`
    : kind === "email_verification"
      ? `${signup ? "Your code is " : "Use this code to verify your email: "}${code}. It expires in 10 minutes. If you didn't sign up, you can ignore this email.`
      : `Reset your password for ${project}:\n${link}\nThis link expires in 1 hour. If you did not request this, you can ignore this email.`;
  const links = kind === "account_exists"
    ? [`${base.replace(/\/$/, "")}/auth/signin`, `${base.replace(/\/$/, "")}/auth/reset-password`] : [link];
  const html = text.split("\n").map(line => {
    const url = links.find(url => url && line.endsWith(url));
    return url ? `<p>${escapeHtml(line.slice(0, -url.length))}<a href="${escapeHtml(url)}">${escapeHtml(url)}</a></p>`
      : `<p>${escapeHtml(line)}</p>`;
  }).join("");
  return {subject, text, html};
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, character => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[character]!);
}

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
