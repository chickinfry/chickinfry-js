import type { SessionPolicy } from "./rules.js";

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

export interface AuthActor {
  readonly id: string;
  readonly user: { readonly id: string; readonly email: string };
}

export interface AuthOptions {
  readonly signup?: "open" | "invite-only";
  readonly projectId?: string;
  readonly session?: SessionPolicy;
}

export interface InviteSummary {
  readonly id: string;
  readonly email: string;
  readonly status: "issued" | "redeemed" | "revoked" | "expired";
  readonly createdAt: string;
  readonly expiresAt: string;
}
