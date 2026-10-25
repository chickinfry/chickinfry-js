import type { SessionPolicy } from "./rules.js";

export interface Tokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: string;
  readonly refreshExpiresAt: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly emailVerified: boolean;
}

export type SessionTransport = "native" | "browser";

export interface BrowserSession {
  readonly credential: string;
  readonly cookieMaxAge: number;
  readonly id: string;
  readonly email: string;
  readonly sessionId: string;
  readonly expiresAt: string;
  readonly emailVerified: boolean;
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
  readonly email?: { readonly verification: "required" | "off" };
  readonly mailer?: AuthMailer;
  readonly emailLinkBase?: string;
  readonly projectName?: string;
}

export type ActionTokenKind = "email_verification" | "password_reset";
export type AuthMailKind = ActionTokenKind | "account_exists";

export interface AuthMail {
  readonly to: string;
  readonly kind: AuthMailKind;
  readonly subject: string;
  readonly text: string;
  readonly html: string;
}

export interface AuthMailer {
  send(message: AuthMail): Promise<void>;
}

export interface Accepted { readonly accepted: true; }

export interface SignupAttempt extends Accepted { readonly attempt: string; }

export type SignupHookResult = void | {readonly reject: string};

export interface InviteSummary {
  readonly id: string;
  readonly email: string;
  readonly status: "issued" | "redeemed" | "revoked" | "expired";
  readonly createdAt: string;
  readonly expiresAt: string;
}
