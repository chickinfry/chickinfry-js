import { Auth, AuthError, type Tokens, type InviteSummary } from "./runtime.js";

export const authOperations = ["auth.signup", "auth.signin", "auth.refresh", "auth.session", "auth.logout", "auth.identity",
  "auth.invite_issue", "auth.invite_list", "auth.invite_revoke"];

export function bearer(request: Request): string {
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/i.exec(request.headers.get("authorization") ?? "");
  if (!match) throw new AuthError("invalid_token", 401);
  return match[1]!;
}

export async function invokeAuth(auth: Auth, operation: string, input: unknown, request: Request): Promise<unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new AuthError("invalid_input", 400);
  const value = input as Record<string, unknown>;
  const text = (key: string): string => {
    if (typeof value[key] !== "string") throw new AuthError("invalid_input", 400);
    return value[key];
  };
  const inviteCode = (): string => Object.hasOwn(value, "invite_code") ? text("invite_code") : "";
  const managementToken = (): string => {
    if (!request.headers.has("authorization")) throw new AuthError("unauthenticated", 401);
    return bearer(request);
  };
  switch (operation) {
    case "auth.signup": return tokens(await auth.signup(text("email"), text("password"), inviteCode()));
    case "auth.signin": return tokens(await auth.signin(text("email"), text("password")));
    case "auth.refresh": return tokens(await auth.refresh(text("refresh_token")));
    case "auth.session": {
      const user = await auth.session(bearer(request));
      return {id: user.id, email: user.email, session_id: user.sessionId};
    }
    case "auth.logout": await auth.logout(bearer(request)); return {status: "ok"};
    case "auth.identity": return tokens(await auth.signinIdentity(text("provider"), value.credential, inviteCode()));
    case "auth.invite_issue": {
      const id = text("id"), email = text("email");
      const result = await auth.inviteIssue(managementToken(), id, email);
      return {...summary(result), code: result.code};
    }
    case "auth.invite_list": {
      const cursor = text("cursor");
      const result = await auth.inviteList(managementToken(), cursor);
      return {items: result.items.map(summary), next_cursor: result.nextCursor};
    }
    case "auth.invite_revoke": {
      const id = text("id");
      return auth.inviteRevoke(managementToken(), id);
    }
    default: throw new AuthError("not_found", 404);
  }
}

function summary(value: InviteSummary) {
  return {id: value.id, email: value.email, status: value.status,
    created_at: value.createdAt, expires_at: value.expiresAt};
}

function tokens(value: Tokens) {
  return {access_token: value.accessToken, refresh_token: value.refreshToken,
    expires_at: value.expiresAt, refresh_expires_at: value.refreshExpiresAt,
    user_id: value.userId, session_id: value.sessionId};
}
