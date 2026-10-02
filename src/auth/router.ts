import { Auth, AuthError, type Tokens } from "./runtime.js";

export const authOperations = ["auth.signup", "auth.signin", "auth.refresh", "auth.session", "auth.logout", "auth.identity"];

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
  switch (operation) {
    case "auth.signup": return tokens(await auth.signup(text("email"), text("password")));
    case "auth.signin": return tokens(await auth.signin(text("email"), text("password")));
    case "auth.refresh": return tokens(await auth.refresh(text("refresh_token")));
    case "auth.session": {
      const user = await auth.session(bearer(request));
      return {id: user.id, email: user.email, session_id: user.sessionId};
    }
    case "auth.logout": await auth.logout(bearer(request)); return {status: "ok"};
    case "auth.identity": return tokens(await auth.signinIdentity(text("provider"), value.credential));
    default: throw new AuthError("not_found", 404);
  }
}

function tokens(value: Tokens) {
  return {access_token: value.accessToken, refresh_token: value.refreshToken,
    expires_at: value.expiresAt, refresh_expires_at: value.refreshExpiresAt,
    user_id: value.userId, session_id: value.sessionId};
}
