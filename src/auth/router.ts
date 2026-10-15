import { Auth, AuthError, type Tokens, type InviteSummary, type BrowserSession } from "./runtime.js";

export const authOperations = ["auth.signup", "auth.signin", "auth.refresh", "auth.session", "auth.logout", "auth.identity",
  "auth.invite_issue", "auth.invite_list", "auth.invite_revoke"];

export function bearer(request: Request): string {
  const match = /^Bearer ([A-Za-z0-9_-]{43})$/i.exec(request.headers.get("authorization") ?? "");
  if (!match) throw new AuthError("invalid_token", 401);
  return match[1]!;
}

export async function invokeAuth(auth: Auth, operation: string, input: unknown, request: Request, browser?: BrowserRequest & {headers: Headers}): Promise<unknown> {
  const removed = /^auth\.browser_(signup|signin|identity|session|logout)$/.exec(operation);
  if (removed) {
    const error = new AuthError("auth_operation_removed", 400);
    error.message = `${operation} was removed; use auth.${removed[1]}.`;
    throw error;
  }
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new AuthError("invalid_input", 400);
  const value = input as Record<string, unknown>;
  const text = (key: string): string => {
    if (typeof value[key] !== "string") throw new AuthError("invalid_input", 400);
    return value[key];
  };
  const inviteCode = (): string => Object.hasOwn(value, "invite_code") ? text("invite_code") : "";
  const managementToken = (): string => {
    if (browser) return browser.credential;
    if (!request.headers.has("authorization")) throw new AuthError("unauthenticated", 401);
    return bearer(request);
  };
  if (browser && !operation.startsWith("auth.invite_")) {
    let result: BrowserSession;
    switch (operation) {
      case "auth.signup": result = await auth.signup(text("email"), text("password"), inviteCode(), "browser", browser.credential); break;
      case "auth.signin": result = await auth.signin(text("email"), text("password"), "browser", browser.credential); break;
      case "auth.identity": result = await auth.signinIdentity(text("provider"), value.credential, inviteCode(), "browser", browser.credential); break;
      case "auth.session": return browserInfo(await auth.session(browser.credential, "browser"));
      case "auth.logout":
        await auth.logout(browser.credential, "browser");
        browser.headers.set("set-cookie", browserCookie(browser.cookieName, "", 0));
        return {status: "ok"};
      case "auth.refresh": throw new AuthError("invalid_input", 400);
      default: throw new AuthError("not_found", 404);
    }
    browser.headers.set("set-cookie", browserCookie(browser.cookieName, result.credential, result.cookieMaxAge));
    return browserInfo(result);
  }
  switch (operation) {
    case "auth.signup": return tokens(await auth.signup(text("email"), text("password"), inviteCode()));
    case "auth.signin": return tokens(await auth.signin(text("email"), text("password")));
    case "auth.refresh": return tokens(await auth.refresh(text("refresh_token")));
    case "auth.session": {
      const user = await auth.session(bearer(request));
      return browserInfo(user);
    }
    case "auth.logout": await auth.logout(bearer(request)); return {status: "ok"};
    case "auth.identity": return tokens(await auth.signinIdentity(text("provider"), value.credential, inviteCode()));
    case "auth.invite_issue": {
      const id = text("id"), email = text("email");
      const result = await auth.inviteIssue(managementToken(), id, email, browser ? "browser" : "native");
      return {...summary(result), code: result.code};
    }
    case "auth.invite_list": {
      const cursor = text("cursor");
      const result = await auth.inviteList(managementToken(), cursor, browser ? "browser" : "native");
      return {items: result.items.map(summary), next_cursor: result.nextCursor};
    }
    case "auth.invite_revoke": {
      const id = text("id");
      return auth.inviteRevoke(managementToken(), id, browser ? "browser" : "native");
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

export interface BrowserRequest {
  readonly credential: string;
  readonly cookieName: string;
}

/** Validates browser transport before any database or application effects. */
export function browserRequest(request: Request, projectId: string, origins: ReadonlySet<string>): BrowserRequest | undefined {
  const cookies = (request.headers.get("cookie") ?? "").split(";").map(item => item.trim());
  const marker = request.headers.get("x-chik-browser");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(projectId)) {
    if (marker === null && !cookies.some(item => item.split("=", 1)[0]!.startsWith("__Host-chik_session_"))) return undefined;
    throw new AuthError("service_unavailable", 503);
  }
  const cookieName = `__Host-chik_session_${projectId.toLowerCase()}`;
  const matches = cookies.filter(item => item.split("=", 1)[0] === cookieName);
  if (marker === null && matches.length === 0) return undefined;
  if (request.headers.has("authorization") || matches.length > 1) throw new AuthError("invalid_input", 400);
  if (marker !== "1" || !origins.has(request.headers.get("origin") ?? "") ||
      request.headers.get("sec-fetch-site") === "cross-site") throw new AuthError("origin_denied", 403);
  if (request.method !== "POST" || request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
    throw new AuthError("invalid_input", 400);
  }
  return {cookieName, credential: matches[0]?.slice(cookieName.length + 1) ?? ""};
}

export function browserCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

function browserInfo(value: {id: string; email: string; sessionId: string; expiresAt: string}) {
  return {id: value.id, email: value.email, session_id: value.sessionId, expires_at: value.expiresAt};
}
