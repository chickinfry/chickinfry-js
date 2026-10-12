export interface ClientTransport {
  invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown>;
}

const sessionRefreshes = new WeakMap<object, Map<string, Promise<string>>>();

export class OperationError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`Operation failed (${code}, HTTP ${status}).`);
    this.name = "OperationError";
  }
}

export class HTTP implements ClientTransport {
  private readonly origin: string;
  private sessionStore: SessionStore | undefined;
  private refreshes = new Map<string, Promise<string>>();

  constructor(origin: string, private readonly token?: string) {
    if (token !== undefined && !validToken(token)) throw new Error("Invalid access token.");
    this.origin = operationOrigin(origin);
  }

  withBearer(token: string): HTTP {
    const copy = new HTTP(this.origin, token);
    copy.sessionStore = undefined;
    return copy;
  }

  withSession(store: SessionStore): HTTP {
    const credentials = store.credentials();
    if (!validToken(credentials.accessToken) || !validToken(credentials.refreshToken)) {
      throw new Error("Invalid session credential.");
    }
    const copy = this.withBearer(credentials.accessToken);
    copy.refreshes = sessionRefreshes.get(store) ?? new Map();
    sessionRefreshes.set(store, copy.refreshes);
    copy.sessionStore = store;
    return copy;
  }

  async invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown> {
    const store = this.sessionStore;
    if (!store) return this.invokeOnce(operation, input, this.token);
    let credentials = store.credentials();
    const token = operation === "auth.refresh" ? undefined : credentials.accessToken;
    try {
      return await this.invokeOnce(operation, input, token);
    } catch (error) {
      if (operation === "auth.refresh" || !(error instanceof OperationError) || error.status !== 401 || error.code !== "invalid_token") throw error;
      credentials = await this.refreshSession(store, credentials.accessToken);
      return this.invokeOnce(operation, input, credentials.accessToken);
    }
  }

  private async refreshSession(store: SessionStore, failedAccessToken: string): Promise<SessionCredentials> {
    let current = store.credentials();
    if (current.accessToken !== failedAccessToken) return current;
    const refreshToken = current.refreshToken;
    let expected = current;
    let flight = this.refreshes.get(refreshToken);
    if (!flight) {
      flight = (async () => {
        try {
          const refreshed = await store.refresh(async latest => {
            expected = latest;
            if (latest.accessToken !== failedAccessToken) return latest;
            const value = await this.invokeOnce("auth.refresh", {refresh_token: latest.refreshToken}, undefined) as Record<string,unknown>;
            return readCredentials(value);
          });
          return refreshed.accessToken;
        } catch (error) {
          if (error instanceof OperationError && error.status === 401) await store.clear(expected);
          throw error;
        } finally {
          this.refreshes.delete(refreshToken);
        }
      })();
      this.refreshes.set(refreshToken, flight);
    }
    await flight;
    current = store.credentials();
    if (!validToken(current.accessToken)) throw new Error("Invalid refreshed session credential.");
    return current;
  }

  private async invokeOnce(operation: string, input: Readonly<Record<string, unknown>>, token: string | undefined): Promise<unknown> {
    const headers = new Headers({"content-type": "application/json"});
    if (token !== undefined) headers.set("authorization", "Bearer " + token);
    return invokeHTTP(this.origin, operation, input, headers, "omit");
  }
}

export interface SessionCredentials {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresAt: string;
  readonly refreshExpiresAt: string;
  readonly userId: string;
  readonly sessionId: string;
}

export interface SessionStore {
  credentials(): SessionCredentials;
  refresh(operation: (credentials: SessionCredentials) => Promise<SessionCredentials>): Promise<SessionCredentials>;
  clear(expected: SessionCredentials): Promise<void>;
}

function validToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

function readCredentials(value: unknown): SessionCredentials {
  if (typeof value !== "object" || value === null) throw new Error("Invalid refresh response.");
  const record = value as Record<string,unknown>;
  const accessToken = record.access_token;
  const refreshToken = record.refresh_token;
  const expiresAt = record.expires_at;
  const refreshExpiresAt = record.refresh_expires_at;
  const userId = record.user_id;
  const sessionId = record.session_id;
  if (typeof accessToken !== "string" || typeof refreshToken !== "string" || !validToken(accessToken) || !validToken(refreshToken) ||
      typeof expiresAt !== "string" || typeof refreshExpiresAt !== "string" || typeof userId !== "string" || typeof sessionId !== "string" ||
      expiresAt === "" || refreshExpiresAt === "" || userId === "" || sessionId === "") {
    throw new Error("Invalid refresh response.");
  }
  return {accessToken,refreshToken,expiresAt,refreshExpiresAt,userId,sessionId};
}

/** Cookie-only transport with no refresh, credential storage, or replay. */
export class BrowserHTTP implements ClientTransport {
  private readonly origin: string;
  constructor(origin: string) { this.origin = operationOrigin(origin); }
  invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown> {
    return invokeHTTP(this.origin, operation, input,
      new Headers({"content-type": "application/json", "x-chik-browser": "1"}), "include");
  }
}

function operationOrigin(origin: string): string {
    let url: URL;
    try { url = new URL(origin); }
    catch { throw new Error("Invalid operation endpoint."); }
    const loopback = url.hostname === "localhost" || url.hostname === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(url.hostname);
    const secure = url.protocol === "https:" || (url.protocol === "http:" && loopback);
    if (!secure || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error("Operation endpoint must be an HTTPS or loopback HTTP origin.");
    }
    return url.origin;
}

async function invokeHTTP(origin: string, operation: string, input: Readonly<Record<string, unknown>>,
  headers: Headers, credentials: RequestCredentials): Promise<unknown> {
    if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(operation)) {
      throw new Error("Invalid operation name.");
    }
    const body = JSON.stringify(input);
    if (new TextEncoder().encode(body).byteLength > 4 << 20) throw new Error("Operation request is too large.");
    const response = await fetch(`${origin}/${operation}`, {
      method: "POST", headers, body, credentials, cache: "no-store",
      redirect: "manual", signal: AbortSignal.timeout(30_000),
    });
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel();
      throw new OperationError("redirect_not_allowed", response.status);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 1 << 20) {
          await reader.cancel();
          throw new Error("Operation response is too large.");
        }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let value: unknown;
    try { value = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw new OperationError("invalid_response", response.status); }
    if (!response.ok) {
      const code = typeof value === "object" && value !== null && "error" in value ? value.error : undefined;
      throw new OperationError(typeof code === "string" && /^[a-z_]+$/.test(code) ? code : "operation_failed", response.status);
    }
    return value;
}
