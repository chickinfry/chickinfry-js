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
    let credentials = {...store.credentials()};
    if (operation === "auth.refresh") {
      const refreshToken = input.refresh_token;
      try { return await this.invokeOnce(operation, input, undefined); }
      catch (error) { return this.#refreshFailed(store, credentials, refreshToken, error, true); }
    }
    const expected = credentials;
    assertSession(expected, credentials);
    const flight = this.refreshes.get(credentials.refreshToken);
    if (flight) {
      await flight;
      credentials = {...store.credentials()};
      assertSession(expected, credentials);
    }
    try {
      return await this.invokeOnce(operation, input, credentials.accessToken);
    } catch (error) {
      if (!(error instanceof OperationError) || error.status !== 401 || error.code !== "invalid_token") throw error;
      await this.refreshSession(store, credentials);
      credentials = store.credentials();
      assertSession(expected, credentials);
      return this.invokeOnce(operation, input, credentials.accessToken);
    }
  }

  private async refreshSession(store: SessionStore, failed: SessionCredentials): Promise<SessionCredentials> {
    let current = {...store.credentials()};
    assertSession(failed, current);
    if (current.accessToken !== failed.accessToken) return current;
    const refreshToken = current.refreshToken;
    let expected = current;
    let flight = this.refreshes.get(refreshToken);
    if (!flight) {
      let responseError: unknown;
      flight = Promise.resolve().then(async () => {
        try {
          const refreshed = await store.refresh(async latest => {
            assertSession(failed, latest);
            expected = {...latest};
            if (latest.accessToken !== failed.accessToken) return latest;
            const shared = this.refreshes.get(latest.refreshToken);
            if (shared && shared !== flight) throw new OperationError("invalid_token", 401);
            const value = await this.invokeOnce("auth.refresh", {refresh_token: latest.refreshToken}, undefined)
              .catch(error => { responseError = error; throw error; }) as Record<string,unknown>;
            return readCredentials(value);
          });
          return refreshed.accessToken;
        } catch (error) {
          const shared = this.refreshes.get(expected.refreshToken);
          if (shared && shared !== flight) return await shared;
          return await this.#refreshFailed(store, expected, expected.refreshToken, error, error === responseError);
        } finally {
          // 소비 여부가 불명인 자격은 새 로그인이나 명시적 복구 전까지 다시 보내지 않습니다.
          if (this.refreshes.get(refreshToken) === flight) this.refreshes.delete(refreshToken);
        }
      });
      this.refreshes.set(refreshToken, flight);
    }
    await flight;
    current = store.credentials();
    assertSession(failed, current);
    return current;
  }

  async #refreshFailed(store: SessionStore, expected: SessionCredentials, refreshToken: unknown,
    error: unknown, fromResponse: boolean): Promise<never> {
    if (!fromResponse || !(error instanceof OperationError) || error.status !== 401 || error.code === "invalid_response") {
      const failure = new OperationError("invalid_token", 401);
      if (typeof refreshToken === "string") {
        const blocked = Promise.reject<string>(failure);
        void blocked.catch(() => {});
        this.refreshes.set(refreshToken, blocked);
      }
      try { if (refreshToken === expected.refreshToken) await store.clear(expected); }
      finally { throw failure; }
    }
    if (error.status === 401 && refreshToken === expected.refreshToken) await store.clear(expected);
    throw error;
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

function assertSession(expected: SessionCredentials, current: SessionCredentials): void {
  if (current.userId !== expected.userId || current.sessionId !== expected.sessionId ||
      !validToken(current.accessToken) || !validToken(current.refreshToken)) {
    throw new OperationError("invalid_token", 401);
  }
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
    // URL 파서가 비정규 IPv4를 정규화하기 전에 원문 호스트를 검사합니다.
    const host = /^[a-z][a-z\d+.-]*:\/\/(\[[^\]]+\]|[^:/\\?#@]+)(?::\d+)?(?:\/|$)/i.exec(origin)?.[1];
    const octets = host?.split(".");
    const loopback = host === "[::1]" || (octets?.length === 4 && octets[0] === "127" &&
      octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255));
    let url: URL;
    try { url = new URL(origin); }
    catch { throw new Error("Invalid operation endpoint."); }
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
      throw new OperationError(typeof code === "string" && /^[a-z_]+$/.test(code) ? code : "invalid_response", response.status);
    }
    return value;
}
