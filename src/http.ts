import {createDevice, failure} from "./device.js";
import type {Device} from "./device.js";

export interface SessionRenewal {
  dueAt(): number | undefined;
  renew(): Promise<void>;
}

export interface Transport {
  invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown>;
  sessionRenewal?(): SessionRenewal | undefined;
}

const sessionRefreshes = new WeakMap<object, Map<string, Promise<string>>>();

export class OperationError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`Operation failed (${code}, HTTP ${status}).`);
    this.name = "OperationError";
  }
}

/** Authentication and device persistence settings for an operation transport. */
export interface TransportOptions {
  readonly token?: string;
  readonly persist?: false | {readonly dir: string};
  readonly timeout?: number;
}

function prepareDevice(transport: object, origin: string, configuration: ReturnType<typeof createDevice>, browser: boolean, token?: string) {
  try {
    const options = {persist: configuration.persist};
    let attached = false;
    for (const key of [Symbol.for("chickinfry.store.scope.v1"), Symbol.for("chickinfry.store.public.v1")]) {
      const descriptor = Object.getOwnPropertyDescriptor(transport, key);
      if (!descriptor) {if (Reflect.has(transport, key)) throw failure(); continue;}
      if (!("value" in descriptor) || descriptor.value === undefined) throw failure();
      Reflect.set(options, key, descriptor.value); attached = true;
    }
    if (!attached) return configuration;
    return createDevice(origin, options, browser, token, configuration);
  } catch {throw failure();}
}

export type ClientErrorCode = "invalid_argument" | "failed_precondition" | "resource_exhausted" |
  "deadline_exceeded" | "canceled" | "unavailable" | "data_loss" | "unimplemented" |
  "internal" | "unknown" | "unauthenticated";

export class ClientError extends Error {
  constructor(readonly code: ClientErrorCode, readonly status?: number, readonly outcomeUnknown = false) {
    super(`Client failed (${code}${status === undefined ? "" : `, HTTP ${status}`}).`);
    this.name = "ClientError";
  }
}

export class HttpTransport implements Transport {
  private readonly origin: string;
  private sessionStore: SessionStore | undefined;
  private renewal: SessionRenewal | undefined;
  private refreshes = new Map<string, Promise<string>>();
  private readonly token: string | undefined;
  private readonly timeout: number;
  private device: Device | undefined;
  private configuration: ReturnType<typeof createDevice>;

  constructor(origin: string, token?: string, options?: Pick<TransportOptions, "timeout">);
  constructor(origin: string, options?: TransportOptions);
  constructor(origin: string, tokenOrOptions?: string | TransportOptions, timeoutOptions: Pick<TransportOptions, "timeout"> = {}) {
    if (tokenOrOptions !== undefined && typeof tokenOrOptions !== "string" &&
        (typeof tokenOrOptions !== "object" || tokenOrOptions === null || Array.isArray(tokenOrOptions))) throw new ClientError("invalid_argument");
    const options = typeof tokenOrOptions === "object" && tokenOrOptions !== null ? tokenOrOptions : {};
    const token = typeof tokenOrOptions === "string" ? tokenOrOptions : options.token;
    if (token !== undefined && !validToken(token)) throw new ClientError("invalid_argument");
    this.token = token;
    this.timeout = timeoutMilliseconds(timeoutOptions.timeout ?? options.timeout);
    this.origin = operationOrigin(origin);
    this.configuration = createDevice(this.origin, options, false, token);
    this.device = this.configuration.device;
  }

  withBearer(token: string): HttpTransport {
    const copy = new HttpTransport(this.origin, token, {timeout:this.timeout});
    copy.sessionStore = undefined;
    return copy;
  }

  withSession(store: SessionStore): HttpTransport {
    const credentials = sessionCredentials(store);
    if (!validToken(credentials.accessToken) || !validToken(credentials.refreshToken)) {
      throw new ClientError("unauthenticated");
    }
    const copy = this.withBearer(credentials.accessToken);
    copy.refreshes = sessionRefreshes.get(store) ?? new Map();
    sessionRefreshes.set(store, copy.refreshes);
    copy.sessionStore = store;
    return copy;
  }

  sessionRenewal(): SessionRenewal | undefined {
    const store = this.sessionStore;
    if (!store) return undefined;
    return this.renewal ??= {
      dueAt: () => {
        const expiresAt = Date.parse(sessionCredentials(store).expiresAt);
        if (!Number.isFinite(expiresAt)) throw new Error("Invalid session expiry.");
        return expiresAt;
      },
      renew: async () => { await this.refreshSession(store, {...sessionCredentials(store)}); },
    };
  }

  async invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown> {
    this.configuration = prepareDevice(this, this.origin, this.configuration, false, this.token);
    this.device = this.configuration.device;
    if (this.device) return withResponseStatus(received => this.device!.invoke(operation, input,
      (operation, input, token, _anonymous, responseStatus) => this.invokeOnce(operation, input, token, status => { received(status); responseStatus?.(status); }),
      this.configuration.publicOperations?.includes(operation)));
    const store = this.sessionStore;
    if (!store) return this.invokeOnce(operation, input, this.token);
    let credentials = {...sessionCredentials(store)};
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
      credentials = {...sessionCredentials(store)};
      assertSession(expected, credentials);
    }
    try {
      return await this.invokeOnce(operation, input, credentials.accessToken);
    } catch (error) {
      if (!(error instanceof OperationError) || error.status !== 401 || error.code !== "invalid_token") throw error;
      await this.refreshSession(store, credentials);
      credentials = sessionCredentials(store);
      assertSession(expected, credentials);
      return this.invokeOnce(operation, input, credentials.accessToken);
    }
  }

  private async refreshSession(store: SessionStore, failed: SessionCredentials): Promise<SessionCredentials> {
    let current = {...sessionCredentials(store)};
    assertSession(failed, current);
    if (current.accessToken !== failed.accessToken) return current;
    const refreshToken = current.refreshToken;
    let expected = current;
    let flight = this.refreshes.get(refreshToken);
    if (!flight) {
      let responseError: unknown;
      let refreshSent = false;
      flight = Promise.resolve().then(async () => {
        try {
          const refreshed = await store.refresh(async latest => {
            assertSession(failed, latest);
            expected = {...latest};
            if (latest.accessToken !== failed.accessToken) return latest;
            const shared = this.refreshes.get(latest.refreshToken);
            if (shared && shared !== flight) throw new ClientError("unauthenticated");
            refreshSent = true;
            return withResponseStatus(async received => {
              const value = await this.invokeOnce("auth.refresh", {refresh_token: latest.refreshToken}, undefined, received)
                .catch(error => { responseError = error; throw error; });
              return readCredentials(value);
            });
          });
          return refreshed.accessToken;
        } catch (error) {
          const shared = this.refreshes.get(expected.refreshToken);
          if (shared && shared !== flight && !refreshSent) return await shared;
          return await this.#refreshFailed(store, expected, expected.refreshToken, error instanceof ClientError || error === responseError ? error : new ClientError("failed_precondition", undefined, true), error === responseError);
        } finally {
          // Credentials with unknown consumption state are not sent again until a fresh sign-in or explicit recovery.
          if (this.refreshes.get(refreshToken) === flight) this.refreshes.delete(refreshToken);
        }
      });
      this.refreshes.set(refreshToken, flight);
    }
    await flight;
    current = sessionCredentials(store);
    assertSession(failed, current);
    return current;
  }

  async #refreshFailed(store: SessionStore, expected: SessionCredentials, refreshToken: unknown,
    error: unknown, fromResponse: boolean): Promise<never> {
    if (!fromResponse || !(error instanceof OperationError) || error.status !== 401) {
      const failure = error instanceof ClientError ? error : new ClientError("unauthenticated", error instanceof OperationError ? error.status : undefined, true);
      if (typeof refreshToken === "string") {
        const blocked = Promise.reject<string>(new ClientError("unauthenticated"));
        void blocked.catch(() => {});
        this.refreshes.set(refreshToken, blocked);
      }
      try { if (refreshToken === expected.refreshToken) await store.clear(expected); }
      finally { throw failure; }
    }
    if (error.status === 401 && refreshToken === expected.refreshToken) {
      try { await store.clear(expected); }
      catch { throw new ClientError("failed_precondition", error.status); }
    }
    throw error;
  }

  private async invokeOnce(operation: string, input: Readonly<Record<string, unknown>>, token: string | undefined, received?: (status: number) => void): Promise<unknown> {
    const headers = new Headers({"content-type": "application/json"});
    if (token !== undefined) headers.set("authorization", "Bearer " + token);
    return invokeHTTP(this.origin, operation, input, headers, "omit", this.timeout, received);
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

/** Keeps session credentials in memory and ignores stale refresh and cleanup results. */
export class MemoryStore implements SessionStore {
  private current: SessionCredentials | undefined;
  constructor(credentials?: SessionCredentials) {
    if (credentials !== undefined) {
      if (!validToken(credentials.accessToken) || !validToken(credentials.refreshToken)) throw new ClientError("invalid_argument");
      this.current = {...credentials};
    }
  }
  credentials(): SessionCredentials {
    if (!this.current) throw new ClientError("unauthenticated");
    return {...this.current};
  }
  async refresh(operation: (credentials: SessionCredentials) => Promise<SessionCredentials>): Promise<SessionCredentials> {
    const expected = this.current;
    const refreshed = await operation(this.credentials());
    if (this.current !== expected) throw new ClientError("failed_precondition");
    assertSession(expected!, refreshed);
    this.current = {...refreshed};
    return this.credentials();
  }
  async clear(expected: SessionCredentials): Promise<void> {
    const current = this.current;
    if (current && current.userId === expected.userId && current.sessionId === expected.sessionId &&
        current.accessToken === expected.accessToken && current.refreshToken === expected.refreshToken) this.current = undefined;
  }
}

function sessionCredentials(store: SessionStore): SessionCredentials {
  try { return store.credentials(); }
  catch (error) { throw error instanceof ClientError ? error : new ClientError("failed_precondition"); }
}

async function withResponseStatus<T>(work: (received: (status: number) => void) => Promise<T>): Promise<T> {
  let status: number | undefined;
  try { return await work(value => { status = value; }); }
  catch (error) {
    if (error instanceof ClientError && error.code === "internal" && error.status === undefined && status !== undefined) {
      throw new ClientError(error.code, status, error.outcomeUnknown);
    }
    throw error;
  }
}

function timeoutMilliseconds(timeout = 30_000): number {
  if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 2_147_483_647) throw new ClientError("invalid_argument");
  return timeout;
}

function transportFailure(error: unknown, status?: number): ClientError {
  const code = error instanceof DOMException && error.name === "TimeoutError" ? "deadline_exceeded" :
    error instanceof DOMException && error.name === "AbortError" ? "canceled" : error instanceof TypeError ? "unavailable" : "unknown";
  return new ClientError(code, status, true);
}

function validToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

function assertSession(expected: SessionCredentials, current: SessionCredentials): void {
  if (current.userId !== expected.userId || current.sessionId !== expected.sessionId ||
      !validToken(current.accessToken) || !validToken(current.refreshToken)) {
    throw new ClientError("unauthenticated");
  }
}

function readCredentials(value: unknown): SessionCredentials {
  if (typeof value !== "object" || value === null) throw new ClientError("internal", undefined, true);
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
    throw new ClientError("internal", undefined, true);
  }
  return {accessToken,refreshToken,expiresAt,refreshExpiresAt,userId,sessionId};
}

/** Cookie-only transport with no token storage, refresh, or operation replay. */
export class BrowserHttpTransport implements Transport {
  private readonly origin: string;
  private device: Device | undefined;
  private configuration: ReturnType<typeof createDevice>;
  constructor(origin: string);
  constructor(origin: string, options?: Omit<TransportOptions, "token">);
  constructor(origin: string, private readonly options: Omit<TransportOptions, "token"> = {}) {
    timeoutMilliseconds(options.timeout);
    this.origin = operationOrigin(origin);
    this.configuration = createDevice(this.origin, options, true, Reflect.get(options, "token"));
    this.device = this.configuration.device;
  }
  async invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown> {
    this.configuration = prepareDevice(this, this.origin, this.configuration, true);
    this.device = this.configuration.device;
    if (this.device) return withResponseStatus(received => this.device!.invoke(operation, input,
      (operation, input, _token, anonymous, responseStatus) => this.invokeOnce(operation, input, anonymous, status => { received(status); responseStatus?.(status); }),
      this.configuration.publicOperations?.includes(operation)));
    return this.invokeOnce(operation, input);
  }
  private invokeOnce(operation: string, input: Readonly<Record<string, unknown>>, anonymous = false, received?: (status: number) => void): Promise<unknown> {
    return invokeHTTP(this.origin, operation, input,
      new Headers({"content-type": "application/json", "x-chik-browser": "1"}), anonymous ? "omit" : "include", this.options.timeout, received);
  }
}

function operationOrigin(origin: string): string {
    // Check the raw host before the URL parser normalizes non-canonical IPv4.
    const host = /^[a-z][a-z\d+.-]*:\/\/(\[[^\]]+\]|[^:/\\?#@]+)(?::\d+)?(?:\/|$)/i.exec(origin)?.[1];
    const octets = host?.split(".");
    const loopback = host === "[::1]" || (octets?.length === 4 && octets[0] === "127" &&
      octets.every(octet => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255));
    let url: URL;
    try { url = new URL(origin); }
    catch { throw new ClientError("invalid_argument"); }
    const secure = url.protocol === "https:" || (url.protocol === "http:" && loopback);
    if (!secure || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new ClientError("invalid_argument");
    }
    return url.origin;
}

async function invokeHTTP(origin: string, operation: string, input: Readonly<Record<string, unknown>>,
  headers: Headers, credentials: RequestCredentials, timeout?: number, received?: (status: number) => void): Promise<unknown> {
    if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(operation)) {
      throw new ClientError("invalid_argument");
    }
    let body: string;
    try { body = JSON.stringify(input); }
    catch { throw new ClientError("invalid_argument"); }
    if (typeof body !== "string") throw new ClientError("invalid_argument");
    if (new TextEncoder().encode(body).byteLength > 4 << 20) throw new ClientError("resource_exhausted");
    if (typeof fetch !== "function" || typeof globalThis.AbortSignal?.timeout !== "function") throw new ClientError("unimplemented");
    let response: Response;
    try { response = await fetch(`${origin}/${operation}`, {
      method: "POST", headers, body, credentials, cache: "no-store",
      redirect: "manual", signal: AbortSignal.timeout(timeoutMilliseconds(timeout)),
    }); } catch (error) { throw transportFailure(error); }
    if (response.status > 0) received?.(response.status);
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      await response.body?.cancel().catch(() => {});
      throw new ClientError("internal", response.status || undefined, true);
    }
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read().catch(error => { throw transportFailure(error, response.status); });
        if (done) break;
        size += value.byteLength;
        if (size > 1 << 20) {
          await reader.cancel().catch(() => {});
          throw new ClientError("resource_exhausted", response.status, true);
        }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    let value: unknown;
    try { value = JSON.parse(new TextDecoder().decode(bytes)); }
    catch { throw new ClientError("internal", response.status, true); }
    if (!response.ok) {
      const code = typeof value === "object" && value !== null && "error" in value ? value.error : undefined;
      if (typeof code !== "string" || /^[a-z_]+$/.exec(code)?.[0] !== code) throw new ClientError("internal", response.status, true);
      throw new OperationError(code, response.status);
    }
    return value;
}
