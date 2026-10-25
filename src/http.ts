import {createDevice, failure} from "./device.js";
import type {Device} from "./device.js";

export interface ClientTransport {
  invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown>;
}

const sessionRefreshes = new WeakMap<object, Map<string, Promise<string>>>();

export class OperationError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(storageMessages[code] ?? `Operation failed (${code}, HTTP ${status}).`);
    this.name = "OperationError";
  }
}

const storageMessages: Readonly<Record<string, string>> = {
  device_storage_unavailable: "Could not use device storage for the session. Check that the storage location is writable, or set persist to another directory or turn it off.",
  device_storage_corrupt: "Stored session data could not be read. Sign out to clear it, then sign in again.",
  device_storage_full: "Device storage for sign-in is full. Finish or cancel pending sign-ups, then try again.",
  device_storage_version_unsupported: "Stored session data was written by a newer SDK. Update the SDK, or sign out and sign in again.",
};

/** Authentication and device persistence settings for an operation transport. */
export interface TransportOptions {
  readonly token?: string;
  readonly persist?: false | {readonly dir: string};
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

export class HTTP implements ClientTransport {
  private readonly origin: string;
  private sessionStore: SessionStore | undefined;
  private refreshes = new Map<string, Promise<string>>();
  private readonly token: string | undefined;
  private device: Device | undefined;
  private configuration: ReturnType<typeof createDevice>;

  constructor(origin: string, token?: string);
  constructor(origin: string, options?: TransportOptions);
  constructor(origin: string, tokenOrOptions?: string | TransportOptions) {
    if (tokenOrOptions !== undefined && typeof tokenOrOptions !== "string" &&
        (typeof tokenOrOptions !== "object" || tokenOrOptions === null || Array.isArray(tokenOrOptions))) throw new Error("Invalid access token.");
    const options = typeof tokenOrOptions === "object" && tokenOrOptions !== null ? tokenOrOptions : {};
    const token = typeof tokenOrOptions === "string" ? tokenOrOptions : options.token;
    if (token !== undefined && !validToken(token)) throw new Error("Invalid access token.");
    this.token = token;
    this.origin = operationOrigin(origin);
    this.configuration = createDevice(this.origin, options, false, token);
    this.device = this.configuration.device;
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
    this.configuration = prepareDevice(this, this.origin, this.configuration, false, this.token);
    this.device = this.configuration.device;
    if (this.device) return this.device.invoke(operation, input, (operation, input, token) => this.invokeOnce(operation, input, token),
      this.configuration.publicOperations?.includes(operation));
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
          // Credentials with unknown consumption state are not sent again until a fresh sign-in or explicit recovery.
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

/** Cookie-only transport with no token storage, refresh, or operation replay. */
export class BrowserHTTP implements ClientTransport {
  private readonly origin: string;
  private device: Device | undefined;
  private configuration: ReturnType<typeof createDevice>;
  constructor(origin: string);
  constructor(origin: string, options?: Omit<TransportOptions, "token">);
  constructor(origin: string, options: Omit<TransportOptions, "token"> = {}) {
    this.origin = operationOrigin(origin);
    this.configuration = createDevice(this.origin, options, true, Reflect.get(options, "token"));
    this.device = this.configuration.device;
  }
  async invoke(operation: string, input: Readonly<Record<string, unknown>>): Promise<unknown> {
    this.configuration = prepareDevice(this, this.origin, this.configuration, true);
    this.device = this.configuration.device;
    if (this.device) return this.device.invoke(operation, input, (operation, input, _token, anonymous) => this.invokeOnce(operation, input, anonymous),
      this.configuration.publicOperations?.includes(operation));
    return this.invokeOnce(operation, input);
  }
  private invokeOnce(operation: string, input: Readonly<Record<string, unknown>>, anonymous = false): Promise<unknown> {
    return invokeHTTP(this.origin, operation, input,
      new Headers({"content-type": "application/json", "x-chik-browser": "1"}), anonymous ? "omit" : "include");
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
