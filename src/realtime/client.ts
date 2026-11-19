import type {ClientErrorCode, Transport} from "../http.js";
import { BrowserHttpTransport, ClientError, HttpTransport, OperationError } from "../http.js";
import { parseServerFrame, validChannel } from "./protocol.js";

export interface SessionRenewal {
  dueAt(): number | undefined;
  renew(): Promise<void>;
}

export interface RealtimeTransport extends Transport {
  sessionRenewal?(): SessionRenewal | undefined;
}

const transportRenewals = new WeakMap<HttpTransport, SessionRenewal>();

export function sessionRenewal(transport: RealtimeTransport): SessionRenewal | undefined {
  if (transport.sessionRenewal !== undefined) return transport.sessionRenewal();
  if (!(transport instanceof HttpTransport)) return undefined;
  // This private package shares its checkout's refresh path without adding public transport members.
  const store = transport["sessionStore"];
  if (!store) return undefined;
  let renewal = transportRenewals.get(transport);
  if (renewal === undefined) {
    const credentials = () => {
      try { return store.credentials(); }
      catch (error) { throw error instanceof ClientError ? error : new ClientError("failed_precondition"); }
    };
    renewal = {
      dueAt: () => {
        const expiresAt = Date.parse(credentials().expiresAt);
        if (!Number.isFinite(expiresAt)) throw new Error("Invalid session expiry.");
        return expiresAt;
      },
      renew: async () => { await transport["refreshSession"](store, {...credentials()}); },
    };
    transportRenewals.set(transport, renewal);
  }
  return renewal;
}

export interface RealtimeEvent {
  readonly type: "event";
  readonly channel: string;
  readonly payload: unknown;
}

export interface RealtimeGap {
  readonly type: "gap";
  readonly channel: string;
}

export type GapHandler = (gap: RealtimeGap) => Promise<void>;

export interface SubscribeOptions {
  readonly onGap?: GapHandler;
}

export interface RealtimeSubscription {
  readonly events: AsyncIterable<RealtimeEvent>;
  unsubscribe(): Promise<void>;
}

export interface RealtimeClient {
  subscribe(channel: string, options?: SubscribeOptions): Promise<RealtimeSubscription>;
}

const ticketPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const defaultEndpointDomain = "chickinfry.app";
const isolatedEndpointDomain = "chickinfry.io";

function endpointDomain(transport: Transport): string {
  const origin = transport instanceof HttpTransport ? transport["origin"] :
    transport instanceof BrowserHttpTransport ? transport["origin"] : undefined;
  const prefix = "https://";
  const suffix = `.${isolatedEndpointDomain}`;
  // Anchor the isolated ticket to its own HTTPS issuer before forwarding it to a socket.
  if (origin?.startsWith(prefix) && origin.endsWith(suffix) &&
      ticketPattern.test(origin.slice(prefix.length, -suffix.length))) return isolatedEndpointDomain;
  return defaultEndpointDomain;
}

interface SharedRenewal {
  readonly watchers: Set<(error: unknown) => void>;
  timeout: ReturnType<typeof setTimeout> | undefined;
  renewing: boolean;
}

// Renew before expiry using the request budget and reauthentication margin.
const renewalMarginMs = 60_000;
const maxTimeoutMs = 2_147_000_000;
const sharedRenewals = new WeakMap<SessionRenewal, SharedRenewal>();

function scheduleRenewal(renewal: SessionRenewal, shared: SharedRenewal): void {
  const expiresAt = renewal.dueAt();
  if (expiresAt === undefined) return;
  shared.timeout = setTimeout(async () => {
    shared.timeout = undefined;
    try {
      const dueAt = renewal.dueAt();
      if (dueAt !== undefined && dueAt - renewalMarginMs - Date.now() > 0) {
        scheduleRenewal(renewal, shared);
        return;
      }
      shared.renewing = true;
      await renewal.renew();
      shared.renewing = false;
      if (shared.watchers.size !== 0) scheduleRenewal(renewal, shared);
      else if (sharedRenewals.get(renewal) === shared) sharedRenewals.delete(renewal);
    } catch (error) {
      shared.renewing = false;
      if (sharedRenewals.get(renewal) === shared) sharedRenewals.delete(renewal);
      const watchers = [...shared.watchers];
      shared.watchers.clear();
      for (const watcher of watchers) watcher(error);
    }
  }, Math.min(Math.max(expiresAt - renewalMarginMs - Date.now(), 0), maxTimeoutMs));
}

export function createRealtimeClient(transport: RealtimeTransport): RealtimeClient {
  const renewal = sessionRenewal(transport);
  return {
    async subscribe(channel, options) {
      if (!validChannel(channel) || (options !== undefined && (typeof options !== "object" || options === null ||
          Array.isArray(options) || Object.keys(options).some(key => key !== "onGap") ||
          (options.onGap !== undefined && typeof options.onGap !== "function")))) throw new ClientError("invalid_argument");
      return subscribe(transport, channel, options?.onGap, renewal);
    },
  };
}

async function subscribe(transport: Transport, channel: string, onGap: GapHandler | undefined, renewal: SessionRenewal | undefined): Promise<RealtimeSubscription> {
  const domain = endpointDomain(transport);
  const subscription = crypto.randomUUID();
  const queue: import("./protocol.js").RealtimeEventFrame[] = [];
  const pending = new Set<() => void>();
  let socket: WebSocket | undefined;
  let disconnect: (() => void) | undefined;
  let cancelRetry: (() => void) | undefined;
  let last = "";
  let checkpoint: string | undefined;
  let active = true;
  let prepared = false;
  let initialReady = false;
  let failure: unknown;
  let failureDelivered = false;
  let connectionGeneration = 0;
  let recovery: {cursor: string; complete: boolean; connection?: number} | undefined;
  let callbackRunning = false;
  let demand = false;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  let sharedRenewal: SharedRenewal | undefined;
  let resolveReady!: () => void;
  let rejectReady!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  let resolveStopped!: () => void;
  const stopped = new Promise<void>(resolve => { resolveStopped = resolve; });

  function wake(): void {
    for (const resolve of pending) resolve();
    pending.clear();
  }
  function budget(): void {
    deadline ??= setTimeout(() => stop(new ClientError("deadline_exceeded")), 30_000);
  }
  function closeConnection(): void {
    const ws = socket;
    socket = undefined;
    prepared = false;
    checkpoint = undefined;
    disconnect?.();
    disconnect = undefined;
    try { ws?.close(); } catch { }
  }
  function stop(error?: unknown): void {
    if (!active) return;
    active = false;
    failure = error;
    recovery = undefined;
    queue.length = 0;
    clearTimeout(deadline);
    deadline = undefined;
    cancelRetry?.();
    closeConnection();
    resolveStopped();
    rejectReady(error ?? new ClientError("canceled"));
    if (renewal !== undefined && sharedRenewal !== undefined) {
      sharedRenewal.watchers.delete(stop);
      if (sharedRenewal.watchers.size === 0) {
        clearTimeout(sharedRenewal.timeout);
        sharedRenewal.timeout = undefined;
        if (!sharedRenewal.renewing && sharedRenewals.get(renewal) === sharedRenewal) sharedRenewals.delete(renewal);
      }
      sharedRenewal = undefined;
    }
    wake();
  }
  function acknowledge(): void {
    if (!prepared || recovery !== undefined || checkpoint === undefined || queue.length !== 0 || socket?.readyState !== WebSocket.OPEN) return;
    try { socket.send(JSON.stringify({type: "ack", channel, cursor: checkpoint})); } catch { }
    checkpoint = undefined;
  }
  function recover(): void {
    if (!active || callbackRunning || recovery === undefined || recovery.complete || (initialReady && !demand)) return;
    const generation = recovery;
    callbackRunning = true;
    // Demand is the sequential consumer's completion boundary for its previous event.
    void Promise.resolve().then(() => {
      if (active && recovery === generation) return onGap!({type: "gap", channel});
    }).then(() => {
      if (!active || recovery !== generation) return;
      generation.complete = true;
      last = generation.cursor;
      queue.length = 0;
      // Replay after the snapshot, even if a connection became ready during the callback.
      closeConnection();
    }, cause => {
      if (!active || recovery !== generation) return;
      const error = new ClientError("unknown");
      Object.defineProperty(error, "cause", {value: cause, configurable: true, writable: true});
      stop(error);
    }).finally(() => {
      callbackRunning = false;
      recover();
      wake();
    });
  }
  function gap(cursor: string): void {
    if (onGap === undefined) return stop(new ClientError("data_loss"));
    recovery = {cursor, complete: false};
    prepared = false;
    queue.length = 0;
    budget();
    recover();
    wake();
  }
  function retry(ms: number): Promise<void> {
    return new Promise(resolve => {
      const timer = setTimeout(finish, ms);
      function finish(): void { clearTimeout(timer); cancelRetry = undefined; resolve(); }
      cancelRetry = finish;
    });
  }
  function connect(address: string): {opened: Promise<void>; closed: Promise<void>} {
    const ws = new WebSocket(address);
    const generation = ++connectionGeneration;
    socket = ws;
    prepared = false;
    if (recovery?.complete) recovery.connection = generation;
    let resolveOpen!: () => void;
    let rejectOpen!: (error: unknown) => void;
    let resolveClosed!: () => void;
    const opened = new Promise<void>((resolve, reject) => { resolveOpen = resolve; rejectOpen = reject; });
    const closed = new Promise<void>(resolve => { resolveClosed = resolve; });
    const timeout = setTimeout(() => {
      if (socket === ws) closeConnection();
    }, 10_000);
    disconnect = () => {
      clearTimeout(timeout);
      rejectOpen(new ClientError("unavailable"));
      resolveClosed();
    };
    let confirmation: string | undefined;
    ws.onopen = () => {
      if (!active || socket !== ws) return;
      clearTimeout(timeout);
      resolveOpen();
    };
    ws.onmessage = event => {
      if (!active || socket !== ws) return;
      const frame = parseServerFrame(typeof event.data === "string" ? event.data : "");
      if (frame === undefined || (frame.channel !== undefined && frame.channel !== channel)) return stop(new ClientError("internal"));
      if (frame.type === "ready") {
        checkpoint = frame.acknowledge === true ? frame.cursor : undefined;
        if (frame.confirmation === undefined) {
          if (confirmation === undefined) {
            confirmation = crypto.randomUUID();
            try { ws.send(JSON.stringify({type: "confirm", channel, confirmation})); }
            catch { closeConnection(); budget(); }
          }
          return;
        }
        if (confirmation === undefined || frame.confirmation !== confirmation) return;
        if (recovery !== undefined) {
          if (!recovery.complete || recovery.connection !== generation) return;
          recovery = undefined;
        }
        prepared = true;
        initialReady = true;
        clearTimeout(deadline);
        deadline = undefined;
        resolveReady();
        acknowledge();
        wake();
        return;
      }
      if (frame.type === "gap") return gap(frame.cursor);
      if (frame.type === "event") {
        if (frame.cursor === last || queue.some(message => message.cursor === frame.cursor)) return;
        const previous = queue.at(-1)?.cursor ?? recovery?.cursor ?? last;
        if (frame.previous !== previous || queue.length >= 256) return gap(frame.cursor);
        queue.push(frame);
        wake();
        return;
      }
      const codes: Record<string, ClientErrorCode> = {
        unauthorized_channel: "permission_denied", already_subscribed: "internal",
        too_many_channels: "resource_exhausted", replay_failed: "unavailable", realtime_unavailable: "unavailable",
      };
      stop(new ClientError(Object.hasOwn(codes, frame.error) ? codes[frame.error] : "unknown"));
    };
    ws.onclose = () => {
      if (socket !== ws) return;
      closeConnection();
      queue.length = 0;
      budget();
      wake();
    };
    ws.onerror = () => { };
    return {opened, closed};
  }
  async function run(): Promise<void> {
    let backoff = 500;
    while (active) {
      let response: Record<string, unknown>;
      let endpoint: string;
      try {
        response = await transport.invoke("realtime.ticket", {}) as Record<string, unknown>;
        if (!active) return;
        if (typeof response !== "object" || response === null || typeof response.ticket !== "string" || !ticketPattern.test(response.ticket)) throw new ClientError("internal");
        endpoint = realtimeEndpoint(response.endpoint, domain);
      } catch (error) {
        if (!active) return;
        if (initialReady && error instanceof OperationError && error.status === 409) return stop(error);
        const transient = error instanceof TypeError || (error instanceof Error && error.name === "TimeoutError") ||
          (error instanceof ClientError && (error.code === "unavailable" || error.code === "deadline_exceeded")) ||
          (error instanceof OperationError && (error.status === 409 || error.status === 429 || error.status >= 500));
        if (!transient) return stop(error instanceof ClientError || error instanceof OperationError ? error : new ClientError("internal"));
        await retry(backoff);
        backoff = Math.min(backoff * 2, 5000);
        continue;
      }
      try {
        const connection = connect(`${endpoint}?ticket=${response.ticket}`);
        await connection.opened;
        if (!active) return;
        socket?.send(JSON.stringify({type: "subscribe", channel, cursor: recovery?.cursor ?? last, subscription}));
        backoff = 500;
        await connection.closed;
      } catch {
        closeConnection();
      }
      if (active) {
        budget();
        await retry(backoff);
        backoff = Math.min(backoff * 2, 5000);
      }
    }
  }

  const iterator: AsyncIterator<RealtimeEvent> = {
    async next() {
      if (demand) throw new ClientError("failed_precondition");
      demand = true;
      try {
        while (true) {
          if (!active) {
            if (failure !== undefined && !failureDelivered) { failureDelivered = true; throw failure; }
            return {done: true, value: undefined};
          }
          if (recovery !== undefined) recover();
          else if (prepared && queue.length !== 0) {
            const event = queue.shift()!;
            last = event.cursor;
            acknowledge();
            return {done: false, value: {type: "event", channel, payload: event.payload}};
          }
          await new Promise<void>(resolve => pending.add(resolve));
        }
      } finally { demand = false; }
    },
    async return() { stop(); await running; return {done: true, value: undefined}; },
  };
  let consumed = false;
  const result: RealtimeSubscription = {
    events: {
      [Symbol.asyncIterator]() {
        if (consumed) throw new ClientError("failed_precondition");
        consumed = true;
        return iterator;
      },
    },
    async unsubscribe() { stop(); await running; },
  };
  budget();
  if (renewal !== undefined) {
    let shared = sharedRenewals.get(renewal);
    if (shared === undefined) {
      shared = {watchers: new Set(), timeout: undefined, renewing: false};
      sharedRenewals.set(renewal, shared);
    }
    shared.watchers.add(stop);
    sharedRenewal = shared;
    try { if (shared.timeout === undefined && !shared.renewing) scheduleRenewal(renewal, shared); }
    catch (error) { stop(error instanceof ClientError ? error : new ClientError("internal")); }
  }
  const running = Promise.race([run(), stopped]);
  await ready;
  return result;
}

/** Validates the product address before attaching a one-use ticket. */
export function realtimeEndpoint(value: unknown, domain = defaultEndpointDomain): string {
  if (typeof value !== "string") throw new ClientError("internal");
  let url: URL;
  try { url = new URL(value); } catch { throw new ClientError("internal"); }
  const suffix = `.${domain}`;
  if (url.protocol !== "wss:" || !url.hostname.endsWith(suffix) || !ticketPattern.test(url.hostname.slice(0, -suffix.length)) ||
      url.port || url.username || url.password || url.pathname !== "/realtime" || url.search || url.hash || url.href !== value) throw new ClientError("internal");
  return value;
}
