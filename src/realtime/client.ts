import type {Transport, SessionRenewal} from "../http.js";
import { ClientError, OperationError } from "../http.js";
import { parseServerFrame, validChannel, validCursor } from "./protocol.js";

export type RealtimeMessage =
  | { readonly type: "event"; readonly channel: string; readonly cursor: string; readonly previous: string; readonly payload: unknown }
  | { readonly type: "gap"; readonly channel: string; readonly cursor: string };

export class RealtimeError extends Error {
  constructor(readonly code: string, readonly channel?: string) {
    super(`Realtime subscription failed (${code}).`);
    this.name = "RealtimeError";
  }
}

export interface RealtimeSubscription extends AsyncIterable<RealtimeMessage> {
  readonly ready: Promise<void>;
  confirm(): Promise<void>;
  /**
   * Resumes from a caller-restored authoritative cursor. The subscription
   * identity is preserved and the gap clears only after a fresh ready echoes
   * a new confirmation nonce. Rejects when closed, already recovering, or
   * regapped, and when the recovery budget expires.
   */
  recover(cursor: string): Promise<void>;
  unsubscribe(): void;
}

export interface RealtimeClient {
  subscribe(channel: string, options?: { readonly cursor?: string }): RealtimeSubscription;
}

const ticketPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

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

export function createRealtimeClient(transport: Transport): RealtimeClient {
  const renewal = transport.sessionRenewal?.();
  return {
    subscribe(channel: string, options?: { readonly cursor?: string }): RealtimeSubscription {
      if (!validChannel(channel)) throw new Error("Invalid realtime channel.");
      if (options?.cursor !== undefined && !validCursor(options.cursor)) throw new Error("Invalid realtime cursor.");
      return subscribe(transport, channel, options?.cursor ?? "", renewal);
    },
  };
}

function subscribe(transport: Transport, channel: string, cursor: string, renewal: SessionRenewal | undefined): RealtimeSubscription {
  const subscription = crypto.randomUUID();
  const cursors = new Map<string, string>([[channel, cursor]]);
  const queue: RealtimeMessage[] = [];
  let socket: WebSocket | undefined;
  let socketReady = false;
  const pending: (() => void)[] = [];
  let failure: { error: unknown } | undefined;
  let active = true;
  let checkpoint: string | undefined;
  let recoveryGap = false;
  let backoff = 500;
  let resolveReady!: () => void;
  let rejectReady!: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  void ready.catch(() => undefined);
  const deadline = setTimeout(() => stop(new Error("Realtime subscription timed out.")),30_000);

  let confirmPending: { confirmation: string; timer: ReturnType<typeof setTimeout>; resolve: () => void; reject: (error: unknown) => void; sent: boolean } | undefined;
  let confirmInFlight: Promise<void> | undefined;
  const settleConfirm = (error?: unknown): void => {
    const pending = confirmPending;
    if (pending === undefined) return;
    confirmPending = undefined;
    confirmInFlight = undefined;
    clearTimeout(pending.timer);
    if (error === undefined) pending.resolve(); else pending.reject(error);
  };
  // The gateway drops confirmations until initial channel authorization completes.
  const sendConfirm = (): void => {
    const pending = confirmPending;
    if (pending === undefined || pending.sent) return;
    pending.sent = true;
    try { socket?.send(JSON.stringify({ type: "confirm", channel, confirmation: pending.confirmation })); }
    catch { settleConfirm(new RealtimeError("realtime_unavailable", channel)); }
  };
  const beginConfirm = (): { confirmation: string; sent: Promise<void> } => {
    const confirmation = crypto.randomUUID();
    let resolveCurrent!: () => void;
    let rejectCurrent!: (error: unknown) => void;
    const pendingPromise = new Promise<void>((resolve, reject) => { resolveCurrent = resolve; rejectCurrent = reject; });
    confirmPending = {
      confirmation,
      timer: setTimeout(() => settleConfirm(new RealtimeError("confirm_unavailable", channel)),30_000),
      resolve: resolveCurrent,
      reject: rejectCurrent,
      sent: false,
    };
    confirmInFlight = pendingPromise;
    return { confirmation, sent: pendingPromise };
  };
  const confirm = (): Promise<void> => {
    if (!active) return Promise.reject(failure !== undefined ? failure.error : new Error("Realtime subscription closed."));
    if (recoveryGap) return Promise.reject(new RealtimeError("gap", channel));
    if (confirmInFlight !== undefined) return confirmInFlight;
    if (socket?.readyState !== WebSocket.OPEN) return Promise.reject(new RealtimeError("realtime_unavailable", channel));
    const started = beginConfirm();
    if (socketReady) sendConfirm();
    return started.sent;
  };

  let recoveryRequest: { cursor: string; regapped: boolean; timer: ReturnType<typeof setTimeout>; resolve: () => void; reject: (error: unknown) => void } | undefined;
  let recoveryNonce: string | undefined;
  const settleRecovery = (error?: unknown): void => {
    const pending = recoveryRequest;
    if (pending === undefined) return;
    const ownedConfirmation = recoveryNonce;
    recoveryRequest = undefined;
    recoveryNonce = undefined;
    clearTimeout(pending.timer);
    if (error !== undefined) {
      // Finish only the recovery-owned confirmation so retries use a fresh nonce.
      if (ownedConfirmation !== undefined && confirmPending?.confirmation === ownedConfirmation) settleConfirm(error);
      return pending.reject(error);
    }
    recoveryGap = false;
    pending.resolve();
    acknowledge();
  };
  const recover = (cursor: string): Promise<void> => {
    if (!validCursor(cursor)) return Promise.reject(new Error("Invalid realtime cursor."));
    if (!active) return Promise.reject(failure !== undefined ? failure.error : new Error("Realtime subscription closed."));
    if (!recoveryGap) return Promise.reject(new Error("Realtime recovery requires a gap."));
    if (recoveryRequest !== undefined) return Promise.reject(new Error("Realtime recovery already in progress."));
    let resolveCurrent!: () => void;
    let rejectCurrent!: (error: unknown) => void;
    const pendingPromise = new Promise<void>((resolve, reject) => { resolveCurrent = resolve; rejectCurrent = reject; });
    recoveryRequest = {
      cursor,
      regapped: false,
      timer: setTimeout(() => settleRecovery(new RealtimeError("recovery_unavailable", channel)),30_000),
      resolve: resolveCurrent,
      reject: rejectCurrent,
    };
    recoveryNonce = undefined;
    cursors.set(channel, cursor);
    queue.length = 0;
    // Clear the current incarnation before CLOSING frames arrive; a late
    // onclose must still settle the closed promise and allow reconnection.
    const oldSocket = socket;
    socket = undefined;
    try { oldSocket?.close(); }
    catch { }
    return pendingPromise;
  };

  let sharedRenewal: SharedRenewal | undefined;
  const endFromRenewal = (error: unknown): void => stop(error);
  if (renewal !== undefined) {
    let shared = sharedRenewals.get(renewal);
    if (shared === undefined) {
      shared = { watchers: new Set(), timeout: undefined, renewing: false };
      sharedRenewals.set(renewal, shared);
    }
    shared.watchers.add(endFromRenewal);
    if (shared.timeout === undefined && !shared.renewing) scheduleRenewal(renewal, shared);
    sharedRenewal = shared;
  }

  const wake = (): void => {
    for (const settle of pending.splice(0)) settle();
  };

  const acknowledge = (): void => {
    if(recoveryGap || checkpoint === undefined || queue.length !== 0 || socket?.readyState !== WebSocket.OPEN)return;
    try { socket.send(JSON.stringify({type:"ack",channel,cursor:checkpoint})); }
    catch { }
    checkpoint=undefined;
  };

  const push = (message: RealtimeMessage): void => {
    if (message.type === "gap") settleConfirm(new RealtimeError("gap", channel));
    if (queue.length >= 256) {
      recoveryGap = true;
      if (recoveryRequest !== undefined) recoveryRequest.regapped = true;
      settleConfirm(new RealtimeError("gap", channel));
      queue.length = 0;
      queue.push({type:"gap",channel:message.channel,cursor:message.cursor});
      wake();
      return;
    }
    if(message.type === "gap"){
      recoveryGap = true;
      if (recoveryRequest !== undefined) recoveryRequest.regapped = true;
    }
    queue.push(message);
    wake();
  };

  const stop = (error?: unknown): void => {
    if (error !== undefined) failure ??= { error };
    active = false;
    clearTimeout(deadline);
    settleConfirm(error !== undefined ? error : new Error("Realtime subscription closed."));
    settleRecovery(error !== undefined ? error : new Error("Realtime subscription closed."));
    rejectReady(error ?? new Error("Realtime subscription closed."));
    try { socket?.close(); }
    catch { }
    if (renewal !== undefined && sharedRenewal !== undefined) {
      sharedRenewal.watchers.delete(endFromRenewal);
      if (sharedRenewal.watchers.size === 0) {
        if (sharedRenewal.timeout !== undefined) {
          clearTimeout(sharedRenewal.timeout);
          sharedRenewal.timeout = undefined;
        }
        if (!sharedRenewal.renewing && sharedRenewals.get(renewal) === sharedRenewal) sharedRenewals.delete(renewal);
      }
      sharedRenewal = undefined;
    }
    wake();
  };

  const run = async (): Promise<void> => {
    while (active) {
      let ticket: string;
      let endpoint: string;
      try {
        const response = await transport.invoke("realtime.ticket", {}) as Record<string, unknown>;
        if (typeof response !== "object" || response === null || typeof response.ticket !== "string" || !ticketPattern.test(response.ticket)) {
          throw new Error("Invalid realtime ticket.");
        }
        ticket = response.ticket;
        endpoint = realtimeEndpoint(response.endpoint);
      } catch (error) {
        const transient = error instanceof TypeError ||
          (error instanceof Error && error.name === "TimeoutError") ||
          (error instanceof ClientError && (error.code === "unavailable" || error.code === "deadline_exceeded")) ||
          (error instanceof OperationError && (error.status === 409 || error.status === 429 || error.status >= 500));
        if (transient && active) {
          await delay(backoff);
          backoff = Math.min(backoff*2,5000);
          continue;
        }
        return stop(error);
      }
      if (!active) return;
      const address = `${endpoint}?ticket=${ticket}`;
      try {
        await connect(address);
      } catch {
        await delay(backoff);
        backoff = Math.min(backoff * 2, 5000);
        continue;
      }
      backoff = 500;
      if (!active) return;
      for (const [name, last] of cursors) {
        try { socket?.send(JSON.stringify({ type: "subscribe", channel: name, cursor: last, subscription })); }
        catch { }
      }
      await connected;
      if (active) {
        await delay(backoff);
        backoff = Math.min(backoff * 2, 5000);
      }
    }
  };

  let connected = Promise.resolve();

  function connect(address: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(address);
      socket = ws;
      socketReady = false;
      let resolveClosed!: () => void;
      connected = new Promise<void>(resolve => { resolveClosed = resolve; });
      const timeout = setTimeout(() => {
        try { ws.close(); }
        catch { }
        reject(new Error("Realtime connection timed out."));
      }, 10_000);
      let settled = false;
      const close = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        reject(new Error("Realtime connection closed before opening."));
      };
      ws.onopen = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve();
      };
      ws.onmessage = event => {
        if (!active || socket !== ws) return;
        const frame = parseServerFrame(typeof event.data === "string" ? event.data : "");
        if (frame === undefined) return stop(new Error("Invalid realtime frame."));
        if (frame.channel !== undefined && frame.channel !== channel) return stop(new Error("Invalid realtime channel."));
        if (frame.type === "ready") {
          const recoveryEcho = recoveryRequest !== undefined && frame.confirmation !== undefined &&
            frame.confirmation === recoveryNonce;
          if (frame.confirmation !== undefined && confirmPending?.sent === true && frame.confirmation === confirmPending.confirmation) settleConfirm();
          socketReady = true;
          checkpoint=frame.acknowledge===true?frame.cursor:undefined;
          acknowledge();
          clearTimeout(deadline);
          resolveReady();
          if (recoveryRequest !== undefined && !recoveryEcho && confirmPending === undefined) {
            const started = beginConfirm();
            recoveryNonce = started.confirmation;
            // Regap or cancellation surfaces through settleRecovery; the echo
            // promise itself must not become an unhandled rejection.
            void started.sent.catch(() => undefined);
          }
          sendConfirm();
          if (recoveryEcho) {
            const pendingRecovery = recoveryRequest;
            settleRecovery(pendingRecovery !== undefined && pendingRecovery.regapped ? new RealtimeError("gap", channel) : undefined);
          }
          return;
        }
        if (frame.type === "event") {
          push({ type: "event", channel: frame.channel, cursor: frame.cursor, previous: frame.previous, payload: frame.payload });
          return;
        }
        if (frame.type === "gap") {
          push({ type: "gap", channel: frame.channel, cursor: frame.cursor });
          return;
        }
        stop(new RealtimeError(frame.error, frame.channel));
      };
      ws.onclose = () => {
        close();
        resolveClosed();
        if (socket !== ws) return;
        socketReady=false;
        checkpoint=undefined;
        queue.splice(0,queue.length,...queue.filter(message=>message.type==="gap"));
        settleConfirm(new Error("Realtime connection closed."));
        resolveClosed();
      };
      ws.onerror = () => { };
    });
  }

  const iterator: AsyncIterator<RealtimeMessage> = {
    next: () => new Promise<IteratorResult<RealtimeMessage>>((resolve, reject) => {
      const settle = (): void => {
        if (queue.length > 0) {
          const message=queue.shift()!;
          cursors.set(message.channel,message.cursor);
          acknowledge();
          return resolve({ done: false, value: message });
        }
        if (!active) {
          if (failure !== undefined) {
            const error = failure.error instanceof Error ? failure.error : new Error(String(failure.error));
            return reject(error);
          }
          return resolve({ done: true, value: undefined });
        }
        pending.push(settle);
      };
      settle();
    }),
    return: (): Promise<IteratorResult<RealtimeMessage>> => {
      stop();
      return Promise.resolve({ done: true, value: undefined });
    },
  };

  void run();
  return {
    ready,
    confirm,
    recover,
    [Symbol.asyncIterator]: () => iterator,
    unsubscribe: () => stop(),
  };
}

const delay = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));

/** Validates the product address before attaching a one-use ticket. */
export function realtimeEndpoint(value: unknown): string {
  if(typeof value!=="string")throw new Error("Invalid realtime endpoint.");
  let url:URL;
  try{url=new URL(value);}catch{throw new Error("Invalid realtime endpoint.");}
  const suffix=".chickinfry.app";
  if(url.protocol!=="wss:"||!url.hostname.endsWith(suffix)||!ticketPattern.test(url.hostname.slice(0,-suffix.length))||
     url.port||url.username||url.password||url.pathname!=="/realtime"||url.search||url.hash||url.href!==value)throw new Error("Invalid realtime endpoint.");
  return value;
}
