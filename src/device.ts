import {ClientError, OperationError} from "./http.js";
import type {ClientErrorCode, SessionCredentials} from "./http.js";

export type Owner = readonly [app: string, project: string, origin: string];
export interface Store {
  read(): Promise<string | null>;
  swap(expected: string | null, value: string, reset?: boolean): Promise<boolean>;
}
interface Configuration {
  device?: Device;
  binding?: string;
  publicOperations?: readonly string[];
  persist?: false | {dir: string};
  cwd?: string;
}
type Session = SessionCredentials | {userId: string; sessionId: string; email: string; expiresAt: string};
interface Attempt {id: string; email: string; screen: string; sequence: string; startedAt: number}
interface Bundle {
  version: number; owner: Owner; browser: boolean; epoch: string;
  revision: string; authGeneration: string; sequence: string; observedAt: number;
  blocked: boolean; block?: string; session?: Session; attempts: Attempt[]; selections: Record<string, string>;
  pending: string[]; refresh?: string;
}
interface Snapshot {raw: string | null; bundle: Bundle}
interface Ticket {epoch: string; generation: string; attempt?: string; email?: string; marker: string;
  sequence?: string; startedAt: number; logicalGeneration: string; localEpoch: string}
type Send = (operation: string, input: Readonly<Record<string, unknown>>, token?: string, anonymous?: boolean, received?: (status: number) => void) => Promise<unknown>;
const flights = new Map<string, Promise<unknown>>();
const peerMarks = new WeakMap<Device, Set<string>>();
const day = 86_400_000;
const maxInteger = (1n << 63n) - 1n;
const uuid = (value: unknown): value is string => typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const integer = (value: unknown): value is string => typeof value === "string" &&
  /^(0|[1-9][0-9]{0,18})$/.test(value) && BigInt(value) <= maxInteger;
const text = (value: unknown, max: number): value is string => typeof value === "string" &&
  value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const screenId = (value: unknown): value is string => text(value, 64) && /^[\x21-\x7e]+$/.test(value) &&
  !["__proto__", "constructor", "prototype"].includes(value);
const timestamp = (value: unknown): value is string => typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value));
const token = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
const record = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const next = (value: string) => { if (!integer(value) || BigInt(value) === maxInteger) throw failure(); return String(BigInt(value) + 1n); };
const copy = <T>(value: T): T => structuredClone(value);
export const failure = (code: ClientErrorCode = "failed_precondition") => new ClientError(code);

function validSession(value: unknown, browser: boolean): value is Session {
  if (!record(value) || !uuid(value.userId) || !uuid(value.sessionId) || !timestamp(value.expiresAt)) return false;
  const allowed = browser ? ["userId", "sessionId", "email", "expiresAt"] :
    ["userId", "sessionId", "expiresAt", "accessToken", "refreshToken", "refreshExpiresAt"];
  return Object.keys(value).every(key => allowed.includes(key)) && (browser ? text(value.email, 320) :
    token(value.accessToken) && token(value.refreshToken) && timestamp(value.refreshExpiresAt) &&
    Date.parse(value.refreshExpiresAt) >= Date.parse(value.expiresAt));
}

function decode(raw: string, owner: Owner, browser: boolean): Bundle {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw failure("data_loss"); }
  if (record(value) && typeof value.version === "number" && value.version > 1) throw failure("unimplemented");
  if (!record(value) || new TextEncoder().encode(raw).length > 8192 || value.version !== 1 ||
      JSON.stringify(value.owner) !== JSON.stringify(owner) || value.browser !== browser || !uuid(value.epoch) ||
      !integer(value.revision) || !integer(value.authGeneration) || !integer(value.sequence) ||
      !Number.isSafeInteger(value.observedAt) || Number(value.observedAt) < 0 || typeof value.blocked !== "boolean" ||
      (value.block !== undefined && (!uuid(value.block) || value.blocked !== true)) ||
      (value.session !== undefined && !validSession(value.session, browser)) ||
      !Array.isArray(value.attempts) || value.attempts.length > 3 || !record(value.selections) ||
      !Object.entries(value.selections).every(([key, sequence]) => screenId(key) && integer(sequence)) ||
      !Array.isArray(value.pending) || !value.pending.every(uuid) || (value.refresh !== undefined && !uuid(value.refresh))) {
    throw failure("data_loss");
  }
  const ids = new Set<string>();
  for (const attempt of value.attempts) {
    if (!record(attempt) || !uuid(attempt.id) || ids.has(attempt.id) || !text(attempt.email, 320) ||
        !screenId(attempt.screen) || !integer(attempt.sequence) || !Number.isSafeInteger(attempt.startedAt) || Number(attempt.startedAt) < 0 ||
        Object.keys(attempt).some(key => !["id", "email", "screen", "sequence", "startedAt"].includes(key))) throw failure("data_loss");
    ids.add(attempt.id);
  }
  if (Object.keys(value).some(key => !["version", "owner", "browser", "epoch", "revision", "authGeneration", "sequence",
      "observedAt", "blocked", "block", "session", "attempts", "selections", "pending", "refresh"].includes(key))) throw failure("data_loss");
  return value as unknown as Bundle;
}

function browserStore(key: string): Store {
  const read = async () => { try { return globalThis.localStorage.getItem(key); } catch (error) { throw storageFailure(error); } };
  return {read, async swap(expected, value, reset) {
    const change = async () => {
      if (!reset && await read() !== expected) return false;
      try { globalThis.localStorage.setItem(key, value); } catch (error) { throw storageFailure(error); }
      return true;
    };
    // A single write is not a transaction between agent clusters without Web Locks.
    return globalThis.navigator?.locks ? globalThis.navigator.locks.request(key, change) : change();
  }};
}

function storageFailure(error: unknown): ClientError {
  return failure(record(error) && (error.name === "QuotaExceededError" || error.code === "ENOSPC") ? "resource_exhausted" : undefined);
}

export class Device {
  private store: Promise<Store> | undefined;
  private readonly initial: Bundle;
  private memory: Bundle | undefined;
  private disk: Snapshot | undefined;
  private memoryGeneration: {
    base?: Snapshot;
    changes: {before: Bundle; after: Bundle; ticket?: Ticket;
      change: (bundle: Bundle, same: boolean) => boolean; auth: boolean}[];
    candidate?: Snapshot & {changes: number};
  } | undefined;
  private blocked: {epoch: string; generation: string} | undefined;
  private localEpoch = crypto.randomUUID();
  private readonly key: string;
  private readonly flightKey: string;
  private readonly cwd: string | undefined;
  private volatile: string | null = null;

  constructor(private readonly owner: Owner, private readonly screen: string,
    private readonly browser: boolean, private readonly dir?: string, private readonly disabled = false, cwd?: string) {
    peerMarks.set(this, new Set());
    this.key = "chickinfry:store:v1:" + encodeURIComponent(JSON.stringify(owner));
    this.cwd = cwd ?? (!browser && typeof process !== "undefined" ? process.cwd() : undefined);
    this.flightKey = disabled ? crypto.randomUUID() : browser ? this.key : JSON.stringify([this.key, this.cwd, dir]);
    this.initial = {version: 1, owner, browser, epoch: crypto.randomUUID(), revision: "0", authGeneration: "0",
      sequence: "0", observedAt: Date.now(), blocked: false, attempts: [], selections: {}, pending: []};
  }

  private storage(): Promise<Store> {
    if (this.disabled) return this.store ??= Promise.resolve({read: async () => this.volatile,
      swap: async (expected, value, reset) => { if (!reset && this.volatile !== expected) return false; this.volatile = value; return true; }});
    return this.store ??= this.browser ? Promise.resolve(browserStore(this.key)) :
      import("./device-node.js").then(module => module.openStore(this.owner, this.dir, this.cwd!));
  }

  private async read(): Promise<Snapshot> {
    const store = await this.storage();
    for (let retry = 0; retry < 3; retry++) {
      const raw = await store.read();
      if (raw !== null) return {raw, bundle: decode(raw, this.owner, this.browser)};
      const initial = JSON.stringify(this.initial);
      if (await store.swap(null, initial)) return {raw: initial, bundle: copy(this.initial)};
    }
    throw failure();
  }

  private async snapshot(): Promise<Snapshot> {
    let value: Snapshot;
    try { value = await this.read(); }
    catch (error) {
      if (!(error instanceof ClientError) || !["failed_precondition", "resource_exhausted"].includes(error.code)) throw error;
      if (this.memory) return {raw: this.disk?.raw ?? null, bundle: copy(this.memory)};
      if (!this.browser) throw error;
      return {raw: null, bundle: copy(this.initial)};
    }
    this.disk = value;
    const boundary = this.draft(value);
    if (this.memory) {
      this.memory = boundary;
      await this.update(undefined, () => true, true);
      value = this.memory ? {raw: this.disk!.raw, bundle: copy(this.memory)} : this.disk!;
    }
    if (value.bundle.attempts.some(attempt => Date.now() >= attempt.startedAt && Date.now() - attempt.startedAt >= day)) {
      await this.update(undefined, draft => {
        if (!draft.attempts.some(attempt => Date.now() >= attempt.startedAt && Date.now() - attempt.startedAt >= day)) return false;
        this.prune(draft); return true;
      }, this.memory !== undefined);
      value = this.memory ? {raw: this.disk!.raw, bundle: copy(this.memory)} : this.disk!;
    }
    if (value.bundle.epoch !== boundary.epoch || value.bundle.authGeneration !== boundary.authGeneration) {
      throw new ClientError("unauthenticated");
    }
    return value;
  }

  private same(bundle: Bundle, ticket: Ticket): boolean {
    return bundle.epoch === ticket.epoch && bundle.authGeneration === ticket.generation &&
      this.localEpoch === ticket.localEpoch && (!this.memory || this.memory.authGeneration === ticket.logicalGeneration);
  }

  private draft(value: Snapshot): Bundle {
    const draft = copy(value.bundle), recovery = this.memoryGeneration;
    if (!this.memory || !recovery) return draft;
    for (const marker of [...draft.pending, ...(draft.refresh ? [draft.refresh] : [])]) {
      if (!recovery.changes.some(value => value.ticket?.marker === marker)) peerMarks.get(this)!.add(marker);
    }
    const sameSession = (left: Session | undefined, right: Session | undefined) => left === undefined ? right === undefined :
      right !== undefined && Object.keys(left).length === Object.keys(right).length &&
      Object.entries(left).every(([key, value]) => Reflect.get(right, key) === value);
    const sameAuth = (left: Bundle, right: Bundle) => left.epoch === right.epoch &&
      left.authGeneration === right.authGeneration && sameSession(left.session, right.session) &&
      left.refresh === right.refresh && left.blocked === right.blocked && left.block === right.block;
    const candidate = recovery.candidate;
    /** A failed flush can follow a completed rename; settle that candidate before fencing generations. */
    if (candidate && (candidate.raw === value.raw || (recovery.base &&
        recovery.changes.slice(0, candidate.changes).some(value => value.auth &&
          !sameAuth(value.before, value.after) && sameAuth(value.after, candidate.bundle)) && sameAuth(candidate.bundle, draft)))) {
      recovery.base = copy(candidate);
      recovery.changes.splice(0, candidate.changes);
      recovery.candidate = undefined;
      if (!recovery.changes.length) {
        this.memory = undefined; this.memoryGeneration = undefined;
        return draft;
      }
    }
    const base = recovery.base?.bundle;
    if (!base || base.epoch !== draft.epoch || base.authGeneration !== draft.authGeneration) {
      peerMarks.get(this)!.clear();
      this.memory = undefined; this.memoryGeneration = undefined; this.localEpoch = crypto.randomUUID();
      throw new ClientError("unauthenticated");
    }
    const screens = new Set(base.attempts.map(attempt => attempt.screen));
    for (const {before, after, ticket, change, auth} of recovery.changes) {
      if (auth) {
        const pending = [...draft.pending], blocked = draft.blocked, block = draft.block;
        const owns = ticket && before.epoch === draft.epoch && before.authGeneration === draft.authGeneration &&
          sameSession(before.session, draft.session) && before.refresh === draft.refresh &&
          (before.refresh === ticket.marker || !before.session || draft.pending.includes(ticket.marker));
        change(draft, !!owns);
        draft.pending = pending;
        /** Legacy booleans have no provenance; only the identified baseline block can be cleared. */
        if (blocked && (!owns || block === undefined || block !== before.block)) {
          draft.blocked = true; draft.block = block;
        }
      }
      const removed = new Set(before.attempts.filter(attempt => !after.attempts.some(value => value.id === attempt.id)).map(attempt => attempt.id));
      draft.attempts = draft.attempts.filter(attempt => !removed.has(attempt.id));
      for (const attempt of after.attempts) {
        screens.add(attempt.screen);
        if (!before.attempts.some(value => value.id === attempt.id) && !draft.attempts.some(value => value.id === attempt.id)) draft.attempts.push(copy(attempt));
      }
      for (const attempt of before.attempts) screens.add(attempt.screen);
      draft.pending = draft.pending.filter(marker => !before.pending.includes(marker) || after.pending.includes(marker));
      for (const marker of after.pending) {
        if (!before.pending.includes(marker) && !draft.pending.includes(marker)) draft.pending.push(marker);
      }
      if (BigInt(after.sequence) > BigInt(draft.sequence)) draft.sequence = after.sequence;
      for (const [screen, sequence] of Object.entries(after.selections)) {
        if (before.selections[screen] !== sequence &&
            (!Object.hasOwn(draft.selections, screen) || BigInt(sequence) > BigInt(draft.selections[screen]))) draft.selections[screen] = sequence;
      }
    }
    for (const screen of screens) {
      const attempts = draft.attempts.filter(attempt => attempt.screen === screen);
      if (!attempts.length) delete draft.selections[screen];
      else draft.selections[screen] = attempts.reduce((sequence, attempt) =>
        BigInt(attempt.sequence) > BigInt(sequence) ? attempt.sequence : sequence, "0");
    }
    return draft;
  }

  private prune(bundle: Bundle): void {
    const now = Date.now();
    const expired = bundle.attempts.filter(attempt => now >= attempt.startedAt && now - attempt.startedAt >= day);
    bundle.attempts = bundle.attempts.filter(attempt => now < attempt.startedAt || now - attempt.startedAt < day);
    for (const attempt of expired) {
      if (bundle.selections[attempt.screen] === attempt.sequence) delete bundle.selections[attempt.screen];
    }
    bundle.observedAt = Math.max(now, bundle.observedAt);
  }

  private async update(ticket: Ticket | undefined, change: (bundle: Bundle, same: boolean) => boolean,
    memoryAllowed = false, auth = false): Promise<Bundle | undefined> {
    let last = this.disk ?? {raw: null, bundle: copy(this.initial)};
    let before: Bundle | undefined, draft: Bundle | undefined, candidate: Snapshot | undefined;
    for (let retry = 0; retry < 3; retry++) {
      before = undefined; draft = undefined; candidate = undefined;
      try {
        last = await this.read(); this.disk = last;
        draft = this.draft(last);
        /** Keep the latest observed merge without changing the original recovery provenance. */
        if (this.memory) this.memory = copy(draft);
        const same = ticket === undefined || this.same(last.bundle, ticket);
        before = copy(draft);
        if (!change(draft, same)) return undefined;
        this.prune(draft);
        draft.revision = next(draft.revision);
        const raw = JSON.stringify(draft);
        if (draft.attempts.length > 3 || new TextEncoder().encode(raw).length > 8192) throw failure("resource_exhausted");
        candidate = {raw, bundle: copy(draft)};
        if (await (await this.storage()).swap(last.raw, raw)) {
          this.disk = {raw, bundle: draft}; this.memory = undefined; this.memoryGeneration = undefined;
          return draft;
        }
        candidate = undefined;
      } catch (error) {
        if (!(error instanceof ClientError)) throw failure();
        if (ticket && error.code === "unauthenticated") return undefined;
        if (!memoryAllowed || !["failed_precondition", "resource_exhausted"].includes(error.code)) throw error;
        break;
      }
    }
    if (!memoryAllowed) throw failure();
    if (!before || !draft) {
      draft = copy(this.memory ?? last.bundle); before = copy(draft);
      if (!change(draft, ticket === undefined || this.same(last.bundle, ticket))) return undefined;
      this.prune(draft);
    }
    const recovery = this.memoryGeneration ??= {base: this.disk ? copy(this.disk) : undefined, changes: []};
    if (JSON.stringify({...before, revision: "", observedAt: 0}) !== JSON.stringify({...draft, revision: "", observedAt: 0})) {
      recovery.changes.push({before, after: copy(draft), ticket: ticket && {...ticket}, change, auth});
    }
    if (candidate) recovery.candidate = {...candidate, changes: recovery.changes.length};
    this.memory = draft;
    return draft;
  }

  private ticket(bundle: Bundle, input: Readonly<Record<string, unknown>>): Ticket {
    const disk = this.disk?.bundle ?? bundle;
    return {epoch: disk.epoch, generation: disk.authGeneration, startedAt: Date.now(), marker: crypto.randomUUID(),
      logicalGeneration: bundle.authGeneration, localEpoch: this.localEpoch,
      attempt: typeof input.attempt === "string" ? input.attempt : undefined,
      email: typeof input.email === "string" ? input.email.trim().toLowerCase() : undefined};
  }

  private capture(ticket: Ticket, bundle: Bundle): void {
    const disk = this.disk?.bundle ?? bundle;
    ticket.epoch = disk.epoch; ticket.generation = disk.authGeneration;
    ticket.logicalGeneration = bundle.authGeneration;
  }

  async invoke(operation: string, input: Readonly<Record<string, unknown>>, send: Send, publicOperation = false): Promise<unknown> {
    const authChange = ["auth.signin", "auth.signup", "auth.verify_email", "auth.identity", "auth.signin_with_code", "auth.exchange_code"].includes(operation);
    const reset = ["auth.request_password_reset", "auth.reset_password"].includes(operation);
    const startsAuth = (authChange && operation !== "auth.verify_email") || reset;
    const publicAuth = publicOperation || authChange || ["auth.send_verification_email", "auth.request_password_reset", "auth.reset_password", "auth.bot_config"].includes(operation);
    if (operation === "auth.logout") {
      const disk = this.disk?.bundle ?? this.initial;
      this.blocked = {epoch: disk.epoch, generation: disk.authGeneration}; this.localEpoch = crypto.randomUUID();
    }
    const flight = flights.get(this.flightKey);
    const inspectReset = reset && (this.memory !== undefined || peerMarks.get(this)!.size > 0);
    if (flight && !authChange && operation !== "auth.logout" &&
        !inspectReset) await flight;
    let bundle: Bundle;
    try { bundle = (await this.snapshot()).bundle; }
    catch (error) {
      if (operation !== "auth.logout" || !(error instanceof ClientError) ||
          !["data_loss", "unimplemented"].includes(error.code)) throw error;
      const fresh = {...copy(this.initial), epoch: crypto.randomUUID(), blocked: true, block: crypto.randomUUID(), revision: "1", authGeneration: "1"};
      const raw = JSON.stringify(fresh);
      await (await this.storage()).swap(null, raw, true);
      this.disk = {raw, bundle: fresh}; this.memory = undefined; this.memoryGeneration = undefined;
      return send(operation, input);
    }
    if (operation === "auth.logout") return this.logout(bundle, input, send);
    const observed = peerMarks.get(this)!;
    const hasObserved = (draft: Bundle) => draft.pending.some(marker => observed.has(marker)) ||
      (draft.refresh !== undefined && observed.has(draft.refresh));
    if (flight && inspectReset && !hasObserved(bundle)) {
      await flight; bundle = (await this.snapshot()).bundle;
    }
    if (startsAuth && hasObserved(bundle)) {
      let current: Bundle | undefined;
      const cleared = await this.update(this.ticket(bundle, input), (draft, same) => {
        if (!same) return false;
        if (!hasObserved(draft)) {current = draft; return false;}
        draft.authGeneration = next(draft.authGeneration); draft.pending = [];
        delete draft.session; delete draft.refresh;
        draft.blocked = true; draft.block = crypto.randomUUID();
        return true;
      });
      if (cleared) {
        observed.clear(); this.localEpoch = crypto.randomUUID(); bundle = cleared;
      } else {
        if (!current) throw new ClientError("unauthenticated");
        bundle = current;
        if (flight && inspectReset) {await flight; bundle = (await this.snapshot()).bundle;}
      }
    }
    if (this.blocked && !this.memory && bundle.session && !bundle.blocked && !bundle.refresh && !bundle.pending.length &&
        Date.parse("refreshExpiresAt" in bundle.session ? bundle.session.refreshExpiresAt : bundle.session.expiresAt) > Date.now() &&
        (bundle.epoch !== this.blocked.epoch || BigInt(bundle.authGeneration) > BigInt(this.blocked.generation))) this.blocked = undefined;
    const expired = bundle.session;
    if (expired && "refreshExpiresAt" in expired && Date.parse(expired.refreshExpiresAt) <= Date.now()) {
      const cleared = await this.update(this.ticket(bundle, input), (draft, same) => {
        if (!same || !draft.session || !("refreshToken" in draft.session) || draft.session.refreshToken !== expired.refreshToken) return false;
        delete draft.session; delete draft.refresh; draft.authGeneration = next(draft.authGeneration); draft.blocked = true; draft.block = crypto.randomUUID(); return true;
      });
      if (!publicAuth || operation === "auth.refresh" || !cleared) throw new ClientError("unauthenticated");
      bundle = cleared;
    }
    const targeting = ["auth.verify_email", "auth.send_verification_email"].includes(operation);
    if (targeting && input.email === undefined && input.attempt === undefined && Date.now() >= bundle.observedAt) {
      const attempt = bundle.attempts.find(value => value.screen === this.screen &&
        value.sequence === bundle.selections[this.screen] && Date.now() >= value.startedAt && Date.now() - value.startedAt < day);
      if (attempt) input = {...input, attempt: attempt.id};
    }
    const ticket = this.ticket(bundle, input);
    const consumed = bundle.attempts.find(value => value.id === ticket.attempt);
    ticket.email ??= consumed?.email;
    if (operation === "auth.signup") {
      const started = await this.update(ticket, (draft, same) => {
        if (!same) return false;
        draft.sequence = next(draft.sequence); draft.selections[this.screen] = draft.sequence;
        return true;
      }, true);
      if (!started) throw new ClientError("unauthenticated");
      ticket.sequence = started?.sequence;
      this.capture(ticket, started);
    }
    if (authChange && bundle.session) {
      const marked = await this.update(ticket, (draft, same) => { if (!same) return false; draft.pending.push(ticket.marker); return true; });
      if (!marked) throw new ClientError("unauthenticated");
      this.capture(ticket, marked);
    }
    if (operation === "auth.refresh") return this.refresh(bundle, send, ticket, input);
    const blocked = !!(this.blocked || bundle.blocked || (bundle.refresh || bundle.pending.length));
    if (!publicAuth && blocked) throw new ClientError("unauthenticated");
    const session = blocked ? undefined : bundle.session;
    if (!publicAuth && !session && !this.browser) throw new ClientError("unauthenticated");
    let access = session && "accessToken" in session ? session.accessToken : undefined;
    let value: unknown;
    try { value = await send(operation, input, access, publicOperation && blocked && !authChange); }
    catch (error) {
      if (authChange && error instanceof OperationError && error.status >= 400 && error.status < 500) {
        await this.update(ticket, (draft, same) => {
          if (!same || !draft.pending.includes(ticket.marker)) return false;
          draft.pending = draft.pending.filter(marker => marker !== ticket.marker); return true;
        });
      }
      if (!this.browser && !authChange && error instanceof OperationError && error.status === 401 && error.code === "invalid_token" && session) {
        const refreshed = await this.refresh(bundle, send, ticket) as Record<string, unknown>;
        access = refreshed.access_token as string;
        const current = (await this.snapshot()).bundle;
        if (current.blocked || current.refresh || current.pending.length || !current.session || !("accessToken" in current.session) ||
            current.session.userId !== session.userId || current.session.sessionId !== session.sessionId ||
            current.session.accessToken !== access) throw new ClientError("unauthenticated");
        return send(operation, input, access);
      }
      throw error;
    }
    if (operation === "auth.signup" && record(value) && value.accepted === true && uuid(value.attempt)) {
      if (!ticket.email || !text(ticket.email, 320) || !ticket.sequence) throw new ClientError("internal", undefined, true);
      await this.update(ticket, (draft, same) => {
        if (!same) return false;
        draft.pending = draft.pending.filter(marker => marker !== ticket.marker);
        if (!draft.selections[this.screen] || BigInt(draft.selections[this.screen]) < BigInt(ticket.sequence!)) draft.selections[this.screen] = ticket.sequence!;
        draft.attempts.push({id: value.attempt as string, email: ticket.email!, screen: this.screen,
          sequence: ticket.sequence!, startedAt: ticket.startedAt});
        return true;
      }, true);
    } else if (authChange || (this.browser && operation === "auth.session")) {
      const session = this.session(value);
      if (this.browser && authChange) {
        let latest: Snapshot;
        try { latest = await this.read(); }
        catch (error) {
          if (!(error instanceof ClientError) || !["failed_precondition", "resource_exhausted"].includes(error.code)) throw error;
          latest = this.disk ?? {raw: null, bundle: copy(this.initial)};
        }
        if (!this.same(latest.bundle, ticket)) return value;
        const current = this.session(await send("auth.session", {}));
        if (current.sessionId !== session.sessionId) throw new ClientError("unauthenticated");
      }
      await this.install(ticket, session);
    }
    return value;
  }

  private session(value: unknown, status?: number): Session {
    if (!record(value)) throw new ClientError("internal", status, true);
    const session: Session = this.browser ? {userId: value.id as string, sessionId: value.session_id as string,
      email: value.email as string, expiresAt: value.expires_at as string} :
      {accessToken: value.access_token as string, refreshToken: value.refresh_token as string,
        userId: value.user_id as string, sessionId: value.session_id as string,
        expiresAt: value.expires_at as string, refreshExpiresAt: value.refresh_expires_at as string};
    if (!validSession(session, this.browser)) throw new ClientError("internal", status, true);
    return session;
  }

  private async install(ticket: Ticket, session: Session): Promise<Bundle | undefined> {
    const installed = await this.update(ticket, (draft, same) => {
      const consumed = ticket.attempt === undefined || draft.attempts.some(value => value.id === ticket.attempt);
      if (!same || !consumed) {
        const before = draft.attempts.length + draft.pending.length;
        if (ticket.attempt) draft.attempts = draft.attempts.filter(value => value.id !== ticket.attempt && value.email !== ticket.email);
        draft.pending = draft.pending.filter(marker => marker !== ticket.marker);
        return before !== draft.attempts.length + draft.pending.length;
      }
      const changed = draft.session?.sessionId !== session.sessionId || draft.session?.userId !== session.userId;
      if (changed) draft.authGeneration = next(draft.authGeneration);
      draft.session = session; draft.blocked = false; delete draft.block;
      draft.pending = changed ? [] : draft.pending.filter(marker => marker !== ticket.marker); delete draft.refresh;
      draft.attempts = draft.attempts.filter(value => value.id !== ticket.attempt && value.email !== (ticket.email ?? ("email" in session ? session.email : undefined)));
      return true;
    }, true, true);
    if (installed?.session?.sessionId === session.sessionId && installed.session.userId === session.userId &&
        ticket.localEpoch === this.localEpoch) {
      this.blocked = undefined;
      if (installed.authGeneration !== ticket.logicalGeneration) this.localEpoch = crypto.randomUUID();
    }
    return installed;
  }

  private async refresh(bundle: Bundle, send: Send, ticket: Ticket, input?: Readonly<Record<string, unknown>>): Promise<unknown> {
    if (this.browser || this.blocked || !bundle.session || !("refreshToken" in bundle.session) || bundle.refresh || bundle.blocked || bundle.pending.length ||
        Date.parse(bundle.session.refreshExpiresAt) <= Date.now() || (input && input.refresh_token !== bundle.session.refreshToken)) throw new ClientError("unauthenticated");
    const session = bundle.session;
    let current: SessionCredentials | undefined;
    const started = await this.update(ticket, (draft, same) => {
      if (!same || draft.refresh || !draft.session || !("refreshToken" in draft.session) ||
          draft.session.userId !== session.userId || draft.session.sessionId !== session.sessionId) return false;
      if (draft.session.accessToken !== session.accessToken || draft.session.refreshToken !== session.refreshToken) {
        current = draft.session; return false;
      }
      draft.session = session; draft.refresh = ticket.marker; return true;
    });
    if (!started) {
      if (current && input === undefined) return {access_token: current.accessToken};
      throw new ClientError("unauthenticated");
    }
    this.capture(ticket, started);
    const run = (async () => {
      let value: unknown;
      let status: number | undefined;
      try { value = await send("auth.refresh", {refresh_token: session.refreshToken}, undefined, undefined, received => { status = received; }); }
      catch (error) {
        if (error instanceof OperationError && error.status === 401) {
          await this.update(ticket, (draft, same) => {
            if (!same || draft.refresh !== ticket.marker) return false;
            delete draft.session; delete draft.refresh; draft.pending = [];
            draft.authGeneration = next(draft.authGeneration); draft.blocked = true; draft.block = crypto.randomUUID(); return true;
          });
          throw error;
        }
        throw error instanceof ClientError ? error : new ClientError("unauthenticated", error instanceof OperationError ? error.status : undefined, true);
      }
      const updated = this.session(value, status);
      if (updated.userId !== session.userId || updated.sessionId !== session.sessionId) throw new ClientError("unauthenticated");
      await this.update(ticket, (draft, same) => {
        if (!same || draft.refresh !== ticket.marker || !draft.session ||
            Object.entries(session).some(([key, value]) => Reflect.get(draft.session!, key) !== value)) return false;
        draft.session = updated; delete draft.refresh; return true;
      }, true, true);
      return value;
    })();
    flights.set(this.flightKey, run);
    try { return await run; } finally { if (flights.get(this.flightKey) === run) flights.delete(this.flightKey); }
  }

  private async logout(bundle: Bundle, input: Readonly<Record<string, unknown>>, send: Send): Promise<unknown> {
    const disk = this.disk?.bundle ?? bundle;
    this.blocked = {epoch: disk.epoch, generation: disk.authGeneration};
    const cleared = await this.update(this.ticket(bundle, {}), (draft, same) => {
      if (!same) return false;
      draft.authGeneration = next(draft.authGeneration); draft.blocked = true; draft.block = crypto.randomUUID();
      delete draft.session; delete draft.refresh; draft.attempts = []; draft.selections = {}; draft.pending = [];
      return true;
    });
    if (cleared) this.blocked = {epoch: cleared.epoch, generation: cleared.authGeneration};
    return send("auth.logout", input, bundle.session && "accessToken" in bundle.session ? bundle.session.accessToken : undefined);
  }
}

/**
 * Private generated-code data properties on options or a transport:
 * Symbol.for("chickinfry.store.scope.v1") is {appId, projectId, origin, screen}, all strings.
 * Symbol.for("chickinfry.store.public.v1") is an optional array of exact public operation names.
 * Missing scope means standalone; malformed properties or an origin mismatch fail closed.
 * Neither property is part of the public types.
 */
export function createDevice(origin: string, options: object, browser: boolean, bearer?: string, previous?: Configuration): Configuration {
  try {
    const publicKey = Symbol.for("chickinfry.store.public.v1");
    const publicDescriptor = Object.getOwnPropertyDescriptor(options, publicKey);
    let publicOperations = previous?.publicOperations;
    if (publicDescriptor) {
      if (!("value" in publicDescriptor) || !Array.isArray(publicDescriptor.value)) throw failure();
      publicOperations = [...publicDescriptor.value];
      if (!publicOperations.every(value => typeof value === "string" && value.length > 0)) throw failure();
    } else if (Reflect.has(options, publicKey)) throw failure();
    const scope: unknown = Reflect.get(options, Symbol.for("chickinfry.store.scope.v1"));
    const persist: unknown = Reflect.get(options, "persist");
    const dir = record(persist) ? persist.dir : undefined;
    let binding: {appId: string; projectId: string; screen: string} | undefined;
    if (scope !== undefined) {
      if (!record(scope)) throw failure();
      const fields = Object.getOwnPropertyDescriptors(scope);
      if (Object.keys(fields).length !== 4 || !text(fields.appId?.value, 256) || !text(fields.projectId?.value, 256) ||
          !screenId(fields.screen?.value) || fields.origin?.value !== origin) throw failure();
      binding = {appId: fields.appId.value, projectId: fields.projectId.value, screen: fields.screen.value};
    }
    if (persist !== undefined && persist !== false && (!record(persist) || !text(dir, 4096) ||
        !dir.trim() || Object.keys(persist).length !== 1)) throw failure();
    if (browser && (bearer !== undefined || record(persist))) throw failure();
    const signature = binding ? JSON.stringify([binding.appId, binding.projectId, origin, binding.screen]) : previous?.binding;
    if (previous && (scope === undefined || previous.binding !== undefined)) {
      if (previous.binding !== signature) throw failure();
      return {...previous, publicOperations};
    }
    const configuration: Configuration = {binding: signature, publicOperations,
      persist: persist === false ? false : record(persist) ? {dir: dir as string} : undefined};
    if (bearer !== undefined || (binding === undefined && !record(persist))) return configuration;
    if (!browser && (typeof process === "undefined" || typeof process.cwd !== "function")) throw failure();
    configuration.cwd = previous?.cwd ?? (!browser ? process.cwd() : undefined);
    const owner: Owner = binding ? [binding.appId, binding.projectId, origin] : ["", "", origin];
    configuration.device = new Device(owner, binding?.screen ?? "default", browser,
      record(persist) ? dir as string : undefined, persist === false, configuration.cwd);
    return configuration;
  } catch { throw failure(); }
}
