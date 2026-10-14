import { AsyncLocalStorage } from "node:async_hooks";

/** Values whose exact, nonempty contents must be hidden from server logs. */
export interface LogSecrets {
  readonly values: readonly string[];
  readonly databaseURL?: string;
}

const marker = Symbol();
type Part = string | typeof marker;
const maxBytes = 4 << 20;
const encoder = new TextEncoder();

function checkSize(value: string): void {
  if (typeof value !== "string" || value.length > maxBytes || encoder.encode(value).byteLength > maxBytes) throw new Error("Log budget exceeded.");
}

function normalize(value: string): string {
  const parts: string[] = [];
  for (let start = 0; start < value.length;) {
    let end = Math.min(start + 8192, value.length);
    if (end < value.length) {
      if (value[end - 1] === "%") end--;
      else if (value[end - 2] === "%") end -= 2;
    }
    parts.push(value.slice(start, end).replace(/%[0-9a-fA-F]{2}/g, escape => escape.toLowerCase()));
    start = end;
  }
  return parts.join("");
}

function createMask(snapshot: LogSecrets): (message: string) => Part[] {
  if (!snapshot || !Array.isArray(snapshot.values) || snapshot.values.some(value => typeof value !== "string")) {
    throw new Error("Invalid log secret snapshot.");
  }
  const values = [...snapshot.values];
  const encoded: string[] = [];
  if (snapshot.databaseURL !== undefined) {
    if (typeof snapshot.databaseURL !== "string" || !snapshot.databaseURL) throw new Error("Invalid log secret snapshot.");
    try {
      const password = new URL(snapshot.databaseURL).password;
      encoded.push(snapshot.databaseURL, password);
      values.push(decodeURIComponent(password));
    } catch { throw new Error("Invalid log secret snapshot."); }
  }
  type Node = {next: Map<string, number>; failure: number; longest: number; matches: number};
  function compile(patterns: string[], foldPercent: boolean) {
    const inputs = [...new Set(patterns.filter(value => value.length > 0))];
    const prefixes = inputs.map(value => foldPercent ? /^[0-9a-f]{2}/i.test(value) ? 2 : /^[0-9a-f]/i.test(value) ? 1 : 0 : 0);
    const nodes: Node[] = [{next: new Map(), failure: 0, longest: 0, matches: 0}];
    for (let pattern = 0; pattern < inputs.length; pattern++) {
      const value = inputs[pattern];
      const variants = [value];
      // An escape before a match can fold its literal prefix; check the original prefix during scanning.
      for (let unit = 1; unit <= prefixes[pattern]; unit++) variants.push(value.slice(0, unit).toLowerCase() + value.slice(unit));
      for (const variant of new Set(variants)) {
        let state = 0;
        for (let i = 0; i < variant.length; i++) {
          const character = variant[i];
          let next = nodes[state].next.get(character);
          if (next === undefined) {
            if (nodes.length >= 128 << 10) throw new Error("Log budget exceeded.");
            next = nodes.length;
            nodes[state].next.set(character, next);
            nodes.push({next: new Map(), failure: 0, longest: 0, matches: 0});
          }
          state = next;
        }
        nodes[state].longest = value.length;
        if (foldPercent) nodes[state].matches |= 1 << pattern;
      }
    }
    const queue = [...nodes[0].next.values()];
    for (let i = 0; i < queue.length; i++) {
      const node = nodes[queue[i]];
      node.longest = Math.max(node.longest, nodes[node.failure].longest);
      node.matches |= nodes[node.failure].matches;
      for (const [character, next] of node.next) {
        let failure = node.failure;
        while (failure && !nodes[failure].next.has(character)) failure = nodes[failure].failure;
        nodes[next].failure = nodes[failure].next.get(character) ?? 0;
        queue.push(next);
      }
    }
    return {inputs, prefixes, nodes, foldPercent};
  }
  let scans: ReturnType<typeof compile>[];
  try { scans = [compile(values, false), compile(encoded.map(normalize), true)]; }
  catch { return () => { throw new Error("Log budget exceeded."); }; }
  return message => {
    checkSize(message);
    const ends = new Uint32Array(message.length);
    for (const {inputs, prefixes, nodes, foldPercent} of scans) {
      if (nodes.length === 1) continue;
      const text = foldPercent ? normalize(message) : message;
      let state = 0;
      for (let i = 0; i < text.length; i++) {
        const character = text[i];
        while (state && !nodes[state].next.has(character)) state = nodes[state].failure;
        state = nodes[state].next.get(character) ?? 0;
        if (!foldPercent) ends[i] = Math.max(ends[i], nodes[state].longest);
        else {
          for (let pattern = 0; pattern < inputs.length; pattern++) {
            if (!(nodes[state].matches & (1 << pattern))) continue;
            const value = inputs[pattern], start = i + 1 - value.length;
            let valid = true;
            for (let unit = 0; unit < prefixes[pattern]; unit++) {
              if (message[start + unit] !== value[unit]) valid = false;
            }
            if (valid) ends[i] = Math.max(ends[i], value.length);
          }
        }
      }
    }
    let length = 0, ranges = 0, protectedNext = false;
    for (let i = message.length - 1; i >= 0; i--) {
      length = Math.max(length, ends[i]);
      const protectedHere = length > 0;
      ends[i] = Number(protectedHere);
      if (protectedHere && !protectedNext) ranges++;
      protectedNext = protectedHere;
      if (length > 0) length--;
    }
    if (ranges > 8192) throw new Error("Log budget exceeded.");
    const parts: Part[] = [];
    let position = 0;
    for (let i = 0; i < message.length; i++) {
      if (!ends[i]) continue;
      if (i === 0 || !ends[i - 1]) parts.push(message.slice(position, i), marker);
      position = i + 1;
    }
    parts.push(message.slice(position));
    return parts;
  };
}

function render(parts: Part[]): string {
  const output = parts.map(part => part === marker ? "[redacted]" : part).join("");
  checkSize(output);
  return output;
}

/** Redacts exact values and database URL/password escapes; throws without returning partial text on failure. */
export function redactLog(message: string, secrets: LogSecrets): string {
  return render(createMask(secrets)(message));
}

type LogState = {mask: (message: string) => Part[]; dropped: number};
const context = new AsyncLocalStorage<LogState>();
let unscopedDropped = 0;
let formatting = false;

function format(args: unknown[], mask: LogState["mask"]): string {
  const parts: Part[] = [];
  const active = new Set<object>();
  let nodes = 0, bytes = 0;
  function text(value: string, quoted = false): void {
    bytes += encoder.encode(value).byteLength;
    if (bytes > maxBytes) throw new Error("Log budget exceeded.");
    const safe = mask(value);
    if (quoted) parts.push('"');
    for (const part of safe) parts.push(part === marker ? marker : quoted ? JSON.stringify(part).slice(1, -1) : part);
    if (quoted) parts.push('"');
  }
  function visit(value: unknown, depth = 0): void {
    if (++nodes > 8192 || depth > 32) throw new Error("Log budget exceeded.");
    if (typeof value === "string") { text(value, depth > 0); return; }
    if (typeof value === "function") { text("[Function]"); return; }
    if (value === null || typeof value !== "object") { text(String(value)); return; }
    if (active.has(value)) { text("[Circular]"); return; }
    active.add(value);
    const keys = Reflect.ownKeys(value);
    if (keys.length > 8192 - nodes) throw new Error("Log budget exceeded.");
    const array = Array.isArray(value);
    parts.push(array ? "[" : "{");
    let first = true;
    for (const key of keys) {
      if (array && key === "length") continue;
      if (!first) parts.push(", ");
      first = false;
      if (!array) { text(String(key), true); parts.push(": "); }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor) throw new Error("Log value changed during inspection.");
      // Never execute getters, toJSON, or custom inspectors while formatting a log.
      if (!("value" in descriptor)) text("[Getter]", true);
      else visit(descriptor.value, depth + 1);
    }
    parts.push(array ? "]" : "}");
    active.delete(value);
  }
  for (let i = 0; i < args.length; i++) {
    if (i) parts.push(" ");
    visit(args[i]);
  }
  // Keep inserted markers opaque when checking matches formed by formatting or adjacent arguments.
  const output: Part[] = [];
  let pending: string[] = [];
  for (const part of parts) {
    if (part !== marker) pending.push(part);
    else { output.push(...mask(pending.join("")), marker); pending = []; }
  }
  output.push(...mask(pending.join("")));
  return render(output);
}

const methods = ["log", "info", "debug", "warn", "error", "trace", "table", "group", "groupCollapsed", "groupEnd", "count", "countReset", "dir", "dirxml", "time", "timeEnd", "timeLog", "timeStamp", "profile", "profileEnd", "clear", "assert"] as const;
const warn = console.warn.bind(console);

function flush(state: LogState): void {
  if (!state.dropped) return;
  try {
    warn(render(state.mask(JSON.stringify({droppedLogs: state.dropped}))));
    state.dropped = 0;
  } catch { unscopedDropped += state.dropped; state.dropped = 0; }
}

for (const method of methods) {
  const writer = console[method] as (...args: unknown[]) => void;
  if (typeof writer !== "function") continue;
  Object.defineProperty(console, method, {configurable: true, writable: true, value: (...args: unknown[]): void => {
    if (method === "assert" && args.shift()) return;
    const state = context.getStore();
    if (!state) { unscopedDropped++; return; }
    if (formatting) { state.dropped++; return; }
    formatting = true;
    try {
      const message = format(args, state.mask);
      if (method === "assert") writer.call(console, false, message);
      else writer.call(console, message);
    } catch { state.dropped++; }
    finally { formatting = false; flush(state); }
  }});
}

/**
 * Runs server work with an immutable secret snapshot, including asynchronous descendants.
 * Importing this server-only module guards console output; logs outside a valid snapshot are discarded.
 * Arguments become one safe string, without format substitutions or user-defined inspection hooks.
 * Logging failures discard only that record and report the count without changing the work result.
 */
export function runWithLogRedaction<T>(secrets: LogSecrets, work: () => T): T {
  const state = {mask: createMask(secrets), dropped: unscopedDropped};
  unscopedDropped = 0;
  return context.run(state, () => { flush(state); return work(); });
}
