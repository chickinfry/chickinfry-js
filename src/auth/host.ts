import { Auth, AuthError } from "./runtime.js";
import { bearer, invokeAuth, type BrowserRequest } from "./router.js";
import type { DatabasePort } from "./store.js";
import { withTransactionState } from "./transaction.js";

export * from "./index.js";

/** An existing host transaction; results preserve the generated ORM's database value types. */
export interface HostLease {
  exec(sql: string, parameters: readonly unknown[]): Promise<readonly Record<string, unknown>[]>;
}

/** The host serializes execution, confirms commit, and resets session state or disposes of the connection before reuse. */
export interface AuthHost extends HostLease {
  transaction<T>(work: (lease: HostLease) => Promise<T>): Promise<T>;
}

/** Adapts an already open lease without acquiring, committing, or rolling it back. */
export function createLeasePort(lease: HostLease): DatabasePort {
  return {
    async query(sql, parameters) {
      assertHostTransaction(sql, parameters);
      return lease.exec(sql, parameters);
    },
    transaction() { throw new Error("Nested transactions are not supported."); },
  };
}

/** Keeps every Auth transaction and its creating hook on the lease supplied by the host. */
export function createHostPort(host: AuthHost): DatabasePort {
  return {
    query: createLeasePort(host).query,
    transaction: work => host.transaction(async lease => {
      let active = true;
      const port = createLeasePort({exec(sql, parameters) {
        if (!active) return Promise.reject(new Error("The transaction is no longer active."));
        return lease.exec(sql, parameters);
      }});
      try { return await withTransactionState(port, () => work(port)); }
      finally { active = false; }
    }),
  };
}

export type RuntimeSession = Awaited<ReturnType<Auth["session"]>>;

export interface RuntimeInvocation {
  readonly protected: boolean;
  invoke(session: RuntimeSession | null): Promise<unknown>;
  readonly browser?: BrowserRequest & {headers: Headers};
  /** Supplied by the trusted connection, never by client forwarding headers. */
  readonly callerIp?: string;
}

/** The generated host owns operation exposure, browser validation, and HTTP error serialization. */
export async function invokeRuntime(auth: Auth, operation: string, input: unknown, request: Request,
  invocation: RuntimeInvocation): Promise<unknown> {
  if (operation.startsWith("auth.")) {
    return invokeAuth(auth, operation, input, request, invocation.browser, invocation.callerIp);
  }
  let session: RuntimeSession | null = null;
  if (invocation.browser) {
    if (invocation.browser.credential) session = await auth.session(invocation.browser.credential, "browser");
  } else if (request.headers.has("authorization")) {
    session = await auth.session(bearer(request));
  }
  if (invocation.protected !== false && !session) throw new AuthError("unauthenticated", 401);
  return invocation.invoke(session);
}

/** Inspect statement starts without mistaking quoted values or comments for transaction commands. */
function assertHostTransaction(sql: string, parameters: readonly unknown[]): void {
  const denied = () => new Error("Transaction control belongs to the host.");
  if (typeof sql !== "string" || /[\0\ud800-\udfff]/u.test(sql)) throw denied();
  type Token = {kind: "identifier" | "literal" | "parameter" | "symbol"; value: string};
  let tokens: Token[] = [];
  const transactionSetting = (value: unknown) => typeof value === "string" &&
    /^(?:default_)?transaction_(?:isolation|read_only|deferrable)$/i.test(value);
  const check = () => {
    const name = (index: number) => tokens[index]?.kind === "identifier" ? tokens[index]!.value.toLowerCase() : "";
    if (/^(?:begin|start|commit|end|rollback|abort|savepoint|release|prepare)$/.test(name(0))) throw denied();
    if (name(0) === "set") {
      const target = name(["local", "session"].includes(name(1)) ? 2 : 1);
      if (["transaction", "characteristics"].includes(target) || transactionSetting(target)) throw denied();
    }
    if (name(0) === "reset" && (name(1) === "all" || transactionSetting(name(1)))) throw denied();
    for (let i = 0; i < tokens.length; i++) {
      if (name(i) !== "set_config" || tokens[i + 1]?.value !== "(") continue;
      const argument = tokens[i + 2];
      if (tokens[i + 3]?.value !== "," || !argument || !["literal", "parameter"].includes(argument.kind)) throw denied();
      const setting = argument.kind === "parameter" ? parameters[Number(argument.value) - 1] : argument.value;
      if (typeof setting !== "string" || transactionSetting(setting)) throw denied();
    }
    tokens = [];
  };
  for (let i = 0; i < sql.length;) {
    const rest = sql.slice(i);
    if (/^[ \t\n\r\f\v]/.test(rest)) { i++; continue; }
    if (rest.startsWith("--")) {
      const end = rest.search(/[\r\n]/);
      if (end < 0) break;
      i += end;
      continue;
    }
    if (rest.startsWith("/*")) {
      let depth = 1;
      i += 2;
      while (i < sql.length && depth) {
        if (sql.startsWith("/*", i)) { depth++; i += 2; }
        else if (sql.startsWith("*/", i)) { depth--; i += 2; }
        else i++;
      }
      if (depth) throw denied();
      continue;
    }
    if (rest[0] === ";") { check(); i++; continue; }
    // Escaped Unicode names need a decoder before they can safely name a setting or function.
    if (/^u&['"]/i.test(rest)) throw denied();
    const quote = rest[0];
    if (quote === "'" || quote === '"') {
      const begin = i + 1;
      let closed = false;
      for (i++; i < sql.length; i++) {
        // Parameters avoid string escaping and differences in standard_conforming_strings.
        if (quote === "'" && sql[i] === "\\") throw denied();
        if (sql[i] !== quote) continue;
        if (sql[i + 1] === quote) { i++; continue; }
        i++; closed = true; break;
      }
      if (!closed) throw denied();
      tokens.push({kind: quote === "'" ? "literal" : "identifier",
        value: sql.slice(begin, i - 1).replaceAll(quote + quote, quote)});
    } else {
      const identifier = /^[a-z_\u0080-\uffff][a-z_0-9$\u0080-\uffff]*/i.exec(rest)?.[0];
      if (identifier) { tokens.push({kind: "identifier", value: identifier}); i += identifier.length; continue; }
      // PostgreSQL tags use identifier characters, including non-ASCII bytes, except dollar signs.
      const delimiter = /^\$(?:[a-z_\u0080-\uffff][a-z_0-9\u0080-\uffff]*)?\$/i.exec(rest)?.[0];
      if (delimiter) {
        const end = sql.indexOf(delimiter, i + delimiter.length);
        if (end < 0) throw denied();
        tokens.push({kind: "literal", value: sql.slice(i + delimiter.length, end)});
        i = end + delimiter.length;
      } else if (rest[0] === "$") {
        const parameter = /^\$([0-9]+)(?![a-z_0-9$\u0080-\uffff])/i.exec(rest);
        if (!parameter) throw denied();
        tokens.push({kind: "parameter", value: parameter[1]!});
        i += parameter[0].length;
      } else { tokens.push({kind: "symbol", value: sql[i]!}); i++; }
    }
  }
  check();
}
