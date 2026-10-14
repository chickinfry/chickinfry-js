import pg from "pg";
import { BlockList, isIP, Socket } from "node:net";
import type { DatabasePort } from "./orm.js";

/** The cleanup port's connection wait is part of the same budget that aborts the whole cleanup task. */
export const cleanupBudgetMillis = 5_000;

export interface PostgresPort extends DatabasePort {
  close(): Promise<void>;
}

const privateAddresses = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],["169.254.0.0",16],
  ["172.16.0.0",12],["192.0.0.0",24],["192.0.2.0",24],["192.88.99.0",24],["192.168.0.0",16],
  ["198.18.0.0",15],["198.51.100.0",24],["203.0.113.0",24],["224.0.0.0",3],
] as const) privateAddresses.addSubnet(address, prefix);
privateAddresses.addRange("::", "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ipv6");
privateAddresses.addRange("4000::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ipv6");
for (const [address, prefix] of [["2001::",23],["2001:db8::",32],["2002::",16],["3fff::",20]] as const) {
  privateAddresses.addSubnet(address, prefix, "ipv6");
}

/** A request owns one lazy connection; deployment connections reject private destinations at connect time. */
export function createPostgresPort(connectionString: string, signal?: AbortSignal, remote = false): PostgresPort {
  let config: pg.ClientConfig;
  let requireChannelBinding = false;
  let invalidMessage = "A complete, permitted PostgreSQL URL is required.";
  try {
    const path = connectionString.match(/^postgres(?:ql)?:\/\/[^/?#]+(\/[^?#]*)/i)?.[1];
    if (!path || path.split("/").some(segment => /^(?:\.|%2e){1,2}$/i.test(segment))) throw new Error();
    const url = new URL(connectionString);
    const hostname = url.hostname;
    if (hostname.startsWith("[") ? isIP(hostname.slice(1,-1)) !== 6 :
        !/^(?:[a-z0-9_-]+\.)*[a-z0-9_-]+\.?$/i.test(hostname) ||
        /(?:^|\.)(?:[0-9]+|0x[0-9a-f]*)\.?$/i.test(hostname) && isIP(hostname) !== 4) {
      invalidMessage = "Unsupported PostgreSQL host. Use an ASCII hostname, a standard dotted-decimal IPv4 address, or a bracketed IPv6 address.";
      throw new Error();
    }
    if (!["postgres:","postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password ||
        !url.pathname || url.pathname === "/" || url.hash) throw new Error();
    const options = [...url.searchParams];
    for (const [name, value] of options) {
      if (!["sslmode", "channel_binding"].includes(name)) {
        invalidMessage = "Unsupported PostgreSQL connection option. Only sslmode and channel_binding are allowed.";
        throw new Error();
      }
      const values = name === "sslmode" ? ["disable","prefer","require","verify-ca","verify-full","no-verify"] : ["require","prefer","disable"];
      if (!values.includes(value) || url.searchParams.getAll(name).length > 1) {
        if (name === "channel_binding") invalidMessage = 'Invalid PostgreSQL connection option "channel_binding".';
        throw new Error();
      }
    }
    const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
    const port = Number(url.port || 5432);
    const database = decodeURIComponent(url.pathname.slice(1)), user = decodeURIComponent(url.username), password = decodeURIComponent(url.password);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535 ||
        [host, database, user, password].some(value => !value || /[\u0000-\u001f\u007f]/.test(value))) throw new Error();
    const family = isIP(host);
    if (remote && (family ? privateAddresses.check(host, family === 4 ? "ipv4" : "ipv6") :
        !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(host) ||
        /(?:^|\.)(?:localhost|local|internal|home|lan)$/.test(host))) throw new Error();
    const mode = url.searchParams.get("sslmode");
    const cloudflare = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";
    const binding = url.searchParams.get("channel_binding");
    requireChannelBinding = binding === "require";
    if (requireChannelBinding && (cloudflare || !mode || mode === "disable")) {
      invalidMessage = cloudflare
        ? "Cloudflare Workers runtime does not support PostgreSQL channel binding. Remove channel_binding=require and register again; connections use sslmode=verify-full."
        : "channel_binding=require needs TLS. Use sslmode=verify-full.";
      throw new Error();
    }
    config = {host, port, database, user, password, options: "-c datestyle=ISO",
      ssl: mode && mode !== "disable" ? {rejectUnauthorized: mode !== "no-verify"} : false,
      enableChannelBinding: !cloudflare && !!mode && mode !== "disable" && (binding === "require" || binding === "prefer"),
      connectionTimeoutMillis: signal ? cleanupBudgetMillis : 10_000,
      // Workers TCP rejects private resolved addresses; Node checks every resolution on the actual socket.
      ...(remote && !cloudflare ? {stream: () => new Socket({blockList: privateAddresses})} : {}),
      types: {getTypeParser: (oid, format) => {
        if (format !== "binary" && (oid === 1082 || oid === 1184)) return (value: string) => value;
        return pg.types.getTypeParser(oid, format);
      }},
    };
  } catch { throw new Error(invalidMessage); }
  const client = new pg.Client(config);
  client.on("error", () => console.error("Database idle connection was closed."));
  let connected: Promise<pg.Client> | undefined;
  let pending: Promise<unknown> = Promise.resolve();
  let closed = false;
  let closing: Promise<void> | undefined;
  let ending: Promise<void> | undefined;
  let rejectConnect: ((error: unknown) => void) | undefined;
  const stream = client.connection.stream;
  if ("_cfSocket" in stream) {
    const socketEnd = stream.end.bind(stream);
    let endingSocket: unknown;
    // pg-cloudflare 1.4.0 dereferences a missing transport on end and can open it after cancellation.
    stream.end = (...args: unknown[]) => {
      const socket = stream._cfSocket;
      if (socket === endingSocket) return stream;
      endingSocket = socket;
      stream.writable = false;
      if (socket) return Reflect.apply(socketEnd, stream, args);
      stream.destroyed = true;
      queueMicrotask(() => stream.emit("close"));
      return stream;
    };
    stream.once("connect", () => { if (closed) stream.destroy(); });
  }
  const connectionClosed = () => signal?.aborted ? signal.reason : new Error("The database connection is closed.");
  const destroy = () => {
    closed = true;
    rejectConnect?.(connectionClosed());
    client.connection.stream.destroy();
  };
  const end = () => ending ??= (async () => {
    rejectConnect?.(connectionClosed());
    // pg can wait for the peer's EOF even after startup has failed.
    const timeout = setTimeout(destroy, cleanupBudgetMillis);
    try { await client.end(); }
    finally { clearTimeout(timeout); }
  })();
  if (requireChannelBinding) {
    let bindingVerified = false;
    const rejectBinding = () => {
      rejectConnect?.(new Error("Could not complete channel_binding=require authentication. Check that the server offers SCRAM-SHA-256-PLUS over TLS."));
      destroy();
    };
    // enableChannelBinding only prefers PLUS; require must reject every non-bound authentication path.
    client.connection.on("authenticationSASL", (message: {mechanisms: string[]}) => {
      message.mechanisms = message.mechanisms.filter(value => value === "SCRAM-SHA-256-PLUS");
      if (message.mechanisms.length === 0) rejectBinding();
    });
    const finalize = Reflect.get(client, "_handleAuthSASLFinal");
    // pg 8.23 clears this session only after its native server-signature verification succeeds.
    Reflect.set(client, "_handleAuthSASLFinal", (message: unknown) => {
      const session = Reflect.get(client, "saslSession");
      if (session?.mechanism !== "SCRAM-SHA-256-PLUS" || session.message !== "SASLResponse") {
        rejectBinding();
        return;
      }
      Reflect.apply(finalize, client, [message]);
      bindingVerified = Reflect.get(client, "saslSession") === null;
      if (!bindingVerified) rejectBinding();
    });
    client.connection.on("authenticationCleartextPassword", rejectBinding);
    client.connection.on("authenticationMD5Password", rejectBinding);
    client.connection.on("authenticationOk", () => { if (!bindingVerified) rejectBinding(); });
    client.connection.on("readyForQuery", () => { if (!bindingVerified) rejectBinding(); });
  }
  const abort = () => { destroy(); void end().catch(() => {}); };
  signal?.addEventListener("abort", abort, {once: true});
  if (signal?.aborted) abort();
  const run = <T>(work: () => Promise<T>): Promise<T> => {
    const result = pending.then(async () => {
      signal?.throwIfAborted();
      if (closed) throw new Error("The database connection is closed.");
      await (connected ??= new Promise<pg.Client>((resolve, reject) => {
        // Own settlement: pg's end handler skips its connect callback once ending starts.
        rejectConnect = reject;
        client.connect((error?: Error) => {
          rejectConnect = undefined;
          if (error) reject(error);
          else resolve(client);
        });
      }));
      signal?.throwIfAborted();
      return work();
    });
    pending = result.catch(() => {});
    return result;
  };
  return {
    query: (sql, parameters) => run(async () => (await client.query(sql, parameters as unknown[])).rows),
    transaction: <T>(work: (tx: DatabasePort) => Promise<T>) => run(async () => {
      let active = true, begun = false, committing = false;
      let value: T, commit: pg.QueryResult;
      try {
        await client.query("begin");
        begun = true;
        const tx: DatabasePort = {
          async query(sql, parameters) {
            if (!active) throw new Error("The transaction is no longer active.");
            signal?.throwIfAborted();
            return (await client.query(sql, parameters as unknown[])).rows;
          },
          transaction() { throw new Error("Nested transactions are not supported."); },
        };
        value = await work(tx);
        signal?.throwIfAborted();
        active = false;
        committing = true;
        commit = await client.query("commit");
      } catch (error) {
        active = false;
        if (committing) {
          closed = true;
          await end().catch(() => {});
          throw new Error("Transaction commit outcome is unknown.", {cause: error});
        }
        if (begun && !signal?.aborted) {
          try { await client.query("rollback"); }
          catch { closed = true; await end().catch(() => {}); }
        } else { closed = true; await end().catch(() => {}); }
        throw error;
      } finally { active = false; }
      // A completed COMMIT can report ROLLBACK; the server has already ended the transaction.
      if (commit.command !== "COMMIT") throw new Error("Transaction commit failed.");
      return value;
    }),
    close() {
      closed = true;
      return closing ??= end().finally(() => signal?.removeEventListener("abort", abort));
    },
  };
}
