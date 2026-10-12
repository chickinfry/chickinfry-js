import pg from "pg";
import type { DatabasePort } from "./orm.js";

/** The cleanup port's connection wait is part of the same budget that aborts the whole cleanup task. */
export const cleanupBudgetMillis = 5_000;

export interface PostgresPort extends DatabasePort {
  close(): Promise<void>;
}

export function createPostgresPort(connectionString: string, signal?: AbortSignal): PostgresPort {
  let url: URL;
  try { url = new URL(connectionString); }
  catch { throw new Error("Invalid database URL."); }
  if (!["postgres:","postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password || !url.pathname || url.pathname === "/" || url.hash) {
    throw new Error("A complete PostgreSQL URL is required.");
  }
  if (!url.port) url.port = "5432";
  url.searchParams.set("options", `${url.searchParams.get("options") ?? ""} -c datestyle=ISO`);
  const pool = new pg.Pool({ connectionString: url.toString(),
    ...(signal ? {connectionTimeoutMillis: cleanupBudgetMillis} : {}), types: {
    getTypeParser: (oid, format) => {
      if (format !== "binary" && (oid === 1082 || oid === 1184)) return (value: string) => value;
      return pg.types.getTypeParser(oid, format);
    },
  } });
  pool.on("error", () => console.error("Database idle connection was closed."));
  const clients = new Set<pg.PoolClient>();
  const abort = () => {
    for (const client of clients) void client.end().catch(() => {});
  };
  if (signal) {
    pool.on("connect", client => {
      clients.add(client);
      if (signal.aborted) void client.end().catch(() => {});
    });
    pool.on("remove", client => clients.delete(client));
    signal.addEventListener("abort", abort, {once: true});
  }
  return {
    async query(sql, parameters) {
      signal?.throwIfAborted();
      const result = await pool.query(sql, parameters as unknown[]);
      return result.rows;
    },
    async transaction<T>(work: (tx: DatabasePort) => Promise<T>): Promise<T> {
      signal?.throwIfAborted();
      const client = await pool.connect();
      let broken = false;
      let active = true;
      let begun = false;
      let committing = false;
      try {
        signal?.throwIfAborted();
        await client.query("begin");
        begun = true;
        const tx: DatabasePort = {
          async query(sql, parameters) {
            if (!active) throw new Error("The transaction is no longer active.");
            signal?.throwIfAborted();
            const result = await client.query(sql, parameters as unknown[]);
            return result.rows;
          },
          transaction() {
            throw new Error("Nested transactions are not supported.");
          },
        };
        const value = await work(tx);
        signal?.throwIfAborted();
        active = false;
        committing = true;
        await client.query("commit");
        return value;
      } catch (error) {
        active = false;
        if (committing) {
          broken = true;
          throw new Error("Transaction commit outcome is unknown.", { cause: error });
        }
        if (begun && !signal?.aborted) {
          try { await client.query("rollback"); }
          catch { broken = true; }
        } else {
          broken = true;
        }
        throw error;
      } finally {
        active = false;
        client.release(broken ? new Error("the transaction connection is no longer usable") : undefined);
      }
    },
    async close() {
      try { await pool.end(); }
      finally { signal?.removeEventListener("abort", abort); }
    },
  };
}
