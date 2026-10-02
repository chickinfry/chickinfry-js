import pg from "pg";
import type { DatabasePort } from "./orm.js";

export interface PostgresPort extends DatabasePort {
  close(): Promise<void>;
}

export function createPostgresPort(connectionString: string): PostgresPort {
  let url: URL;
  try { url = new URL(connectionString); }
  catch { throw new Error("Invalid database URL."); }
  if (!["postgres:","postgresql:"].includes(url.protocol) || !url.hostname || !url.username || !url.password || !url.pathname || url.pathname === "/" || url.hash) {
    throw new Error("A complete PostgreSQL URL is required.");
  }
  if (!url.port) url.port = "5432";
  url.searchParams.set("options", `${url.searchParams.get("options") ?? ""} -c datestyle=ISO`);
  const pool = new pg.Pool({ connectionString: url.toString(), types: {
    getTypeParser: (oid, format) => {
      if (format !== "binary" && (oid === 1082 || oid === 1184)) return (value: string) => value;
      return pg.types.getTypeParser(oid, format);
    },
  } });
  pool.on("error", () => console.error("Database idle connection was closed."));
  return {
    async query(sql, parameters) {
      const result = await pool.query(sql, parameters as unknown[]);
      return result.rows;
    },
    async transaction<T>(work: (tx: DatabasePort) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      let broken = false;
      let active = true;
      let begun = false;
      let committing = false;
      try {
        await client.query("begin");
        begun = true;
        const tx: DatabasePort = {
          async query(sql, parameters) {
            if (!active) throw new Error("The transaction is no longer active.");
            const result = await client.query(sql, parameters as unknown[]);
            return result.rows;
          },
          transaction() {
            throw new Error("Nested transactions are not supported.");
          },
        };
        const value = await work(tx);
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
        if (begun) {
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
      await pool.end();
    },
  };
}
