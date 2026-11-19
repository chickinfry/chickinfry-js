import type { DatabasePort } from "./store.js";

/** Checks transaction identity and settings; detection cannot undo an already completed commit. */
export async function withTransactionState<T>(port: DatabasePort, work: () => Promise<T>): Promise<T> {
  const sql = `select pg_catalog.json_build_array(
    pg_catalog.pg_backend_pid()::pg_catalog.text,
    pg_catalog.extract('epoch', pg_catalog.transaction_timestamp())::pg_catalog.text,
    pg_catalog.current_setting('transaction_read_only'), pg_catalog.current_setting('transaction_isolation'),
    pg_catalog.current_setting('transaction_deferrable'))::pg_catalog.text as transaction_state`;
  const [before] = await port.query(sql, []);
  if (typeof before?.transaction_state !== "string") throw new Error("Could not verify the borrowed transaction state.");
  const result = await work();
  const [after] = await port.query(sql, []);
  if (before.transaction_state !== after?.transaction_state) throw new Error("Transaction state changed during borrowed work.");
  return result;
}
