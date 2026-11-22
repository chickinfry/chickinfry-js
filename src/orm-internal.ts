import type { Repository } from "./orm.js";

type InsertIfAbsent = <Row extends object, Insert extends object, Update extends object, Key extends object>(
  repository: Repository<Row, Insert, Update, Key>,
  row: NoInfer<Insert & Key>,
) => Promise<boolean>;

export let insertIfAbsent: InsertIfAbsent;

export function registerInsertIfAbsent(operation: InsertIfAbsent): void {
  insertIfAbsent = operation;
}
