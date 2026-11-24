import type { Repository } from "./orm.js";

export const insertIfAbsentKey: unique symbol = /* @__PURE__ */ Symbol("insertIfAbsent");

export function insertIfAbsent<Row extends object, Insert extends object, Update extends object, Key extends object>(
  repository: Repository<Row, Insert, Update, Key>,
  row: NoInfer<Insert & Key>,
): Promise<boolean> {
  return repository[insertIfAbsentKey](row);
}
