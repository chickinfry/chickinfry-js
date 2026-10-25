export interface DatabasePort {
  query(sql: string, parameters: readonly unknown[]): Promise<readonly Record<string, unknown>[]>;
  transaction<T>(work: (tx: DatabasePort) => Promise<T>): Promise<T>;
}

type StringKey<Row> = Extract<keyof Row, string>;
type ComparisonOperator = "=" | "<>" | ">" | ">=" | "<" | "<=";
const comparisonOperators = new Set<string>(["=", "<>", ">", ">=", "<", "<="]);

interface AnyColumn {
  readonly propertyName: string;
  readonly databaseName: string;
  encodeDatabaseValue(value: unknown): unknown;
  decodeDatabaseValue(value: unknown): unknown;
}

interface ComparisonFilter {
  readonly kind: "comparison";
  readonly column: AnyColumn;
  readonly operator: ComparisonOperator;
  readonly value: unknown;
}

interface InFilter {
  readonly kind: "in";
  readonly column: AnyColumn;
  readonly values: readonly unknown[];
}

interface NullFilter {
  readonly kind: "null";
  readonly column: AnyColumn;
  readonly negate: boolean;
}

interface LogicalFilter {
  readonly kind: "and" | "or";
  readonly filters: readonly Filter[];
}

interface NotFilter {
  readonly kind: "not";
  readonly filter: Filter;
}

export type Filter = ComparisonFilter | InFilter | NullFilter | LogicalFilter | NotFilter;

export interface Order {
  readonly column: AnyColumn;
  readonly direction: "asc" | "desc";
}

export class GeneratedColumn<Value> implements AnyColumn {
  constructor(
    readonly propertyName: string,
    readonly databaseName: string,
    private readonly encodeValue: (value: Value) => unknown,
    private readonly decodeValue: (value: unknown) => Value,
  ) {}

  eq(value: NonNullable<Value>): Filter {
    return comparison(this, "=", value);
  }

  ne(value: NonNullable<Value>): Filter {
    return comparison(this, "<>", value);
  }

  gt(value: NonNullable<Value>): Filter {
    return comparison(this, ">", value);
  }

  gte(value: NonNullable<Value>): Filter {
    return comparison(this, ">=", value);
  }

  lt(value: NonNullable<Value>): Filter {
    return comparison(this, "<", value);
  }

  lte(value: NonNullable<Value>): Filter {
    return comparison(this, "<=", value);
  }

  isIn(values: readonly NonNullable<Value>[]): Filter {
    if (!Array.isArray(values)) throw new Error("in filter values must be an array.");
    const copy = [...values];
    if (copy.some((value) => value === undefined || value === null)) throw new Error("Filter values cannot be null or undefined; use isNull or isNotNull.");
    return { kind: "in", column: this, values: copy };
  }

  isNull(): Filter {
    return { kind: "null", column: this, negate: false };
  }

  isNotNull(): Filter {
    return { kind: "null", column: this, negate: true };
  }

  asc(): Order {
    return { column: this, direction: "asc" };
  }

  desc(): Order {
    return { column: this, direction: "desc" };
  }

  encodeDatabaseValue(value: unknown): unknown {
    try {
      return this.encodeValue(value as Value);
    } catch (error) {
      throw columnCodecError(this, "input encoding", error);
    }
  }

  decodeDatabaseValue(value: unknown): Value {
    try {
      return this.decodeValue(value);
    } catch (error) {
      throw columnCodecError(this, "result decoding", error);
    }
  }
}

export interface ColumnCodec<Value> {
  readonly databaseName: string;
  readonly encode?: ((value: Value) => unknown) | undefined;
  readonly decode?: ((value: unknown) => Value) | undefined;
}

export interface TableDefinitionInput<Row extends object> {
  readonly name: string;
  readonly primaryKey: readonly StringKey<Row>[];
  readonly insertColumns?: readonly StringKey<Row>[] | undefined;
  readonly requiredInsertColumns?: readonly StringKey<Row>[] | undefined;
  readonly updateColumns?: readonly StringKey<Row>[] | undefined;
  readonly columns: { readonly [Key in StringKey<Row>]: string | ColumnCodec<Row[Key]> };
  readonly constraints?: Readonly<Partial<Record<StringKey<Row>, ColumnConstraint>>>;
}

export interface ColumnConstraint {
  readonly unique: boolean;
  readonly references: string;
}

export interface TableDefinition<Row extends object> {
  readonly name: string;
  readonly primaryKey: readonly StringKey<Row>[];
  readonly insertColumns: readonly StringKey<Row>[];
  readonly requiredInsertColumns: readonly StringKey<Row>[];
  readonly updateColumns: readonly StringKey<Row>[];
  readonly columnOrder: readonly StringKey<Row>[];
  readonly columns: { readonly [Key in StringKey<Row>]: GeneratedColumn<Row[Key]> };
  readonly constraints: Readonly<Partial<Record<StringKey<Row>, ColumnConstraint>>>;
}

const declaredColumnsByTable = new WeakMap<object, ReadonlySet<AnyColumn>>();

export function defineTable<Row extends object>(input: TableDefinitionInput<Row>): TableDefinition<Row> {
  assertIdentifier(input.name, "table");
  const columnOrder = Object.keys(input.columns) as StringKey<Row>[];
  const databaseNames = new Set<string>();
  const columns = {} as { [Key in StringKey<Row>]: GeneratedColumn<Row[Key]> };
  for (const key of columnOrder) {
    const definition = input.columns[key];
    if (typeof definition !== "string"
      && (typeof definition !== "object" || definition === null || Array.isArray(definition))) {
      throw new Error(`Column ${String(key)} definition must be a database name or codec object.`);
    }
    const databaseName = typeof definition === "string" ? definition : definition.databaseName;
    assertIdentifier(databaseName, `column ${String(key)}`);
    if (databaseNames.has(databaseName)) {
      throw new Error(`Duplicate database column: ${databaseName}`);
    }
    databaseNames.add(databaseName);
    const codec = typeof definition === "string" ? { databaseName: definition } : definition;
    columns[key] = new GeneratedColumn<Row[StringKey<Row>]>(
      String(key),
      databaseName,
      codec.encode ?? ((value: Row[StringKey<Row>]) => value),
      codec.decode ?? ((value: unknown) => value as Row[StringKey<Row>]),
    );
  }
  if (columnOrder.length === 0) throw new Error("A table requires at least one column.");
  if (input.primaryKey.length === 0 || input.primaryKey.some((key) => !Object.hasOwn(columns, key))) {
    throw new Error("The primary key must reference at least one generated column.");
  }
  const primaryKey = [...input.primaryKey];
  if (new Set(primaryKey).size !== primaryKey.length) {
    throw new Error("The primary key cannot contain duplicate columns.");
  }
  const primaryKeySet = new Set<StringKey<Row>>(primaryKey);
  const insertColumns = input.insertColumns === undefined ? [...columnOrder] : [...input.insertColumns];
  checkColumnList(insertColumns, columns, "insert", false);
  const insertColumnSet = new Set<StringKey<Row>>(insertColumns);
  const requiredInsertColumns = input.requiredInsertColumns === undefined ? [] : [...input.requiredInsertColumns];
  checkColumnList(requiredInsertColumns, columns, "required insert", false);
  if (requiredInsertColumns.some((column) => !insertColumnSet.has(column))) {
    throw new Error("A required insert column must be an insert column.");
  }
  const updateColumns = input.updateColumns === undefined
    ? columnOrder.filter((column) => !primaryKeySet.has(column))
    : [...input.updateColumns];
  checkColumnList(updateColumns, columns, "update", false);
  if (updateColumns.some((column) => primaryKeySet.has(column))) {
    throw new Error("A primary key column cannot be updated.");
  }
  const definition: TableDefinition<Row> = {
    name: input.name,
    primaryKey,
    insertColumns,
    requiredInsertColumns,
    updateColumns,
    columnOrder,
    columns,
    constraints: input.constraints ?? ({} as TableDefinition<Row>["constraints"]),
  };
  declaredColumnsByTable.set(definition, new Set(Object.values(columns as Record<string, AnyColumn>)));
  return definition;
}

function checkColumnList<Row extends object>(
  list: readonly StringKey<Row>[],
  columns: TableDefinition<Row>["columns"],
  label: string,
  allowDuplicates: boolean,
): void {
  if (!allowDuplicates && new Set(list).size !== list.length) {
    throw new Error(`${label} columns cannot contain duplicates.`);
  }
  for (const column of list) {
    if (!Object.hasOwn(columns, column)) throw new Error(`Unknown ${label} column: ${String(column)}`);
  }
}

export function and(...filters: readonly Filter[]): Filter {
  if (filters.length === 0) throw new Error("An and filter requires at least one condition.");
  return { kind: "and", filters };
}

export function or(...filters: readonly Filter[]): Filter {
  if (filters.length === 0) throw new Error("An or filter requires at least one condition.");
  return { kind: "or", filters };
}

export function not(filter: Filter): Filter {
  return { kind: "not", filter };
}

export interface FindManyOptions<Row extends object> {
  readonly where?: Filter | ((columns: TableDefinition<Row>["columns"]) => Filter) | undefined;
  readonly orderBy?: Order | readonly Order[] | ((columns: TableDefinition<Row>["columns"]) => Order | readonly Order[]) | undefined;
  readonly limit?: number | undefined;
  readonly offset?: number | undefined;
}

type NumericIncrementFields<Update extends object> = {
  [Key in StringKey<Update> as NonNullable<Update[Key]> extends number ? Key : never]: number;
};
export type IncrementValues<Update extends object> =
  keyof NumericIncrementFields<Update> extends never ? never : Partial<NumericIncrementFields<Update>>;

export class Repository<
  Row extends object,
  Insert extends object = Partial<Row>,
  Update extends object = Partial<Row>,
  PrimaryKey extends object = Partial<Row>,
> {
  constructor(
    private readonly database: DatabasePort,
    readonly table: TableDefinition<Row>,
  ) {}

  async findMany(options: FindManyOptions<Row> = {}): Promise<Row[]> {
    const parameters: unknown[] = [];
    let sql = `select ${this.selectList()} from ${quoteIdentifier(this.table.name, "table")}`;
    const where = typeof options.where === "function" ? options.where(this.table.columns) : options.where;
    if (options.where !== undefined) sql += ` where ${compileFilter(where as Filter, this.table, parameters)}`;
    const requestedOrder = typeof options.orderBy === "function" ? options.orderBy(this.table.columns) : options.orderBy;
    if (options.orderBy !== undefined && requestedOrder === undefined) throw new Error("Order callback must return a declared order.");
    const orderBy = requestedOrder === undefined ? [] : Array.isArray(requestedOrder) ? requestedOrder : [requestedOrder];
    if (orderBy.length > 0) {
      sql += ` order by ${orderBy.map(({ column, direction }) => {
        const validatedColumn = validateTableColumn(column, this.table);
        if (direction !== "asc" && direction !== "desc") {
          throw new Error(`Unsupported sort direction: ${String(direction)}`);
        }
        return `${quoteIdentifier(validatedColumn.databaseName, "column")} ${direction}`;
      }).join(", ")}`;
    }
    if (options.limit !== undefined) {
      assertNonNegativeInteger(options.limit, "limit");
      parameters.push(options.limit);
      sql += ` limit $${parameters.length}`;
    }
    if (options.offset !== undefined) {
      assertNonNegativeInteger(options.offset, "offset");
      parameters.push(options.offset);
      sql += ` offset $${parameters.length}`;
    }
    return this.mapRows(await this.database.query(sql, parameters));
  }

  async findById(key: PrimaryKey): Promise<Row | null> {
    return (await this.findMany({ where: this.primaryKeyFilter(key), limit: 1 }))[0] ?? null;
  }

  async insert(row: Insert): Promise<Row> {
    return this.insertRow(row,false);
  }

  async upsert(row: Insert & PrimaryKey): Promise<Row> {
    return this.insertRow(row,true);
  }

  private async insertRow(row: Insert, upsert: boolean): Promise<Row> {
    const record = inputRecord(row, "insert");
    assertKnownInputColumns(record, this.table.insertColumns, "insert");
    for (const column of this.table.requiredInsertColumns) {
      if (!Object.hasOwn(record, column) || record[column] === undefined) {
        throw new Error(`Missing required insert column value: ${String(column)}`);
      }
    }
    const keys = this.table.insertColumns.filter((key) => Object.hasOwn(record, key) && record[key] !== undefined);
    let sql = keys.length === 0
      ? `insert into ${quoteIdentifier(this.table.name, "table")} default values`
      : `insert into ${quoteIdentifier(this.table.name, "table")} (${keys.map((key) => quoteIdentifier(this.table.columns[key].databaseName, "column")).join(", ")}) values (${keys.map((key, index) => `$${index + 1}`).join(", ")})`;
    if (upsert) {
      for (const key of this.table.primaryKey) {
        if (!keys.includes(key)) throw new Error("Upsert requires every primary key value.");
      }
      const mutable = keys.filter(key => !this.table.primaryKey.includes(key));
      if (mutable.length === 0) throw new Error("Upsert requires mutable values.");
      const primary = this.table.primaryKey.map(key => quoteIdentifier(this.table.columns[key].databaseName,"column"));
      const assignments = mutable.map(key => {
        const column = quoteIdentifier(this.table.columns[key].databaseName,"column");
        return `${column} = excluded.${column}`;
      });
      sql += ` on conflict (${primary.join(", ")}) do update set ${assignments.join(", ")}`;
    }
    sql += ` returning ${this.selectList()}`;
    const parameters = keys.map((key) => this.table.columns[key].encodeDatabaseValue(record[key]));
    return this.requireRow(await this.database.query(sql, parameters), "insert");
  }

  async update(key: PrimaryKey, patch: Update): Promise<Row> {
    const row = await this.updateMatching(this.primaryKeyFilter(key), patch);
    if (row === undefined) throw Object.assign(new Error("Update target was not found."), {code:"not_found"});
    return row;
  }

  async updateIf(
    key: PrimaryKey,
    condition: Filter | ((columns: TableDefinition<Row>["columns"]) => Filter),
    patch: Update,
  ): Promise<Row | undefined> {
    const filter = typeof condition === "function" ? condition(this.table.columns) : condition;
    return this.updateMatching(and(this.primaryKeyFilter(key), filter), patch);
  }

  async increment(key: PrimaryKey, columns: IncrementValues<Update>): Promise<Row> {
    const record = inputRecord(columns, "increment");
    assertKnownInputColumns(record, this.table.updateColumns, "increment");
    const keys = this.table.updateColumns.filter((column) => Object.hasOwn(record, column) && record[column] !== undefined);
    if (keys.length === 0) throw new Error("No columns to increment.");
    const parameters: unknown[] = [];
    const assignments = keys.map((column) => {
      const amount = record[column];
      if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount === 0) {
        throw new Error("Increment amounts must be non-zero safe integers.");
      }
      parameters.push(amount);
      const name = quoteIdentifier(this.table.columns[column].databaseName, "column");
      return `${name} = ${name} + $${parameters.length}`;
    });
    const where = compileFilter(this.primaryKeyFilter(key), this.table, parameters);
    const sql = `update ${quoteIdentifier(this.table.name, "table")} set ${assignments.join(", ")} where ${where} returning ${this.selectList()}`;
    return this.requireRow(await this.database.query(sql, parameters), "increment");
  }

  async incrementIf(
    key: PrimaryKey,
    condition: Filter | ((columns: TableDefinition<Row>["columns"]) => Filter),
    columns: IncrementValues<Update>,
    patch: Update,
  ): Promise<Row | undefined> {
    const incrementRecord = inputRecord(columns, "increment");
    const updateRecord = inputRecord(patch, "update");
    assertKnownInputColumns(incrementRecord, this.table.updateColumns, "increment");
    assertKnownInputColumns(updateRecord, this.table.updateColumns, "update");
    const incrementKeys = this.table.updateColumns.filter((column) => Object.hasOwn(incrementRecord, column) && incrementRecord[column] !== undefined);
    const updateKeys = this.table.updateColumns.filter((column) => Object.hasOwn(updateRecord, column) && updateRecord[column] !== undefined);
    if (incrementKeys.length === 0 || updateKeys.length === 0) throw new Error("Increment updates require both increment and set columns.");
    if (incrementKeys.some((column) => updateKeys.includes(column))) throw new Error("A column cannot be incremented and set together.");
    const parameters: unknown[] = [];
    const assignments = incrementKeys.map((column) => {
      const amount = incrementRecord[column];
      if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount === 0) {
        throw new Error("Increment amounts must be non-zero safe integers.");
      }
      parameters.push(amount);
      const name = quoteIdentifier(this.table.columns[column].databaseName, "column");
      return `${name} = ${name} + $${parameters.length}`;
    });
    assignments.push(...updateKeys.map((column) => {
      const tableColumn = this.table.columns[column];
      parameters.push(tableColumn.encodeDatabaseValue(updateRecord[column]));
      return `${quoteIdentifier(tableColumn.databaseName, "column")} = $${parameters.length}`;
    }));
    const filter = typeof condition === "function" ? condition(this.table.columns) : condition;
    const where = compileFilter(and(this.primaryKeyFilter(key), filter), this.table, parameters);
    const sql = `update ${quoteIdentifier(this.table.name, "table")} set ${assignments.join(", ")} where ${where} returning ${this.selectList()}`;
    return this.mapRows(await this.database.query(sql, parameters))[0];
  }

  private async updateMatching(filter: Filter, patch: Update): Promise<Row | undefined> {
    const record = inputRecord(patch, "update");
    assertKnownInputColumns(record, this.table.updateColumns, "update");
    const keys = this.table.updateColumns.filter((column) => Object.hasOwn(record, column) && record[column] !== undefined);
    if (keys.length === 0) throw new Error("No columns to update.");
    const parameters: unknown[] = [];
    const assignments = keys.map((column) => {
      const tableColumn = this.table.columns[column];
      parameters.push(tableColumn.encodeDatabaseValue(record[column]));
      return `${quoteIdentifier(tableColumn.databaseName, "column")} = $${parameters.length}`;
    });
    const where = compileFilter(filter, this.table, parameters);
    const sql = `update ${quoteIdentifier(this.table.name, "table")} set ${assignments.join(", ")} where ${where} returning ${this.selectList()}`;
    return this.mapRows(await this.database.query(sql, parameters))[0];
  }

  async delete(key: PrimaryKey): Promise<Row | null> {
    const parameters: unknown[] = [];
    const where = compileFilter(this.primaryKeyFilter(key), this.table, parameters);
    const sql = `delete from ${quoteIdentifier(this.table.name, "table")} where ${where} returning ${this.selectList()}`;
    return this.mapRows(await this.database.query(sql, parameters))[0] ?? null;
  }

  private primaryKeyFilter(key: PrimaryKey): Filter {
    const record = inputRecord(key, "primary key");
    assertKnownInputColumns(record, this.table.primaryKey, "primary key");
    const filters = this.table.primaryKey.map((column) => {
      if (!Object.hasOwn(record, column) || record[column] === undefined) {
        throw new Error(`Missing primary key value: ${String(column)}`);
      }
      return comparison(this.table.columns[column], "=", record[column]);
    });
    return filters.length === 1 ? filters[0]! : and(...filters);
  }

  private selectList(): string {
    return this.table.columnOrder
      .map((key) => quoteIdentifier(this.table.columns[key].databaseName, "column"))
      .join(", ");
  }

  private mapRows(rows: readonly Record<string, unknown>[]): Row[] {
    return rows.map((databaseRow) => {
      if (typeof databaseRow !== "object" || databaseRow === null || Array.isArray(databaseRow)) {
        throw new TypeError(`${this.table.name} database row must be an object.`);
      }
      const row: Partial<Row> = {};
      for (const key of this.table.columnOrder) {
        const databaseName = this.table.columns[key].databaseName;
        if (!Object.hasOwn(databaseRow, databaseName)) throw new Error(`Database result column is missing: ${databaseName}`);
        row[key] = this.table.columns[key].decodeDatabaseValue(databaseRow[databaseName]) as Row[typeof key];
      }
      return row as Row;
    });
  }

  private requireRow(rows: readonly Record<string, unknown>[], operation: string): Row {
    const row = this.mapRows(rows)[0];
    if (!row && operation === "increment") throw Object.assign(new Error("Increment target was not found."), {code:"not_found"});
    if (!row) throw new Error(`${operation} result row is missing.`);
    return row;
  }
}

function comparison(column: AnyColumn, operator: ComparisonOperator, value: unknown): Filter {
  if (value === undefined || value === null) throw new Error("Filter values cannot be null or undefined; use isNull or isNotNull.");
  return { kind: "comparison", column, operator, value };
}

function compileFilter(
  filter: Filter,
  table: object,
  parameters: unknown[],
  ancestors = new Set<object>(),
): string {
  if (typeof filter !== "object" || filter === null || Array.isArray(filter)) {
    throw new Error("Filter must be an object.");
  }
  if (ancestors.has(filter)) throw new Error("Cyclic filter structures are not supported.");
  ancestors.add(filter);
  try {
    switch (filter.kind) {
      case "comparison": {
        const column = validateTableColumn(filter.column, table);
        const operator = validateComparisonOperator(filter.operator);
        if (filter.value === undefined || filter.value === null) throw new Error("Filter values cannot be null or undefined; use isNull or isNotNull.");
        const encodedValue = column.encodeDatabaseValue(filter.value);
        if (encodedValue === null) throw new Error("Use isNull or isNotNull for SQL NULL.");
        parameters.push(encodedValue);
        return `${quoteIdentifier(column.databaseName, "column")} ${operator} $${parameters.length}`;
      }
      case "in": {
        const column = validateTableColumn(filter.column, table);
        if (!Array.isArray(filter.values)) throw new Error("in filter values must be an array.");
        if (filter.values.some((value) => value === undefined || value === null)) {
          throw new Error("Filter values cannot be null or undefined; use isNull or isNotNull.");
        }
        if (filter.values.length === 0) return "1 = 0";
        const encoded = filter.values.map((value) => column.encodeDatabaseValue(value));
        if (encoded.some((value) => value === null)) throw new Error("Use isNull or isNotNull for SQL NULL.");
        const placeholders = encoded.map((value) => {
          parameters.push(value);
          return `$${parameters.length}`;
        });
        return `${quoteIdentifier(column.databaseName, "column")} in (${placeholders.join(", ")})`;
      }
      case "null": {
        const column = validateTableColumn(filter.column, table);
        if (typeof filter.negate !== "boolean") {
          throw new Error("Null filter negate must be a boolean.");
        }
        return `${quoteIdentifier(column.databaseName, "column")} is ${filter.negate ? "not " : ""}null`;
      }
      case "and":
      case "or": {
        if (!Array.isArray(filter.filters) || filter.filters.length === 0) {
          throw new Error("A logical filter requires at least one child.");
        }
        return `(${filter.filters.map((child) => compileFilter(child, table, parameters, ancestors)).join(` ${filter.kind} `)})`;
      }
      case "not":
        return `not (${compileFilter(filter.filter, table, parameters, ancestors)})`;
      default:
        throw new Error("Unsupported filter kind.");
    }
  } finally {
    ancestors.delete(filter);
  }
}

function validateComparisonOperator(value: unknown): ComparisonOperator {
  if (typeof value !== "string" || !comparisonOperators.has(value)) {
    throw new Error("Unsupported comparison operator.");
  }
  return value as ComparisonOperator;
}

function validateTableColumn(column: unknown, table: object): AnyColumn {
  const declaredColumns = declaredColumnsByTable.get(table);
  if (!declaredColumns?.has(column as AnyColumn)) {
    throw new Error("Undeclared table columns cannot be used.");
  }
  return column as AnyColumn;
}

function columnCodecError(column: AnyColumn, operation: string, error: unknown): TypeError {
  const reason = error instanceof Error ? error.message : "Unknown codec error.";
  return new TypeError(`${column.propertyName}(${column.databaseName}) column ${operation} failed: ${reason}`);
}

function assertIdentifier(value: string, kind: string): void {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error(`${kind} identifier is invalid: ${String(value)}`);
  }
}

function quoteIdentifier(value: string, kind: string): string {
  assertIdentifier(value, kind);
  return `${kind === "table" ? '"public".' : ""}"${value.replaceAll('"', '""')}"`;
}

function assertNonNegativeInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a safe integer of at least 0.`);
}

function inputRecord(value: object, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} input must be an object.`);
  }
  return value as Record<string, unknown>;
}

function assertKnownInputColumns(
  record: Record<string, unknown>,
  allowedColumns: readonly string[],
  label: string,
): void {
  const allowed = new Set<string>(allowedColumns);
  for (const column of Object.keys(record)) {
    if (!allowed.has(column)) {
      throw new Error(`Unknown ${label} column: ${column}`);
    }
  }
}

export function encodeIntegerValue(value: number | null): unknown {
  if (value === null) return null;
  if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) throw new Error("Integer values must be signed 32-bit integers.");
  return value;
}

export function decodeIntegerValue(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < -2147483648 || value > 2147483647) {
    throw new Error("Database integer values must decode to signed 32-bit integers.");
  }
  return value;
}

const datePattern = /^\d{4}-\d{2}-\d{2}$/;

export function encodeDateValue(value: string | null): unknown {
  if (value === null) return null;
  if (typeof value !== "string" || !datePattern.test(value) || value.startsWith("0000")) throw new Error("Date values must use YYYY-MM-DD.");
  const parsed = new Date(value + "T00:00:00.000Z");
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0,10) !== value) throw new Error("Date value is invalid.");
  return value;
}

export function decodeDateValue(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Database date values must decode to YYYY-MM-DD.");
  }
  encodeDateValue(value);
  return value;
}

export function encodeTimestampValue(value: string | null): unknown {
  if (value === null) return null;
  return normalizeTimestamp(value);
}

export function decodeTimestampValue(value: unknown): string {
  if (typeof value !== "string") throw new Error("Database timestamp must preserve its text precision.");
  return normalizeTimestamp(value);
}

function normalizeTimestamp(value: string): string {
  if (typeof value !== "string") throw new Error("Timestamp must be a string.");
  const normalized = value.replace(" ","T").replace(/([+-]\d{2})$/, "$1:00");
  const parts = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/.exec(normalized);
  if (!parts || Number(parts[2])>23 || Number(parts[3])>59 || Number(parts[4])>59) throw new Error("Timestamp must include a valid time and timezone.");
  encodeDateValue(parts[1]!);
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) throw new Error("Timestamp is invalid.");
  const iso = parsed.toISOString();
  if (!/^\d{4}-/.test(iso) || iso.startsWith("0000")) throw new Error("Timestamp is outside the supported calendar range.");
  return iso.replace(/\.\d{3}Z$/, "."+(parts[5] ?? "").padEnd(3,"0")+"Z");
}

export function encodeValue(kind: string, nullable: boolean, value: unknown): unknown {
  if (value === null) {
    if (!nullable) throw new Error("A non-null column cannot accept null.");
    return null;
  }
  switch (kind) {
    case "string":
      if (typeof value !== "string" || value.includes("\0")) throw new Error("A text column requires a string without NUL.");
      return value;
    case "id":
      if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new Error("An ID column requires a UUID.");
      return value.toLowerCase();
    case "integer":
      if (typeof value !== "number") throw new Error("An integer column requires a number.");
      return encodeIntegerValue(value);
    case "date":
      if (typeof value !== "string") throw new Error("A date column requires a string.");
      return encodeDateValue(value);
    case "timestamp":
      if (typeof value !== "string") throw new Error("A timestamp column requires a string.");
      return encodeTimestampValue(value);
    default: throw new Error("Unsupported scalar kind.");
  }
}

/** Decodes database values without changing date or timestamp precision. */
export function decodeValue(kind: string, nullable: boolean, value: unknown): unknown {
  return encodeValue(kind, nullable, value);
}
