import {strict as assert} from "node:assert";
import {Repository, defineTable, encodeValue, or} from "../src/orm.js";
import type {DatabasePort, Filter} from "../src/orm.js";

interface Row {id:string; quantity:number; note:string|null}
const table=defineTable<Row>({name:"items",primaryKey:["id"],updateColumns:["quantity","note"],columns:{id:"id",quantity:"quantity",note:{databaseName:"note",encode:value=>encodeValue("string",true,value)}}});
let rows: readonly Record<string,unknown>[]=[];
let calls=0;
let sql="";
let parameters: readonly unknown[]=[];
let failure: Error|undefined;
const port:DatabasePort={async query(query,values){calls++;sql=query;parameters=values;if(failure)throw failure;return rows;},async transaction(work){return work(this);}};
const repo=new Repository<Row,Partial<Row>,Partial<Row>,Pick<Row,"id">>(port,table);
assert.equal(await repo.findById({id:"missing"}),null,"missing findById must return null");
assert.equal(await repo.delete({id:"missing"}),null,"missing delete must return null");
const notFound=(error:unknown)=>error instanceof Error && "code" in error && error.code === "not_found";
await assert.rejects(repo.update({id:"missing"},{note:"new"}),notFound);
await assert.rejects(repo.increment({id:"missing"},{quantity:1}),notFound);
assert.equal(await repo.updateIf({id:"missing"},table.columns.quantity.eq(1),{quantity:2}),undefined);
rows=[{id:"one",quantity:2,note:null}];
assert.deepEqual(await repo.findById({id:"one"}),{id:"one",quantity:2,note:null});
assert.deepEqual(await repo.delete({id:"one"}),{id:"one",quantity:2,note:null});
assert.match(sql,/^delete from "public"\."items" where "id" = \$1 returning /);
assert.deepEqual(parameters,["one"]);
for(const [filter,operator,value] of [
 [table.columns.quantity.eq(1),"=",1],[table.columns.quantity.ne(2),"<>",2],
 [table.columns.quantity.gt(3),">",3],[table.columns.quantity.gte(4),">=",4],
 [table.columns.quantity.lt(5),"<",5],[table.columns.quantity.lte(6),"<=",6],
] as const){await repo.findMany({where:filter});assert.match(sql,new RegExp('where "quantity" '+operator+' \\$1$'));assert.deepEqual(parameters,[value]);}
await repo.findMany({where:table.columns.quantity.isIn([1,2])});
assert.ok(sql.endsWith('where "quantity" in ($1, $2)'));assert.deepEqual(parameters,[1,2]);
await repo.findMany({where:table.columns.quantity.isIn([])});assert.ok(sql.endsWith("where 1 = 0"));
await repo.findMany({where:or(table.columns.note.isIn(["x"]),table.columns.note.isNull())});
assert.ok(sql.endsWith('where ("note" in ($1) or "note" is null)'));assert.deepEqual(parameters,["x"]);
await repo.findMany({where:table.columns.note.isNotNull()});assert.ok(sql.endsWith('where "note" is not null'));
const before=calls;
for(const make of [()=>table.columns.note.eq(null as never),()=>table.columns.note.ne(null as never),()=>table.columns.note.isIn(["x",null] as never)]){
 await assert.rejects(async()=>repo.findMany({where:make()}),/null|NULL/);
}
for(const filter of [{kind:"comparison",column:table.columns.note,operator:"=",value:null},{kind:"in",column:table.columns.note,values:[null]}]){
 await assert.rejects(repo.findMany({where:filter as Filter}),/null|NULL/);
}
assert.equal(calls,before,"null comparisons must never reach the database");
failure=Object.assign(new Error("database unavailable"),{code:"database_failed"});
await assert.rejects(repo.update({id:"one"},{quantity:1}),error=>error === failure);
await assert.rejects(repo.increment({id:"one"},{quantity:1}),error=>error === failure);
