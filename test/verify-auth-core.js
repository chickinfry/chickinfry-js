import assert from "node:assert/strict";
import test from "node:test";
import { readFile, readdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { resolve, dirname, relative, join, sep } from "node:path";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { createScanner, SyntaxKind, LanguageVariant } from "typescript/unstable/ast";
import { build } from "esbuild";
import * as rules from "../dist/auth/core/rules.js";
import { Auth } from "../dist/auth/runtime.js";
import { coreVersion } from "../dist/auth/core/version.js";

const root = resolve("src/auth/core");

async function sources(directory) {
  const entries = await readdir(directory, {withFileTypes: true});
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? sources(join(directory, entry.name))
    : entry.name.endsWith(".ts") ? [join(directory, entry.name)] : []))).flat();
}

function moduleSpecifiers(text) {
  const scanner = createScanner(true, LanguageVariant.Standard, text);
  const tokens = [];
  for (let kind = scanner.scan(); kind !== SyntaxKind.EndOfFile; kind = scanner.scan()) {
    tokens.push({kind, text: scanner.getTokenText(), value: scanner.getTokenValue()});
  }
  const names = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if ((token.kind === SyntaxKind.FromKeyword || token.kind === SyntaxKind.ImportKeyword)
      && tokens[i + 1]?.kind === SyntaxKind.StringLiteral) names.push(tokens[i + 1].value);
    if ((token.kind === SyntaxKind.ImportKeyword || token.text === "require")
      && tokens[i + 1]?.kind === SyntaxKind.OpenParenToken) {
      assert.equal(tokens[i + 2]?.kind, SyntaxKind.StringLiteral, "Nonliteral module reference");
      names.push(tokens[i + 2].value);
    }
  }
  return names;
}

test("core imports stay inside the core and approved crypto primitives", async () => {
  for (const file of await sources(root)) {
    for (const name of moduleSpecifiers(await readFile(file, "utf8"))) {
      /** Node URL conversion validates ACE labels on Node and compatible Workers hosts. */
      if (name === "node:crypto" || name === "node:buffer" || name === "node:url") continue;
      assert.ok(name.startsWith("."), `Forbidden core import: ${relative(root, file)} -> ${name}`);
      const target = resolve(dirname(file), name).replace(/\.js$/, ".ts");
      assert.ok(target.startsWith(root + sep), `Forbidden core import: ${relative(root, file)} -> ${name}`);
    }
  }
  for (const file of await sources(resolve("src/auth"))) {
    if ([resolve("src/auth/store.ts"), resolve("src/auth/private/database.ts")].includes(file)) continue;
    for (const name of moduleSpecifiers(await readFile(file, "utf8"))) {
      const target = resolve(dirname(file), name).replace(/\.js$/, ".ts");
      assert.ok(!["pg", "pg-cloudflare"].includes(name)
        && ![resolve("src/orm.ts"), resolve("src/postgres.ts"), resolve("src/auth/private/database.ts")].includes(target),
        `ORM import outside auth adapter: ${relative(resolve("src/auth"), file)}`);
    }
  }
});

test("core rule vectors are deterministic without an ambient clock", async () => {
  const cases = (await Promise.all(["rules.json", "email.json"].map(async file =>
    JSON.parse(await readFile(join(root, "testdata", file), "utf8"))))).flat();
  const clock = Date.now;
  try {
    Date.now = () => { throw new Error("Ambient clock read by core rules."); };
    for (const c of cases) {
      const before = JSON.stringify(c.args);
      const invoke = () => rules[c.rule](...c.args) ?? null;
      if (c.error) {
        assert.throws(invoke, c.error, c.name);
        assert.throws(invoke, c.error, c.name);
      } else {
        assert.deepEqual(invoke(), c.expected, c.name);
        assert.deepEqual(invoke(), c.expected, c.name);
      }
      assert.equal(JSON.stringify(c.args), before, c.name);
    }
  } finally { Date.now = clock; }
  console.log(`Validated ${cases.length} core rule vectors.`);
});

test("core builds as one independent ES module and runtime carries its version", async () => {
  const directory = await mkdtemp(join(tmpdir(), "chik-auth-core-"));
  try {
    const path = join(directory, "core.mjs");
    const result = await build({stdin: {
      contents: 'export * from "./src/auth/core/flows.ts"; export * from "./src/auth/core/crypto.ts"; export * from "./src/auth/core/rules.ts"; export * from "./src/auth/core/version.ts";',
      resolveDir: resolve("."), loader: "ts",
    }, bundle: true, platform: "node", format: "esm", outfile: path, write: false, metafile: true});
    assert.equal(result.outputFiles.length, 1);
    assert.ok(Object.keys(result.metafile.inputs).every(file => file === "<stdin>" || resolve(file).startsWith(root + sep)));
    await writeFile(path, result.outputFiles[0].contents);
    const core = await import(pathToFileURL(path).href);
    assert.equal(core.coreVersion, coreVersion);
    assert.equal(core.coreVersion, "0.1.0");
    assert.equal(typeof core.Flows, "function");
    const auth = new Auth({query() { throw new Error("Unexpected I/O"); }, transaction() { throw new Error("Unexpected I/O"); }});
    assert.equal(auth.coreVersion, coreVersion);
    assert.deepEqual(core.sessionPolicy(), rules.sessionPolicy());
    console.log(`Independent core module: ${path}, ${result.outputFiles[0].contents.byteLength} bytes.`);
  } finally { await rm(directory, {recursive: true, force: true}); }
});
