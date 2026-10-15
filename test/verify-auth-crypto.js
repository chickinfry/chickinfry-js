import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { verifyPassword } from "../dist/auth/core/crypto.js";

const vectors = JSON.parse(await readFile(new URL("../src/auth/core/testdata/passwords.json", import.meta.url), "utf8"));

for (const language of ["go", "rust"]) {
  test(`core verifies pinned ${language} password vectors without exposing values`, async () => {
    const source = vectors.sources[language];
    assert.match(source.sha, /^[a-f0-9]{40}$/);
    const cases = vectors.cases.filter(c => c.language === language);
    assert.ok(cases.length > 0);
    for (const c of cases) {
      const actual = await verifyPassword(c.password, c.stored);
      assert.ok(actual === c.expected, `${c.name} password verification differs`);
    }
    console.log(`${language}: ${cases.length} cases, ${cases.length} passed, 0 failed.`);
  });
}
