import { strict as assert } from "node:assert";
import { HTTP, BrowserHTTP, OperationError } from "../src/http.js";

const origins: ReadonlyArray<readonly [string, boolean]> = [
  ["http://127.0.0.1", true],
  ["http://127.0.0.0:8012", true],
  ["http://127.255.255.255/", true],
  ["http://[::1]:8012", true],
  ["HTTP://127.0.0.1:80/", true],
  ["http://localhost:8012", false],
  ["http://127.1", false],
  ["http://127.0.1", false],
  ["http://0x7f000001", false],
  ["http://0x7f.0.0.1", false],
  ["http://0177.0.0.1", false],
  ["http://127.00.0.1", false],
  ["http://127.0.0.01", false],
  ["http://2130706433", false],
  ["http://127.0.0.256", false],
  ["http://127.0.0.-1", false],
  ["http://127.0.0.1.", false],
  ["http://%31%32%37.0.0.1", false],
  ["http://127.0.\t0.1", false],
  ["http://[::ffff:127.0.0.1]", false],
  ["http://[::ffff:7f00:1]", false],
  ["http://[0:0:0:0:0:0:0:1]", false],
  ["http://126.255.255.255", false],
  ["http://128.0.0.0", false],
  ["http://192.168.0.1", false],
  ["https://example.com", true],
  ["https://localhost", true],
  ["https://127.1", true],
  ["https://[::ffff:127.0.0.1]", true],
  ["ftp://127.0.0.1", false],
  ["http://user:password@127.0.0.1", false],
  ["https://user:password@example.com", false],
  ["http://127.0.0.1/path", false],
  ["https://example.com/path", false],
  ["http://127.0.0.1?query=1", false],
  ["https://example.com?query=1", false],
  ["http://127.0.0.1#fragment", false],
  ["https://example.com#fragment", false],
];
for (const Transport of [HTTP, BrowserHTTP]) {
  for (const [origin, allowed] of origins) {
    const create = () => new Transport(origin);
    if (allowed) assert.doesNotThrow(create, origin);
    else assert.throws(create, /operation endpoint|Operation endpoint/, origin);
  }
}

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(null, {status: 302, headers: {location: "https://redirect.example"}});
try {
  await new HTTP("https://example.com").invoke("catalog.create", {});
  throw new Error("redirect was followed");
} catch (error) {
  if (!(error instanceof OperationError) || error.code !== "redirect_not_allowed" || error.status !== 302) throw error;
} finally {
  globalThis.fetch = originalFetch;
}

const errorResponses: ReadonlyArray<readonly [string, number, string]> = [
  ["not JSON", 502, "invalid_response"],
  ["{}", 400, "invalid_response"],
  ['{"message":"Rejected."}', 403, "invalid_response"],
  ['{"error":42}', 401, "invalid_response"],
  ['{"error":null}', 500, "invalid_response"],
  ['{"error":"INVALID_TOKEN"}', 401, "invalid_response"],
  ['{"error":""}', 503, "invalid_response"],
  ['{"error":"invalid-token"}', 401, "invalid_response"],
  ["null", 500, "invalid_response"],
  ["[]", 502, "invalid_response"],
  ['{"error":"invalid_token"}', 401, "invalid_token"],
  ['{"error":"operation_failed"}', 500, "operation_failed"],
];
try {
  for (const [body, status, code] of errorResponses) {
    globalThis.fetch = async () => new Response(body, {status});
    await assert.rejects(new HTTP("https://example.com").invoke("catalog.create", {}),
      error => error instanceof OperationError && error.code === code && error.status === status, body);
  }
} finally {
  globalThis.fetch = originalFetch;
}
