import { HTTP, OperationError } from "../src/http.js";

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
