import { HTTP, OperationError } from "../src/http.js";

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => ({type: "opaqueredirect", status: 0}) as Response;
try {
  await new HTTP("https://example.com").invoke("catalog.create", {});
  throw new Error("opaque redirect was accepted");
} catch (error) {
  if (!(error instanceof OperationError) || error.code !== "redirect_not_allowed" || error.status !== 0) throw error;
} finally {
  globalThis.fetch = originalFetch;
}
