import { HttpTransport, ClientError } from "../src/http.js";

const originalFetch = globalThis.fetch;
globalThis.fetch = async () => ({type: "opaqueredirect", status: 0}) as Response;
try {
  await new HttpTransport("https://example.com").invoke("catalog.create", {});
  throw new Error("opaque redirect was accepted");
} catch (error) {
  if (!(error instanceof ClientError) || error.code !== "internal" || error.status !== undefined) throw error;
} finally {
  globalThis.fetch = originalFetch;
}
