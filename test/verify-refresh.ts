import { HTTP, OperationError } from "../src/http.js";

const oldAccessToken = "a".repeat(43);
const newAccessToken = "c".repeat(43);
let accessToken = oldAccessToken;
let refreshToken = "b".repeat(43);
let refreshes = 0;
let cleared = false;
let rejectRefresh = false;
interface Credentials {
  accessToken: string; refreshToken: string; expiresAt: string;
  refreshExpiresAt: string; userId: string; sessionId: string;
}
const store = {
  credentials: (): Credentials => ({accessToken,refreshToken,expiresAt:"2099-01-01T00:00:00Z",refreshExpiresAt:"2099-01-02T00:00:00Z",userId:"user",sessionId:"session"}),
  refresh: async (operation: (credentials: Credentials) => Promise<Credentials>) => {
    const refreshed = await operation({accessToken,refreshToken,expiresAt:"2099-01-01T00:00:00Z",refreshExpiresAt:"2099-01-02T00:00:00Z",userId:"user",sessionId:"session"});
    accessToken = refreshed.accessToken;
    refreshToken = refreshed.refreshToken;
    return refreshed;
  },
  clear: async (expected: Credentials) => {
    if (expected.accessToken !== accessToken || expected.refreshToken !== refreshToken) return;
    accessToken = ""; refreshToken = ""; cleared = true;
  },
};
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(String(input));
  if (url.pathname === "/auth.refresh") {
    refreshes += 1;
    if (rejectRefresh) return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
    if (refreshes > 1) return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
    return new Response(JSON.stringify({access_token:newAccessToken,refresh_token:"d".repeat(43),expires_at:"2099-01-01T00:00:00Z",refresh_expires_at:"2099-01-02T00:00:00Z",user_id:"user",session_id:"session"}),{status:200});
  }
  if (new Headers(init?.headers).get("authorization") !== "Bearer "+newAccessToken) {
    return new Response(JSON.stringify({error:"invalid_token"}),{status:401});
  }
  return new Response("{}",{status:200});
};
try {
  const transport = new HTTP("https://example.com").withSession(store);
  const secondTransport = new HTTP("https://example.com").withSession(store);
  await Promise.all(Array.from({length:8},index => (index%2 ? secondTransport : transport).invoke("catalog.create",{})));
  if (refreshes !== 1 || accessToken !== newAccessToken || refreshToken !== "d".repeat(43) || cleared) {
    throw new Error("refresh state mismatch: "+refreshes+" "+accessToken+" "+refreshToken+" "+cleared);
  }
  rejectRefresh = true;
  accessToken = oldAccessToken;
  refreshToken = "e".repeat(43);
  try {
    await transport.invoke("catalog.create",{});
    throw new Error("rejected refresh was accepted");
  } catch (error) {
    if (!(error instanceof OperationError) || error.status !== 401) throw error;
  }
  if (!cleared || refreshes !== 2) {
    throw new Error("failure state mismatch: "+cleared+" "+refreshes);
  }
} finally {
  globalThis.fetch = originalFetch;
}
