# @chickinfry/chickinfry-js

Shared TypeScript runtime for Chickinfry generated clients and servers.
Generated code provides your application's typed services, models, and
repositories; this package provides their transport, authentication, and ORM
runtime.

## Install

```sh
npm install @chickinfry/chickinfry-js
```

This package uses ECMAScript modules (ESM).

## Usage

Generated clients use the HTTP transport to call your application's declared
operations. You can also call an operation directly:

```js
import { HTTP } from "@chickinfry/chickinfry-js";

const transport = new HTTP("https://api.example.com");
const result = await transport.invoke("catalog.list", {});
console.log(result);
```

Replace the endpoint and operation with those from your application. Endpoints
must be HTTPS origins, or HTTP origins with an explicit loopback IP address for
local development. Authenticated operations use
`transport.withBearer(accessToken).invoke(...)`.

## Entry points

- `@chickinfry/chickinfry-js`: HTTP transport, operation errors, session
  refresh, and the type-safe ORM core.
- `@chickinfry/chickinfry-js/auth`: authentication runtime for generated servers.
- `@chickinfry/chickinfry-js/postgres`: PostgreSQL adapter for generated repositories.
- `@chickinfry/chickinfry-js/logging`: server console redaction with a secret snapshot.

The logging entry point guards the server's global console when imported. Run
server work inside `runWithLogRedaction({values, databaseURL}, work)`; asynchronous
descendants retain that snapshot. Logs outside a snapshot are discarded and
counted. Console arguments become one safe string; format placeholders remain
literal, getters and custom inspectors are not called, and logging failures do
not change the work result. The root client entry point does not change console.
Direct output streams and exception records collected by the execution host are
separate paths and are not covered by console redaction. Console message
arguments are masked, but metadata that the execution host attaches to console
records, such as function names in call stacks, is a separate path and is not
masked. Matching is per record: secret fragments split across separate log
calls are not recombined, so reassembling them across records is not protected.
Only exact bound values and database URL/password percent escapes are matched,
not arbitrary encodings or credentials issued during a request.

## License

Apache-2.0. See [LICENSE](./LICENSE).

Browser clients use the generated `createBrowserClient(origin)` when `auth.browser_session` is enabled. The cookie-only transport sends `X-Chik-Browser: 1` with credentials included and never stores tokens or retries operations. Bearer transport omits cookies. Browser sessions use a project-specific HttpOnly, Secure, host-only cookie with SameSite=Strict.

Sessions expire after 30 days without use by default, with no absolute lifetime cap. Native refresh rotation renews this idle deadline; access tokens last 15 minutes and access lookups do not renew it. A successful browser cookie authentication renews the server's idle deadline. Expired or revoked sessions cannot be revived. Refresh reuse revokes the family, and concurrent SDK requests share one refresh and retry each original request once.

With a generator that supports session policies, configure integer seconds in `chik/auth.yml`:

```yaml
auth:
  session:
    idle_timeout_seconds: 2592000
    absolute_lifetime_seconds: 0
```

Idle timeout accepts 3600 through 31536000 seconds. Absolute lifetime accepts the same range, or `0` to disable the cap; it may be shorter than the idle timeout. Invalid values fail rather than being corrected. Current settings apply at the next access, refresh, or cookie validation. Existing users may need to sign in again when a timeout is shortened or an absolute cap is enabled. Apply the additive authentication schema migration before upgrading the runtime. Valid legacy sessions transition on their next normal renewal, preserving family creation as the first-login fallback.

Only successful signup, sign-in, and identity authentication issue a new cookie; logout revokes the session and deletes it. Business responses and session lookups never set or delete cookies, including on 401. Cookie storage lifetime is 400 days when the absolute cap is disabled, or the remaining absolute lifetime otherwise. Server idle expiry still applies while a cookie remains stored. A continuously active browser must sign in again after its cookie expires; browsers may limit storage further. Existing seven-day cookies retain their original storage lifetime until the next sign-in.

Tabs in the same browser profile share cookies, including when several people use that profile in succession. Late authentication responses can replace or delete a newer cookie; a revoked credential remains rejected by the server. Sign out before handing over a shared device.

Local HTTP browser sessions work in Chromium and Firefox; Safari/WebKit does not store this Secure cookie on local HTTP. Use the existing local endpoint without weakening cookie attributes. Remote browser sessions require a same-site HTTPS frontend and API; local browser results do not establish production ingress support.
