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

## License

Apache-2.0. See [LICENSE](./LICENSE).

Browser clients use the generated `createBrowserClient(origin)` when `auth.browser_session` is enabled. The cookie-only transport sends `X-Chik-Browser: 1` with credentials included and never stores tokens, refreshes sessions, or retries operations. Bearer transport omits cookies. Browser sessions use a project-specific HttpOnly, Secure, host-only cookie with SameSite=Strict and an absolute seven-day lifetime.

Local HTTP browser sessions work in Chromium and Firefox; Safari/WebKit does not store this Secure cookie on local HTTP. Use the existing local endpoint without weakening cookie attributes. Remote browser sessions require a same-site HTTPS frontend and API; local browser results do not establish production ingress support.
