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
