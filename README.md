# @chickinfry/chickinfry-js

Shared TypeScript runtime for Chickinfry generated clients and servers.

Generated code imports this package; application code normally does not need
to use it directly.

## Entry points

- `@chickinfry/chickinfry-js` — HTTP transport with session refresh, operation
  errors, and the type-safe ORM core.
- `@chickinfry/chickinfry-js/auth` — authentication core used by generated
  servers (signup, signin, session verification, token rotation, rate limits).
- `@chickinfry/chickinfry-js/postgres` — PostgreSQL adapter for the ORM.

## Development

```
npm install
npm run build
npm test
```

The private authentication repository under `src/auth/private` is generated
from the compiler schema and must not be edited. Regenerate it from a
chickinfry CLI checkout:

```
go run ./internal/authpackage /path/to/this/package/src
```

Tests run without a database. The transport check uses a mocked `fetch`.
