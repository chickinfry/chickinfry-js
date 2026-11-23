# Release notes — @chickinfry/chickinfry 0.5.0

This is the release where the generator and the runtime upgrade together. The
0.4.x line never shipped session policy or device authorization.

## Breaking changes

### Browser operations use the native names

`auth.browser_signup`, `auth.browser_signin`, `auth.browser_identity`,
`auth.browser_session`, and `auth.browser_logout` are removed. Both transports call
`auth.signup`, `auth.signin`, `auth.identity`, `auth.session`, and `auth.logout`.
The runtime router returns `auth_operation_removed` for a removed name and
identifies the replacement in the error message.

Browser session responses carry `id`, `email`, `session_id`, `expires_at`, and
`email_verified`, or the logout status. They never carry tokens. Native
`auth.session` returns the same fields.

### The database subpath is not exported

`@chickinfry/chickinfry/postgres` is not in the published package. Database access
goes through the `DatabasePort` the host injects. The package therefore carries no
`pg` dependency.

## Features

- Session policy with `idle_timeout_seconds` (3600–31536000) and
  `absolute_lifetime_seconds` (same range, or 0 to disable). Invalid values fail
  instead of being corrected.
- RFC 8628 device authorization, including the node store that keeps sessions and
  pending signup attempts across processes.
- Host lease runtime at `./auth/runtime` for generated servers that already hold a
  transaction.
- Signup rate limits, email verification and password reset, and signup hooks
  limited to five seconds.
- Logging entry point that redacts server console output against a secret snapshot.
- ORM filter names and missing-row results aligned with the other runtimes.
- Private realtime client with async subscriptions and gap recovery, bundled into
  the generated server and not exported.
- The reserved `/api` path may follow the server origin, such as
  `https://app.example.com/api`, so a web app reaches its server through its own
  origin. No other path is accepted.

## Session policy by server language

The generator accepts `auth.session` declarations for TypeScript, Go, Rust,
Dart, Kotlin, Python and Swift. Server language availability in release builds
also depends on runtime publication and the CLI's server compatibility checks.

## Upgrade

1. Upgrade the generator and this runtime together.
2. Apply the additive authentication schema migration before starting the runtime.
3. Replace any `auth.browser_*` call with the unified name.
4. Move any `@chickinfry/chickinfry/postgres` import to the host-injected
   `DatabasePort`. The CLI must carry the host-port change first; without it a
   TypeScript project pinned to 0.5.0 fails at `tsc`.

Rollback per registry is in [docs/release-rollback.md](./docs/release-rollback.md).
