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

JavaScript 0.5.0 breaks compatibility with the old `auth.browser_*` operation names. Both transports use `auth.signup`, `auth.signin`, `auth.identity`, `auth.session`, and `auth.logout`, with no legacy aliases. Browser session responses contain `id`, `email`, `session_id`, `expires_at`, and `email_verified` (or the logout status), never tokens. Native `auth.session` returns the same session fields, with expiry limited by the stored credential and current session policy. A project authentication cookie or browser marker combined with `Authorization` is rejected before authentication; unrelated cookies do not affect bearer requests. Upgrade the generator and runtime together.

Platform authentication is enabled by a nonempty `auth.methods` or `browser_session: true`. A database alone does not enable it: operations remain anonymous, `/auth.*` is unavailable, and customer handlers receive `Authorization` and `Cookie` unchanged. To use an identity provider, declare `methods: [identity]` in `chik/auth.yml` before registering it in application options; an undeclared provider fails at startup with `declare auth in auth.yml`. Authentication hooks also require an authentication declaration. Enabling authentication requires confirmation when generating, protects operations by default, and removes credential headers from customer requests; mark public operations with `public: true`.

Sessions expire after 30 days without use by default, with no absolute lifetime cap. Native refresh rotation renews this idle deadline; access tokens last 15 minutes and access lookups do not renew it. A successful browser cookie authentication renews the server's idle deadline. Expired or revoked sessions cannot be revived. Refresh reuse revokes the family, and concurrent SDK requests share one refresh and retry each original request once.

With a generator that supports session policies, configure integer seconds in `chik/auth.yml`:

```yaml
auth:
  session:
    idle_timeout_seconds: 2592000
    absolute_lifetime_seconds: 0
```

Idle timeout accepts 3600 through 31536000 seconds. Absolute lifetime accepts the same range, or `0` to disable the cap; it may be shorter than the idle timeout. Invalid values fail rather than being corrected. Current settings apply at the next access, refresh, or cookie validation. Existing users may need to sign in again when a timeout is shortened or an absolute cap is enabled. Apply the additive authentication schema migration before upgrading the runtime. Valid legacy sessions transition on their next normal renewal, preserving family creation as the first-login fallback.

Successful signup, sign-in, identity authentication, and two-step signup verification issue a session cookie; logout revokes the session and deletes it. Required-mode signup returns an accepted response without a cookie. Business responses and session lookups never set or delete cookies, including on 401. Cookie storage lifetime is 400 days when the absolute cap is disabled, or the remaining absolute lifetime otherwise. Server idle expiry still applies while a cookie remains stored. A continuously active browser must sign in again after its cookie expires; browsers may limit storage further. Existing seven-day cookies retain their original storage lifetime until the next sign-in.

Tabs in the same browser profile share cookies, including when several people use that profile in succession. Late authentication responses can replace or delete a newer cookie; a revoked credential remains rejected by the server. Sign out before handing over a shared device.

Local HTTP browser sessions work in Chromium and Firefox; Safari/WebKit does not store this Secure cookie on local HTTP. Use the existing local endpoint without weakening cookie attributes. Remote browser sessions require a same-site HTTPS frontend and API; local browser results do not establish production ingress support.

### Email verification and password reset

Email behavior is opt-in at the runtime boundary. With no email options, signup still issues a session immediately, duplicate addresses return `account_exists` (409), and no mail is sent. A generator can enable verification explicitly with `email: {verification: "required"}`; the runtime requires an injected `AuthMailer` and an HTTPS `emailLinkBase` (HTTP loopback is allowed for development). Apply the generated email authentication migration before enabling these options.

```ts
import { Auth, type AuthMailer } from "@chickinfry/chickinfry-js/auth";

const mailer: AuthMailer = {
  async send(message) {
    await yourMailProvider.send({
      to: message.to,
      subject: message.subject,
      text: message.text,
      html: message.html,
    });
  },
};

const auth = new Auth(databasePort, [], Date.now, {}, {
  email: {verification: "required"},
  mailer,
  emailLinkBase: "https://app.example.com",
  projectName: "Example",
}, runtimeContext);
```

The email link base accepts an absolute HTTPS URL with only `/` and ASCII unreserved characters in its path. Percent encoding, non-ASCII path characters, credentials, queries, and fragments are rejected at startup. HTTP is allowed only for `localhost` and `127.0.0.1`, including an explicit port; IPv6 loopback HTTP is rejected.

With verification required, new and existing signups return `200 {"accepted":true,"attempt":"<opaque id>"}` after a one-second minimum. New addresses receive a six digit verification code; existing accounts receive sign-in and reset-request links. Signup stores a 24-hour attempt, not a user. Each signup keeps its own password and code. At most three active attempts may coexist for one normalized email; further requests return the same response shape without replacing an existing attempt. Attempts expire after 24 hours. The hourly mail budget suppresses mail after three messages per normalized address.

The signup screen retains the returned attempt across reloads, collects the code from the email, and sends `auth.verify_email({attempt,code})`. The attempt is scoped to that signup screen; users do not enter it. Runtime callers use `verifyEmail({attempt}, code)`. Codes contain six digits, expire in ten minutes, and become invalid after five incorrect entries. A new code invalidates the previous code and resets the failed-attempt count. Only email-scoped hashes are stored and comparison uses constant time; codes remain distinct across active attempts for the same email. Invalid, expired, exhausted, and missing codes all return `invalid_code` (400). Successful verification creates the verified user, consumes any invite, runs the creation hook, and issues a session in one transaction; all attempts for that email are deleted. Native responses contain tokens, while browser responses set the session cookie and contain session metadata.

`UserCreationHooks.checkSignup({email})` accepts a normalized email without a database handle and has a five-second deadline. Return `undefined` to continue or `{reject: "message"}` for `signup_rejected` (400). `creating(transaction, user)` runs only at verification in required mode: return `{reject: "message"}` for `user_creation_rejected` (422). Rejection messages must be strings with 1–200 characters after trimming. Exceptions and invalid returns fail with `signup_check_failed` or `user_creation_failed` (500), without the exception message. Creation failures roll back the user, invite consumption, hook writes, and session, retaining the attempt for retry. `committed(user)` runs after commit. Setup adapters must return the result of `userCreating`, rather than discarding it.

With verification required, every unverified user receives `email_not_verified` (403) after a correct password, including accounts created before verification was enabled. That request starts or renews the verification code without issuing a session. Incorrect passwords return `invalid_credentials` (401) with the same hash-verification cost and send no mail. Pending signup attempts are not accounts: their sign-in returns the same `invalid_credentials` (401) as an absent account, regardless of the supplied password. Verifying an existing user issues a native or browser session in the same transaction as recording verification. Required mode rejects unverified sessions at issuance, validation, connection revalidation, and refresh, including sessions issued before the upgrade. No switch timestamp or migration-state option is needed. `email_verified` remains present in sign-in and session responses. Verification off keeps immediate signup and existing session behavior.

For existing users, `auth.send_verification_email({email})` can only renew a live, unexhausted code started by a successful password check. It cannot start verification without that check. Pending signup resends use `auth.send_verification_email({attempt})` or runtime `sendVerificationEmail({attempt})`, changing only that attempt's code. The legacy `{email}` input never resends a signup attempt. Resends and password sign-ins that send a new code must be at least 60 seconds apart and share the hourly mail budget; each new code invalidates the previous one. Unverified sign-ins use the same one-second response floor as email requests. Password reset ignores pending signups and retains the existing behavior for users.

Before enabling required verification, check that your users can receive email at their registered addresses. Users whose email address no longer works cannot sign in.

Public operations are `auth.send_verification_email({attempt})` and `auth.verify_email({attempt,code})` for signup attempts, `auth.send_verification_email({email})` and `auth.verify_email({email,code})` for existing users, `auth.request_password_reset({email})`, and `auth.reset_password({token,password})`. Email requests always return the same accepted response, including when no account exists or a mail budget is exhausted. Verification codes expire in ten minutes; password reset links expire in one hour. Reset tokens are stored hashed and can be consumed once. Resetting a password also verifies an unverified email address, revokes every existing native and browser session, and requires a fresh sign-in. Missing, expired, or used action tokens all return `invalid_token` (400).

Mail is dispatched after commit; failures log only `auth_mail_failed` and the mail kind, without changing the response. Pass the existing runtime context so its `waitUntil` owns asynchronous delivery completion. The injected mailer defines the transport; this package has no platform mail dependency. `developmentAuthMailer()` prints fixed authentication messages, including codes and reset links, to the local development console instead of sending email. These messages contain credentials, so use it only in local development.

The runtime shares a three-message hourly budget per normalized address across verification, reset, and existing-account notices, plus 30 messages per caller IP per hour. The host passes the trusted connection IP as the final `invokeAuth` argument; on Cloudflare use the connection IP supplied by the ingress, never a client-controlled `X-Forwarded-For` header. The router reads no IP header. Without a host IP, requests share a fixed local budget.
