# TypeScript realtime conformance driver

This private Node entrypoint implements protocol 2 and `realtime-v1` for the
RT-DX-01 diagnostic in the shared `sdk-realtime` profile. It is a driver skeleton:
the 13 base SDK cases are explicitly unimplemented and belong to a language-core
follow-up PR. It consumes the product-generated plain/auth SDK
paths supplied by the coordinator and reads credential records only from fd 3.
The auth-free realtime fixture uses `createClient` with `HttpTransport` or
`BrowserHttpTransport`; the shared runner selects the transport and owns faults
and assertions. The generated browser-session entrypoint is checked by the CLI
generator tests separately.

`main.mjs` calls only generated operations, `realtime.subscribe`, `events`, and
`unsubscribe`. Its customer gap callback invokes the generated `probe.list`
operation. It reports observations without reading the suite's expected values.
Observation waits remain concurrent with release and cancellation commands.

`hooks.mjs` is an isolated Node module loader. It loads the pinned runtime source
and generated TypeScript directly, verifies exact instrumentation anchors, sets
the private recovery queue capacity to 512, permits only the runner's exact
loopback WebSocket endpoint, and measures internal receive/cleanup checkpoints.
The original socket callback is retained when dispatch is held, so releasing it
exercises the SDK's existing generation guard. Runtime source and public package
exports are unchanged. None of this directory is included by `npm pack`.

Run the driver checks with `node --test conformance/driver/test.mjs`.
The shared CLI runner rewrites only `driverCommit` in `driver.json` to the
reviewed registry commit; its complete hashed runtime and driver input list is
verified before execution. Recreate that list after changing any listed input.
