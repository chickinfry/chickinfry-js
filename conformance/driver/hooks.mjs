import {existsSync, readFileSync} from "node:fs";
import {registerHooks, stripTypeScriptTypes} from "node:module";
import {fileURLToPath, pathToFileURL} from "node:url";
import {resolve} from "node:path";

export const hookKey = Symbol.for("chickinfry.conformance.realtime.v1");

// Only the isolated driver loads these hooks; published runtime bytes stay intact.
export function instrument(source) {
  const replace = (before, after) => {
    if (source.split(before).length !== 2) throw new Error("Unsupported realtime instrumentation input.");
    source = source.replace(before, after);
  };
  const hook = 'globalThis[Symbol.for("chickinfry.conformance.realtime.v1")]';
  replace('  function wake(): void {', `  ${hook}.inspect = () => ({pendingReads: pending.size, activeRenewalWatchers: sharedRenewal?.watchers.size ?? 0});\n  function wake(): void {`);
  replace('    deadline ??= setTimeout(() => stop(new ClientError("deadline_exceeded")), 30_000);', `    if (deadline === undefined) ${hook}.budget(initialReady, 30_000);\n    deadline ??= setTimeout(() => stop(new ClientError("deadline_exceeded")), 30_000);`);
  replace('  function gap(cursor: string): void {', `  function gap(cursor: string): void {\n    ${hook}.gap();`);
  replace('        if (frame.previous !== previous || queue.length >= 256) return gap(frame.cursor);', `        if (frame.previous !== previous || queue.length >= 512) {\n          if (queue.length >= 512) ${hook}.overflow();\n          return gap(frame.cursor);\n        }`);
  replace('          recovery = undefined;', `          recovery = undefined;\n          ${hook}.recovered();`);
  replace('        endpoint = realtimeEndpoint(response.endpoint, domain);', `        endpoint = ${hook}.endpoint(response.endpoint);`);
  // Count an actual stale callback reaching the SDK's existing generation guard.
  replace('      if (!active || socket !== ws) return;\n      const frame', `      if (!active || socket !== ws) { ${hook}.discarded(); return; }\n      const frame`);
  return source;
}

export function install(root, sdkPaths) {
  const src = resolve(root, "src");
  return registerHooks({
    resolve(specifier, context, next) {
      let path;
      if (specifier === "@chickinfry/chickinfry") path = resolve(src, "index.ts");
      else if (specifier === "@chickinfry/chickinfry-realtime") path = resolve(src, "realtime/client.ts");
      else if (Object.hasOwn(sdkPaths, specifier)) path = resolve(sdkPaths[specifier], "client.ts");
      else if (specifier.startsWith(".") && specifier.endsWith(".js") && context.parentURL?.startsWith(pathToFileURL(src).href + "/")) {
        const candidate = fileURLToPath(new URL(specifier.slice(0, -3) + ".ts", context.parentURL));
        if (existsSync(candidate)) path = candidate;
      }
      if (path) return {url: pathToFileURL(path).href, shortCircuit: true};
      return next(specifier, context);
    },
    load(url, context, next) {
      if (!url.startsWith("file:") || !url.endsWith(".ts")) return next(url, context);
      let source = readFileSync(fileURLToPath(url), "utf8");
      if (fileURLToPath(url) === resolve(src, "realtime/client.ts")) source = instrument(source);
      return {format: "module", source: stripTypeScriptTypes(source, {mode: "transform", sourceUrl: url}), shortCircuit: true};
    },
  });
}
