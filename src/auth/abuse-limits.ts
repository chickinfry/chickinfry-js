import type { AbuseLimitOptions } from "./core/types.js";
import { positiveInteger, environmentInteger } from "./signup-rate-limit.js";

// Each limit is declared in AuthOptions.abuseLimits and may be overridden by its
// environment variable. The third column is only the fallback when neither is set.
const limits = [
  ["mailWindowSeconds", "AUTH_RATE_LIMITS_MAIL_WINDOW_SECONDS", 3_600, 31_536_000],
  ["mailAddressMax", "AUTH_RATE_LIMITS_MAIL_ADDRESS_MAX", 3, 2_147_483_647],
  ["mailIpMax", "AUTH_RATE_LIMITS_MAIL_IP_MAX", 30, 2_147_483_647],
  ["pendingSignupMax", "AUTH_RATE_LIMITS_PENDING_SIGNUP_MAX", 3, 1_000],
  ["defaultMax", "AUTH_RATE_LIMITS_DEFAULT_MAX", 10, 2_147_483_647],
  ["defaultWindowSeconds", "AUTH_RATE_LIMITS_DEFAULT_WINDOW_SECONDS", 900, 31_536_000],
] as const;

export function resolveAbuseLimits(input: AbuseLimitOptions | undefined,
  lookupEnv: (name: string) => string | undefined): Required<AbuseLimitOptions> {
  if (input !== undefined && (input === null || typeof input !== "object" || Array.isArray(input) ||
    Object.keys(input).some(key => !limits.some(([name]) => name === key)))) {
    throw new Error("auth.abuse_limits must be an object of the documented limit names.");
  }
  const read = (name: string) => {
    try { return lookupEnv(name); }
    catch { throw new Error(`${name} could not be read.`); }
  };
  const resolved: Record<string, number> = {};
  for (const [name, variable, fallback, maximum] of limits) {
    const declared = positiveInteger(input?.[name] ?? fallback, maximum, `auth.abuse_limits.${name}`);
    resolved[name] = environmentInteger(read, variable, declared, maximum);
  }
  return resolved as Required<AbuseLimitOptions>;
}
