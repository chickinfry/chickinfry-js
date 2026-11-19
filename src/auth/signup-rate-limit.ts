import type { SignupRateLimitOptions } from "./core/types.js";

export function resolveSignupRateLimit(input: SignupRateLimitOptions | undefined,
  lookupEnv: (name: string) => string | undefined): Required<SignupRateLimitOptions> {
  if (input !== undefined && (input === null || typeof input !== "object" || Array.isArray(input) ||
    Object.keys(input).some(key => key !== "signal" && key !== "max" && key !== "windowSeconds"))) {
    throw new Error("auth.rate_limits.signup must be an object with signal, max, or window_seconds.");
  }
  const {signal = "email", max = 10, windowSeconds = 900} = input ?? {};
  const declaredSignal = signupSignal(signal, "auth.rate_limits.signup.signal");
  const declaredMax = positiveInteger(max, 2_147_483_647, "auth.rate_limits.signup.max");
  const declaredWindow = positiveInteger(windowSeconds, 31_536_000, "auth.rate_limits.signup.window_seconds");

  const read = (name: string) => {
    try { return lookupEnv(name); }
    catch { throw new Error(`${name} could not be read.`); }
  };
  const signalName = "AUTH_RATE_LIMITS_SIGNUP_SIGNAL";
  return {
    signal: signupSignal(read(signalName) ?? declaredSignal, signalName),
    max: environmentInteger(read, "AUTH_RATE_LIMITS_SIGNUP_MAX", declaredMax, 2_147_483_647),
    windowSeconds: environmentInteger(read, "AUTH_RATE_LIMITS_SIGNUP_WINDOW_SECONDS", declaredWindow, 31_536_000),
  };
}

function signupSignal(value: unknown, field: string): Required<SignupRateLimitOptions>["signal"] {
  if (value !== "email" && value !== "global" && value !== "off") {
    throw new Error(`${field} must be email, global, or off.`);
  }
  return value;
}

function positiveInteger(value: number, maximum: number, field: string): number {
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${field} must be an integer between 1 and ${maximum}.`);
  }
  return value;
}

function environmentInteger(lookupEnv: (name: string) => string | undefined, name: string, fallback: number, maximum: number): number {
  const raw = lookupEnv(name);
  if (raw === undefined) return fallback;
  const value = Number(raw);
  return positiveInteger(String(value) === raw ? value : NaN, maximum, name);
}
