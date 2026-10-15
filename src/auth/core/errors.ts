export class AuthError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`Authentication failed (${code}).`);
    this.name = "AuthError";
  }
}
