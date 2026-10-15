import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

const prefix = "scrypt$32768$8$3$";
const format = /^scrypt\$32768\$8\$3\$([a-f0-9]{32})\$([a-f0-9]{64})$/;

function derive(password: string, salt: Uint8Array): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 32, { N: 32768, r: 8, p: 3, maxmem: 64 << 20 }, (error, key) => {
      if (error) reject(new Error("Password hashing failed."));
      else resolve(key);
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await derive(password, salt);
  return prefix + salt.toString("hex") + "$" + key.toString("hex");
}

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  const parts = stored === null ? null : format.exec(stored);
  const salt = parts ? Buffer.from(parts[1]!, "hex") : Buffer.alloc(16);
  const expected = parts ? Buffer.from(parts[2]!, "hex") : Buffer.alloc(32);
  const actual = await derive(password, salt);
  const matched = timingSafeEqual(actual, expected);
  return parts !== null && matched;
}

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
