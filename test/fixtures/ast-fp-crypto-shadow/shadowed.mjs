// FALSE POSITIVE GUARD: none of these must be flagged.
// A name-based scanner that matches `crypto.generateKeyPairSync(...)` or
// `jwt.sign(...)` by identifier text would fire on every line here. We resolve
// bindings, so a local object — or a shadowing declaration — is never the lib.
import crypto from 'node:crypto';

// 1. A local object literal that happens to be named `crypto`.
const notCrypto = { generateKeyPairSync: () => 'fake' };
export const a = notCrypto.generateKeyPairSync('rsa');

// 2. A function parameter named `crypto` — shadows nothing real.
export function withParam(crypto) {
  return crypto.generateKeyPairSync('rsa');
}

// 3. A block-scoped shadow of the real import: inside here `crypto` is a plain
//    object, so its `.generateKeyPairSync('rsa')` call is NOT node:crypto.
export function shadowed() {
  const crypto = { generateKeyPairSync: () => 'still fake' };
  return crypto.generateKeyPairSync('rsa');
}

// 4. A variable named `jwt` that is not jsonwebtoken.
const jwt = { sign: (payload) => JSON.stringify(payload) };
export const b = jwt.sign({ ok: true });

// The real import above is intentionally never used with a vulnerable call.
void crypto;
