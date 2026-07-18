// FALSE POSITIVE GUARD: SHA-256 hashing, HMAC, and random bytes are NOT
// quantum-vulnerable. shorproof must never flag SHA-256 as a risk (a competing
// tool does — it is factually wrong). Correct output: nothing.
import { createHash, createHmac, randomBytes } from 'node:crypto';

export function fingerprint(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function mac(key, data) {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function token() {
  return randomBytes(32).toString('hex');
}
