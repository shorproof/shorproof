// jose SignJWT builder: the alg lives in setProtectedHeader({ alg }). The scanner
// walks the chain back to `new SignJWT(...)` bound to jose.
import { SignJWT } from 'jose';

export function classical(payload, key) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'RS256' }).sign(key); // jose/rs256 high
}

export function postQuantum(payload, key) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'ML-DSA-65' }).sign(key); // jose/ml-dsa-65 safe
}
