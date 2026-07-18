// THE PHILOSOPHY PROOF: a service that has already migrated to post-quantum jose,
// using ML-DSA-65 for both keygen and signing. The correct output is SAFE — a
// positive "already quantum-safe" finding, and crucially NOT a single high/
// vulnerable finding. This is the false-positive test the whole product rests on.
import { SignJWT, generateKeyPair } from 'jose';

export const keys = () => generateKeyPair('ML-DSA-65');

export function sign(payload, key) {
  return new SignJWT(payload).setProtectedHeader({ alg: 'ML-DSA-65' }).sign(key);
}
