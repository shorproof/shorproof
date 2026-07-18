// Remaining generateKeyPair key types, plus the unresolved-type review fallback.
import { generateKeyPairSync } from 'node:crypto';

export const pss = () => generateKeyPairSync('rsa-pss', { modulusLength: 2048 });
export const ed448keys = () => generateKeyPairSync('ed448');
export const x448keys = () => generateKeyPairSync('x448');

// Computed key type — not a string literal. Expect a review-level finding,
// because every real generateKeyPair type is vulnerable but we can't say which.
export function dynamic(kind) {
  return generateKeyPairSync(kind, { modulusLength: 2048 });
}
