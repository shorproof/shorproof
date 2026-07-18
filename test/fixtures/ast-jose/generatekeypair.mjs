// jose.generateKeyPair(alg) — the alg is the first argument. Classical algs are
// Shor-broken (high); ML-DSA is post-quantum (safe, positive detection).
import { generateKeyPair } from 'jose';

export const ecdsa = () => generateKeyPair('ES256'); // jose/es256 high
export const eddsa = () => generateKeyPair('EdDSA'); // jose/eddsa high
export const postQuantum = () => generateKeyPair('ML-DSA-65'); // jose/ml-dsa-65 safe
