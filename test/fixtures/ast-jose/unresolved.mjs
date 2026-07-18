// The alg is computed at runtime — a jose keygen is confirmed but the algorithm
// isn't, so a review-level finding, never a confident classical one.
import { generateKeyPair } from 'jose';

export const dynamic = (pickAlg) => generateKeyPair(pickAlg()); // jose/review review
