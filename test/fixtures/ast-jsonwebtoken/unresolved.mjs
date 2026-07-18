// The algorithm can't be resolved statically (computed at runtime). We confirmed
// a jsonwebtoken sign, but not which alg — so a review-level finding, never a
// confident classical one.
import jwt from 'jsonwebtoken';

export const dynamic = (p, k, pickAlg) => jwt.sign(p, k, { algorithm: pickAlg() }); // jsonwebtoken/review review
