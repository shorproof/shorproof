// jsonwebtoken sign with an explicit algorithm option. RS/PS/ES families are
// classical asymmetric signatures (Shor-broken) → high; HS is HMAC → safe.
import jwt from 'jsonwebtoken';

export const rsa = (p, k) => jwt.sign(p, k, { algorithm: 'RS256' }); // jsonwebtoken/rs256 high
export const pss = (p, k) => jwt.sign(p, k, { algorithm: 'PS384' }); // jsonwebtoken/ps384 high
export const ecdsa = (p, k) => jwt.sign(p, k, { algorithm: 'ES256' }); // jsonwebtoken/es256 high
export const hmac = (p, k) => jwt.sign(p, k, { algorithm: 'HS256' }); // jsonwebtoken/hs256 safe
