// FALSE POSITIVE GUARD: sign without an options object can't be confirmed to use
// a vulnerable alg (jsonwebtoken defaults to HS256, which is safe). No finding.
import jwt from 'jsonwebtoken';

export const a = (p, k) => jwt.sign(p, k);
