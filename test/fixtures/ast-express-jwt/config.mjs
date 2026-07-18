// express-jwt accepts tokens signed with the algorithms in its `algorithms`
// option. A quantum-vulnerable alg there is a real finding; HS256 is safe; the
// array may arrive via a const; no `algorithms` key → nothing to confirm.
import { expressjwt } from 'express-jwt';

const ACCEPTED = ['ES384'];

export const rsa = expressjwt({ secret: 's', algorithms: ['RS256'] }); // express-jwt/rs256 high
export const hmac = expressjwt({ secret: 's', algorithms: ['HS256'] }); // express-jwt/hs256 safe
export const viaConst = expressjwt({ secret: 's', algorithms: ACCEPTED }); // express-jwt/es384 high (const-prop)
export const noAlgs = expressjwt({ secret: 's' }); // no algorithms → no finding
