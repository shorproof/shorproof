// Best-effort constant propagation: the options object and the alg value may be
// referenced through const bindings rather than written inline.
import { sign } from 'jsonwebtoken';

const OPTS = { algorithm: 'RS512' };
const ALG = 'PS256';

export const viaObject = (p, k) => sign(p, k, OPTS); // jsonwebtoken/rs512 high (opts object resolved)
export const viaAlgConst = (p, k) => sign(p, k, { algorithm: ALG }); // jsonwebtoken/ps256 high (alg const resolved)
