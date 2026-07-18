// Recursive binding resolution (M3): namespace aliasing. `c2` re-binds the crypto
// namespace `c`; the resolver follows c2 -> c -> namespace. (Was a known-gaps canary in M2.)
import * as c from 'node:crypto';

const c2 = c;

export function makeKey() {
  return c2.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
