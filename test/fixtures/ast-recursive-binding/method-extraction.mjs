// Recursive binding resolution (M3): method extraction. `g` is generateKeyPairSync
// pulled off the crypto namespace, then called. The resolver follows
// g -> c.generateKeyPairSync -> namespace c. (Was a known-gaps canary in M2.)
import * as c from 'node:crypto';

const g = c.generateKeyPairSync;

export function makeKey() {
  return g('rsa', { modulusLength: 2048 });
}
