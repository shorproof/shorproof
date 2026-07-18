// KNOWN GAP (M3): method extraction. `g` is the generateKeyPairSync function
// pulled off the namespace, then called. Resolving this needs recursive binding
// resolution (follow g -> c.generateKeyPairSync -> namespace c), which lands in
// M3 alongside constant propagation. Today this is a MISS by design.
import * as c from 'node:crypto';

const g = c.generateKeyPairSync;

export function makeKey() {
  return g('rsa', { modulusLength: 2048 });
}
