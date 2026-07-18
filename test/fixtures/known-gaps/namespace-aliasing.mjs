// KNOWN GAP (M3): namespace aliasing. `c2` is a plain re-binding of the crypto
// namespace `c`. Resolving c2.generateKeyPairSync needs recursive binding
// resolution (follow c2 -> c -> namespace), which lands in M3. Today: a MISS.
import * as c from 'node:crypto';

const c2 = c;

export function makeKey() {
  return c2.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
