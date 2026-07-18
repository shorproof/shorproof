// Binding style 4/6: ESM namespace import.
// `c` is the whole module namespace; `c.generateKeyPairSync` is the export.
import * as c from 'node:crypto';

export function makeRsaKeypair() {
  return c.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
