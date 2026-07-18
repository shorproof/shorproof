// Binding style 1/6: ESM default import.
// Node builtins expose the whole module as the default export, so `crypto`
// here is namespace-like and `crypto.generateKeyPairSync` is the vulnerable call.
import crypto from 'node:crypto';

export function makeRsaKeypair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
