// Binding style 6/6: dynamic import().
// `crypto` is bound to the awaited module namespace of a dynamic import.
const crypto = await import('node:crypto');

export function makeRsaKeypair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}
