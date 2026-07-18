// globalThis.crypto is the same WebCrypto object.
export const gen = () =>
  globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign']); // webcrypto/ed25519 medium (keygen)
