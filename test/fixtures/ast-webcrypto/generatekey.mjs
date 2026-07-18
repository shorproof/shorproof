// WebCrypto via the global `crypto` (browsers + Node 20+). generateKey is key
// material: RSA is high; EC bare keygen is medium; AES is symmetric (no finding).
export const rsa = () =>
  crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  ); // webcrypto/rsassa-pkcs1-v1_5 high

export const ecKeygen = () =>
  crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']); // webcrypto/ecdsa medium (keygen)

export const aes = () =>
  crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']); // symmetric — no finding
