// Confirmed WebCrypto usage escalates EC from medium to high, per the severity
// principle. RSA-OAEP encryption is a harvest-now-decrypt-later case.
export async function signEc(key, data) {
  return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data); // webcrypto/ecdsa high (confirmed usage)
}

export async function ecdh(baseKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  ); // webcrypto/ecdh high (key agreement)
}

export async function rsaEncrypt(key, data) {
  return crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data); // webcrypto/rsa-oaep high
}
