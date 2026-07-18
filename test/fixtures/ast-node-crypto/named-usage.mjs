// node:crypto vulnerable usage via named ESM imports (direct-call bindings).
// Note: the `signer.sign(...)` / `verifier.verify(...)` method calls below must
// NOT be flagged as one-shot crypto.sign/verify — `signer` resolves to a local
// createSign() result, not to the node:crypto module.
import {
  createSign,
  createVerify,
  createECDH,
  publicEncrypt,
  privateDecrypt,
  generateKeyPair,
  generateKeyPairSync,
} from 'node:crypto';

export function signRsa(privateKey, data) {
  const signer = createSign('sha256'); // crypto/create-sign
  signer.update(data);
  return signer.sign(privateKey);
}

export function verifyRsa(publicKey, data, sig) {
  const verifier = createVerify('sha256'); // crypto/create-verify
  verifier.update(data);
  return verifier.verify(publicKey, sig);
}

export function exchange() {
  return createECDH('secp256k1'); // crypto/create-ecdh
}

export function seal(publicKey, buf) {
  return publicEncrypt(publicKey, buf); // crypto/public-encrypt
}

export function open(privateKey, buf) {
  return privateDecrypt(privateKey, buf); // crypto/private-decrypt
}

export function ecKeys() {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); // crypto/generate-keypair-ec
}

export function edKeys() {
  return generateKeyPairSync('ed25519'); // crypto/generate-keypair-ed25519
}

export function xKeys() {
  return generateKeyPairSync('x25519'); // crypto/generate-keypair-x25519
}

export function dsaKeys(cb) {
  return generateKeyPair('dsa', { modulusLength: 2048 }, cb); // crypto/generate-keypair-dsa
}
