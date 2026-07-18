// node:crypto vulnerable usage via whole-module require (namespace-member bindings).
const crypto = require('node:crypto');

function dh() {
  return crypto.createDiffieHellman(2048); // crypto/create-diffie-hellman
}

function dhGroup() {
  return crypto.createDiffieHellmanGroup('modp14'); // crypto/create-diffie-hellman-group
}

function signOneShot(key, data) {
  return crypto.sign('sha256', data, key); // crypto/sign
}

function verifyOneShot(key, data, sig) {
  return crypto.verify('sha256', data, key, sig); // crypto/verify
}

function rsaKeys() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 3072 }); // crypto/generate-keypair-rsa
}

module.exports = { dh, dhGroup, signOneShot, verifyOneShot, rsaKeys };
