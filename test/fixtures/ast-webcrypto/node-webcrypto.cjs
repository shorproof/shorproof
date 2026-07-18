// Node's WebCrypto: node:crypto exposes it as `webcrypto`. Host detection must
// resolve the binding, not just match the name `crypto`.
const { webcrypto } = require('node:crypto');

module.exports.gen = () =>
  webcrypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, hash: 'SHA-256' },
    true,
    ['sign'],
  ); // webcrypto/rsa-pss high
