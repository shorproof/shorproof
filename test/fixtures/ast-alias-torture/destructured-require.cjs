// Binding style 3/6: destructured require.
// `generateKeyPairSync` is pulled straight out of the require() call. The
// binding's declarator init is a require('node:crypto') call.
const { generateKeyPairSync } = require('node:crypto');

function makeRsaKeypair() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

module.exports = { makeRsaKeypair };
