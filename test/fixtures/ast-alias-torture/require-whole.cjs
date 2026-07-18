// Binding style 5/6: whole-module require.
// `nodeCrypto` is bound to the entire module object via require(); the
// vulnerable export is reached through member access.
const nodeCrypto = require('node:crypto');

function makeRsaKeypair() {
  return nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

module.exports = { makeRsaKeypair };
