// Regression guard (discovered miss class): computed member access with a
// string-literal key must resolve exactly like dot access. Before the fix the
// binding resolver's `!computed` guard dropped this call entirely.
const c = require('node:crypto');

module.exports = function makeKey() {
  return c['generateKeyPairSync']('rsa', { modulusLength: 2048 });
};
