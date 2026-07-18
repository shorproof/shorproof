// Namespace-imported builder class + a builder held in a variable (not an inline
// chain). Both must resolve: new jose.SignJWT(...) stored in `s`, then
// s.setProtectedHeader({ alg }).
import * as jose from 'jose';

export function viaNamespace(payload, key) {
  const s = new jose.SignJWT(payload);
  s.setProtectedHeader({ alg: 'ES384' }); // jose/es384 high
  return s.sign(key);
}
