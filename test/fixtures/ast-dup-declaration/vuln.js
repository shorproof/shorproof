// A real vulnerable usage that must still be found even though a sibling file
// (dup.js) makes Babel's scope builder throw "Duplicate declaration". One bad
// file must never hide the findings in its neighbours.
import jwt from 'jsonwebtoken';

export function issue(payload, key) {
  return jwt.sign(payload, key, { algorithm: 'RS256' });
}
