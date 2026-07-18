// jsonwebtoken verify carries the algorithm list under `algorithms` (an array).
// A quantum-vulnerable alg in the accepted list is a finding.
const { verify } = require('jsonwebtoken');

module.exports.check = (t, k) => verify(t, k, { algorithms: ['ES512'] }); // jsonwebtoken/es512 high
