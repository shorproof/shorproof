// FALSE POSITIVE GUARD: a local object named `jwt` that is not jsonwebtoken. Its
// .sign({ algorithm: 'RS256' }) must not be flagged — the binding isn't the lib.
const jwt = { sign: (opts) => JSON.stringify(opts) };

export const a = () => jwt.sign({ algorithm: 'RS256' });
