// FALSE POSITIVE GUARD: a local object named `crypto` with a `subtle` shape. It
// has a binding that isn't node:crypto and isn't the free global, so its
// .subtle.generateKey({ name: 'ECDSA' }) must not be flagged.
const crypto = { subtle: { generateKey: () => undefined } };

export const a = () => crypto.subtle.generateKey({ name: 'ECDSA' });
