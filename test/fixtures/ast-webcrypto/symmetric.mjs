// FALSE POSITIVE GUARD: symmetric and hashing WebCrypto operations are not
// quantum-vulnerable. None of these must be flagged.
export const digest = (data) => crypto.subtle.digest('SHA-256', data);
export const aes = () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
export const hmac = (key, data) => crypto.subtle.sign({ name: 'HMAC' }, key, data);
