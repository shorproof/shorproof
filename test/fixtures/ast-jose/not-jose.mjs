// FALSE POSITIVE GUARD: a local class named SignJWT that is not jose. Its
// .setProtectedHeader({ alg: 'RS256' }) must not be flagged — the constructor
// doesn't resolve to a jose import.
class SignJWT {
  setProtectedHeader() {
    return this;
  }
  sign() {
    return '';
  }
}

export function a() {
  return new SignJWT().setProtectedHeader({ alg: 'RS256' }).sign();
}
