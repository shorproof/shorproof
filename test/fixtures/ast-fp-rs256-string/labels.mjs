// FALSE POSITIVE GUARD: the token "RS256" appears in a comment and in string
// data, but there is no crypto call here. A scanner that regex-matches "RS256"
// over source text would fire; we only match confirmed AST usage. Nothing here.

// Historical note: this service used to sign with RS256 and ES256.
export const SUPPORTED_ALGS = ['RS256', 'ES256', 'PS256', 'EdDSA'];

export function algLabel(alg) {
  return `Algorithm: ${alg}`;
}

export const DEFAULT_ALG = 'RS256';
