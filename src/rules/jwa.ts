import type { AlgOutcome } from '../types.ts';

/**
 * JWA / COSE algorithm knowledge base: an `alg` value → its outcome, shared by
 * every JWT library (jsonwebtoken, jose, and the middleware configs). One
 * algorithm, one verdict, wherever it appears.
 *
 * Severity follows the brand's philosophy:
 * - RSA / RSA-PSS / ECDSA / EdDSA signing in a JWT is a confirmed auth usage —
 *   `high` (context-confirmed usage escalates; see CLAUDE.md severity section).
 * - HMAC (HS***) is symmetric — `safe`, reported as positive detection.
 * - ML-DSA (FIPS 204 / RFC 9964) is post-quantum — `safe`, "already PQ ✓".
 *
 * Every `why` is written to survive cryptographer review.
 */

const SIG_MIGRATION = 'Move signing to ML-DSA (FIPS 204) — available in jose ≥ v6 or Node 24.7+.';

function rsaSig(alg: string): AlgOutcome {
  return {
    severity: 'high',
    category: 'signature',
    algorithm: `RSA (${alg})`,
    confidence: 'high',
    lifetimeSensitive: false,
    why: `JWT signed with ${alg} (RSA PKCS#1 v1.5) — RSA signatures are broken by Shor’s algorithm.`,
    migration: SIG_MIGRATION,
  };
}

function pssSig(alg: string): AlgOutcome {
  return {
    severity: 'high',
    category: 'signature',
    algorithm: `RSA-PSS (${alg})`,
    confidence: 'high',
    lifetimeSensitive: false,
    why: `JWT signed with ${alg} (RSA-PSS) — RSA signatures are broken by Shor’s algorithm.`,
    migration: SIG_MIGRATION,
  };
}

function ecSig(alg: string, curve: string): AlgOutcome {
  return {
    severity: 'high',
    category: 'signature',
    algorithm: `ECDSA (${alg}, ${curve})`,
    confidence: 'high',
    lifetimeSensitive: false,
    why: `JWT signed with ${alg} (ECDSA on ${curve}) — elliptic-curve signatures are broken by Shor’s algorithm.`,
    migration: SIG_MIGRATION,
  };
}

function hmac(alg: string): AlgOutcome {
  return {
    severity: 'safe',
    category: 'symmetric',
    algorithm: `HMAC (${alg})`,
    confidence: 'high',
    lifetimeSensitive: false,
    why: `JWT signed with ${alg} (HMAC) — symmetric, not affected by Shor’s algorithm. Ensure a high-entropy secret.`,
    migration: '',
  };
}

function mldsa(alg: string): AlgOutcome {
  return {
    severity: 'safe',
    category: 'signature',
    algorithm: alg,
    confidence: 'high',
    lifetimeSensitive: false,
    why: `JWT signed with ${alg} (FIPS 204) — a NIST post-quantum signature. Already quantum-safe.`,
    migration: '',
  };
}

export const JWA_ALGS: Readonly<Record<string, AlgOutcome>> = Object.freeze({
  // RSA PKCS#1 v1.5 signatures
  RS256: rsaSig('RS256'),
  RS384: rsaSig('RS384'),
  RS512: rsaSig('RS512'),
  // RSA-PSS signatures
  PS256: pssSig('PS256'),
  PS384: pssSig('PS384'),
  PS512: pssSig('PS512'),
  // ECDSA signatures
  ES256: ecSig('ES256', 'P-256'),
  ES384: ecSig('ES384', 'P-384'),
  ES512: ecSig('ES512', 'P-521'),
  ES256K: ecSig('ES256K', 'secp256k1'),
  // EdDSA signatures (Ed25519 / Ed448)
  EdDSA: {
    severity: 'high',
    category: 'signature',
    algorithm: 'EdDSA (Ed25519/Ed448)',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'JWT signed with EdDSA (Ed25519/Ed448) — elliptic-curve signatures are broken by Shor’s algorithm.',
    migration: SIG_MIGRATION,
  },
  // HMAC — symmetric, safe
  HS256: hmac('HS256'),
  HS384: hmac('HS384'),
  HS512: hmac('HS512'),
  // ML-DSA (FIPS 204 / RFC 9964) — post-quantum, safe
  'ML-DSA-44': mldsa('ML-DSA-44'),
  'ML-DSA-65': mldsa('ML-DSA-65'),
  'ML-DSA-87': mldsa('ML-DSA-87'),
});
