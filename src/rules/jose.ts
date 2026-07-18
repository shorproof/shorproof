import type { JwtCallRule } from '../types.ts';

/**
 * jose detection config.
 *
 * jose is the post-quantum-capable JWT library: it supports classical algs
 * (RS/PS/ES/EdDSA — Shor-broken) AND ML-DSA (FIPS 204 / RFC 9964). So detection
 * here is where positive detection earns its keep — an ML-DSA usage must come
 * out `safe`, not silent and not flagged.
 *
 * Two call shapes carry the algorithm:
 * - `generateKeyPair('ES256')` — the alg is the first argument (handled as a
 *   direct-arg JwtCallRule below).
 * - `new SignJWT(payload).setProtectedHeader({ alg: 'ES256' })` — a builder; the
 *   alg is the `alg` key of setProtectedHeader's object, detected structurally
 *   by the scanner (see JOSE_SIGN_BUILDERS).
 */

const REVIEW_WHY =
  'A jose signing/keygen call was confirmed, but its algorithm couldn’t be resolved statically — check whether it is classical (RS/PS/ES/EdDSA, Shor-broken) or post-quantum (ML-DSA).';
const REVIEW_MIGRATION =
  'Pin the algorithm; jose ≥ v6 supports ML-DSA (FIPS 204) directly if you need to migrate off a classical alg.';

export const JOSE_RULES = [
  {
    modules: ['jose'],
    export: 'generateKeyPair',
    algArgIndex: 0,
    algIsArray: false,
    ruleIdPrefix: 'jose',
    reviewRuleId: 'jose/review',
    reviewTitle: 'jose.generateKeyPair — unresolved algorithm',
    reviewWhy: REVIEW_WHY,
    reviewMigration: REVIEW_MIGRATION,
  },
] as const satisfies readonly JwtCallRule[];

/**
 * jose signing builders whose `.setProtectedHeader({ alg })` carries a JWS
 * algorithm. The scanner walks the builder chain back to a `new <Class>(…)` of
 * one of these, bound to jose, then reads the `alg`.
 */
export const JOSE_SIGN_BUILDERS: readonly string[] = [
  'SignJWT',
  'CompactSign',
  'FlattenedSign',
  'GeneralSign',
];

/** Review metadata for a jose builder whose header alg can't be resolved. */
export const JOSE_BUILDER_REVIEW = {
  ruleId: 'jose/review',
  title: 'jose signer — unresolved algorithm',
  why: REVIEW_WHY,
  migration: REVIEW_MIGRATION,
} as const;
