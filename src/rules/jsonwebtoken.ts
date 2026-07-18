import type { JwtCallRule } from '../types.ts';

/**
 * jsonwebtoken detection config. The library is JWS-only:
 * - `sign(payload, key, options)` — options.algorithm is a single string (default HS256).
 * - `verify(token, key, options)` — options.algorithms is an array of accepted algs.
 *
 * The alg value(s) are looked up in the shared JWA table; a confirmed call whose
 * algorithm can't be resolved statically yields the shared review finding.
 */
const REVIEW_WHY =
  'A jsonwebtoken sign/verify call was confirmed, but its algorithm couldn’t be resolved statically — check whether it uses RS/PS/ES (Shor-broken) or HS (safe).';
const REVIEW_MIGRATION =
  'Pin the algorithm explicitly; if it is RS/PS/ES, plan a move to ML-DSA (FIPS 204).';

export const JSONWEBTOKEN_RULES = [
  {
    modules: ['jsonwebtoken'],
    export: 'sign',
    optionArgIndex: 2,
    optionKey: 'algorithm',
    optionIsArray: false,
    ruleIdPrefix: 'jsonwebtoken',
    reviewRuleId: 'jsonwebtoken/review',
    reviewTitle: 'jsonwebtoken.sign — unresolved algorithm',
    reviewWhy: REVIEW_WHY,
    reviewMigration: REVIEW_MIGRATION,
  },
  {
    modules: ['jsonwebtoken'],
    export: 'verify',
    optionArgIndex: 2,
    optionKey: 'algorithms',
    optionIsArray: true,
    ruleIdPrefix: 'jsonwebtoken',
    reviewRuleId: 'jsonwebtoken/review',
    reviewTitle: 'jsonwebtoken.verify — unresolved algorithm',
    reviewWhy: REVIEW_WHY,
    reviewMigration: REVIEW_MIGRATION,
  },
] as const satisfies readonly JwtCallRule[];
