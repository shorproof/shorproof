import type { JwtCallRule } from '../types.ts';

/**
 * JWT middleware configs, detected "where cheap" — i.e. where the accepted
 * algorithms are a plain option on a direct call, so the existing JwtCallRule
 * machinery applies without new call shapes.
 *
 * express-jwt (v7+) is exactly that: `expressjwt({ secret, algorithms: [...] })`.
 * A quantum-vulnerable alg in the accepted list means the app verifies tokens
 * signed with it. (passport-jwt uses `new Strategy({...})` and @fastify/jwt uses
 * nested register config — different call shapes, left for a later pass.)
 */

const REVIEW_WHY =
  'A JWT middleware was configured, but its accepted algorithms couldn’t be resolved statically — check whether RS/PS/ES are accepted.';
const REVIEW_MIGRATION =
  'Pin the accepted algorithms; drop RS/PS/ES in favor of ML-DSA (FIPS 204) when your stack supports it.';

export const JWT_MIDDLEWARE_RULES = [
  {
    modules: ['express-jwt'],
    export: 'expressjwt',
    algArgIndex: 0,
    algOptionKey: 'algorithms',
    algIsArray: true,
    ruleIdPrefix: 'express-jwt',
    reviewRuleId: 'express-jwt/review',
    reviewTitle: 'express-jwt — unresolved algorithms',
    reviewWhy: REVIEW_WHY,
    reviewMigration: REVIEW_MIGRATION,
  },
] as const satisfies readonly JwtCallRule[];
