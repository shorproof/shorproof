/**
 * Artifact knowledge base — the crypto facts the artifact scanner needs, as
 * data, not code. The scanner parses JWKS/PEM/X.509 with native `node:crypto`
 * (no new dependency), determines a key's algorithm, and looks the family up
 * here to build a finding.
 *
 * Severity follows the HNDL/lifetime principle codified in CLAUDE.md, applied
 * consistently with the deps and AST scanners:
 *   - The RSA family is encryption-capable and its keys/certs are long-lived —
 *     a harvest-now-decrypt-later time bomb. It sits one tier above EC.
 *   - The EC family (ECDSA/EdDSA/ECDH/X25519/X448/DSA/DH) is dominated by
 *     signatures and ephemeral key agreement, where the lifetime clock is soft.
 * Context then escalates: a *deployed* or *stored-secret* key (a JWKS entry, a
 * private-key file, a certificate valid past the quantum horizon) is confirmed
 * long-lived material, so it lands above bare key generation — never below.
 */
import type { Category, Confidence, Severity } from '../types.ts';

/**
 * The date past which a still-valid classical certificate is treated as
 * living into the window where quantum attacks are anticipated (NIST's
 * deprecation horizon). A certificate valid past this is elevated one tier.
 */
export const QUANTUM_HORIZON = new Date('2030-01-01T00:00:00.000Z');

/**
 * The two Shor-breakability classes that drive severity. `rsa` is the
 * encryption-capable, long-lived-by-default family (one tier hotter); `ec`
 * covers every other Shor-breakable asymmetric primitive we detect, whose
 * lifetime clock is softer.
 */
export type ShorClass = 'rsa' | 'ec';

/** Where a key was found. Drives the lifetime/HNDL escalation. */
export type ArtifactContext = 'private-key' | 'public-key' | 'jwks' | 'certificate';

/**
 * What we know about a detected key once its algorithm is identified — the
 * classification, plus the honest per-family wording and migration hint. The
 * scanner adds the size/curve and the context clause.
 */
export interface KeyInfo {
  /** Ruleid suffix and algorithm tag, e.g. 'rsa', 'ec', 'ed25519', 'x25519'. */
  readonly tag: string;
  readonly shorClass: ShorClass;
  readonly category: Category;
  /** Display label without size, e.g. 'RSA', 'ECDSA', 'Ed25519', 'X25519'. */
  readonly label: string;
  /** The family-level reason (a cryptographer would sign off on this sentence). */
  readonly why: string;
  readonly migration: string;
}

const MIGRATION_SIG =
  'Migrate to ML-DSA (FIPS 204) — in JOSE, AKP keys (kty: AKP, RFC 9964); or SLH-DSA (FIPS 205).';
const MIGRATION_KEX =
  'Migrate to ML-KEM (FIPS 203) key establishment, or a hybrid (e.g. X25519+ML-KEM).';
const MIGRATION_RSA =
  'Migrate to ML-DSA (FIPS 204) for signatures and ML-KEM (FIPS 203) for key establishment.';

const WHY_RSA =
  "RSA is broken by Shor's algorithm: a cryptographically-relevant quantum computer recovers the private key from the public modulus. RSA is also used to encrypt, so recorded ciphertext is a harvest-now-decrypt-later target.";
const WHY_ECDSA =
  "ECDSA/EdDSA signatures are broken by Shor's algorithm, which recovers the signing key from the public key; exposure tracks the signing key's lifetime and compliance deadlines.";
const WHY_ECDH =
  "ECDH/DH key agreement is broken by Shor's algorithm; a recovered private key exposes every session key derived from it, so recorded traffic is a harvest-now-decrypt-later target.";
const WHY_DSA =
  "DSA signatures are broken by Shor's algorithm (and DSA is already deprecated); a quantum computer recovers the signing key from the public key.";

/**
 * Node `KeyObject.asymmetricKeyType` values (and X.509 subject key types) mapped
 * to their classification. Frozen — this is a fact table, not behaviour.
 */
export const KEY_TYPES: Readonly<Record<string, KeyInfo>> = Object.freeze({
  rsa: { tag: 'rsa', shorClass: 'rsa', category: 'signature', label: 'RSA', why: WHY_RSA, migration: MIGRATION_RSA },
  'rsa-pss': { tag: 'rsa-pss', shorClass: 'rsa', category: 'signature', label: 'RSA-PSS', why: WHY_RSA, migration: MIGRATION_RSA },
  ec: { tag: 'ec', shorClass: 'ec', category: 'signature', label: 'ECDSA', why: WHY_ECDSA, migration: MIGRATION_SIG },
  ed25519: { tag: 'ed25519', shorClass: 'ec', category: 'signature', label: 'Ed25519', why: WHY_ECDSA, migration: MIGRATION_SIG },
  ed448: { tag: 'ed448', shorClass: 'ec', category: 'signature', label: 'Ed448', why: WHY_ECDSA, migration: MIGRATION_SIG },
  x25519: { tag: 'x25519', shorClass: 'ec', category: 'key-exchange', label: 'X25519', why: WHY_ECDH, migration: MIGRATION_KEX },
  x448: { tag: 'x448', shorClass: 'ec', category: 'key-exchange', label: 'X448', why: WHY_ECDH, migration: MIGRATION_KEX },
  dsa: { tag: 'dsa', shorClass: 'ec', category: 'signature', label: 'DSA', why: WHY_DSA, migration: MIGRATION_SIG },
  dh: { tag: 'dh', shorClass: 'ec', category: 'key-exchange', label: 'Diffie-Hellman', why: WHY_ECDH, migration: MIGRATION_KEX },
});

/** JWK `kty` (+ `crv` for OKP) mapped to a key type key of {@link KEY_TYPES}. */
export function jwkKeyType(kty: string, crv: string | undefined): string | null {
  switch (kty) {
    case 'RSA':
      return 'rsa';
    case 'EC':
      return 'ec';
    case 'OKP':
      switch (crv) {
        case 'Ed25519':
          return 'ed25519';
        case 'Ed448':
          return 'ed448';
        case 'X25519':
          return 'x25519';
        case 'X448':
          return 'x448';
        default:
          return null;
      }
    default:
      return null;
  }
}

/** OpenSSL curve names (as reported by `asymmetricKeyDetails.namedCurve`) → JOSE names for display. */
export const CURVE_LABELS: Readonly<Record<string, string>> = Object.freeze({
  prime256v1: 'P-256',
  secp384r1: 'P-384',
  secp521r1: 'P-521',
  secp256k1: 'secp256k1',
});

/**
 * The severity matrix: (Shor class × context), with a one-tier elevation for
 * certificates valid past the quantum horizon. RSA sits one tier above EC in
 * every column, honoring the HNDL principle.
 */
export function artifactSeverity(
  shorClass: ShorClass,
  context: ArtifactContext,
  pastHorizon: boolean,
): Severity {
  if (shorClass === 'rsa') {
    switch (context) {
      case 'private-key':
      case 'jwks':
        return 'critical';
      case 'certificate':
        return pastHorizon ? 'critical' : 'high';
      case 'public-key':
        return 'high';
    }
  }
  // EC family — one tier cooler; deployed/stored contexts still escalate above
  // bare keygen (medium) to high, but never to critical on lifetime alone.
  switch (context) {
    case 'private-key':
    case 'jwks':
      return 'high';
    case 'certificate':
      return pastHorizon ? 'high' : 'medium';
    case 'public-key':
      return 'medium';
  }
}

/** Whether a finding's severity turns on a lifetime clock, for the `lifetimeSensitive` flag and wording. */
export function artifactLifetimeSensitive(
  shorClass: ShorClass,
  context: ArtifactContext,
  pastHorizon: boolean,
): boolean {
  if (shorClass === 'rsa') return true; // encryption-capable: always HNDL
  // EC family: long-lived only when the context confirms it.
  return context === 'private-key' || context === 'jwks' || (context === 'certificate' && pastHorizon);
}

/** Confidence is high whenever we definitively parsed the algorithm; the caller downgrades unknowns. */
export const ARTIFACT_CONFIDENCE: Confidence = 'high';

/** The positive-detection outcome for a post-quantum JWK (kty: AKP, RFC 9964). */
export interface SafeArtifact {
  readonly ruleId: string;
  readonly title: string;
  readonly algorithm: string;
  readonly why: string;
  readonly migration: string;
}

export const AKP_SAFE: SafeArtifact = Object.freeze({
  ruleId: 'jwks/akp',
  title: 'Post-quantum JWKS key (ML-DSA)',
  algorithm: 'ML-DSA',
  why: 'kty: AKP is the RFC 9964 Algorithm Key Pair type for ML-DSA (FIPS 204) — this key is already post-quantum.',
  migration: 'No action needed — already a NIST PQC signature key.',
});
