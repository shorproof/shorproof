import type { AlgOutcome } from '../types.ts';

/**
 * WebCrypto (`crypto.subtle.*`) knowledge base. Competing scanners have zero
 * WebCrypto coverage — this closes that gap.
 *
 * Severity is operation-aware, honoring the HNDL/lifetime principle: the RSA
 * family is always `high`; the EC family (ECDSA/Ed25519/ECDH/X25519) is `medium`
 * at bare key generation/import but escalates to `high` for a confirmed usage
 * (sign/verify/deriveKey/deriveBits/encrypt/decrypt). RSA-OAEP encryption is a
 * harvest-now-decrypt-later case.
 */

type Family = 'rsa-sig' | 'rsa-pss' | 'rsa-enc' | 'ec-sig' | 'ed-sig' | 'ec-kex';

/** WebCrypto algorithm `name` → primitive family. Absent = not Shor-relevant (AES/SHA/HMAC/…). */
const FAMILY: Readonly<Record<string, Family>> = {
  'RSASSA-PKCS1-v1_5': 'rsa-sig',
  'RSA-PSS': 'rsa-pss',
  'RSA-OAEP': 'rsa-enc',
  ECDSA: 'ec-sig',
  Ed25519: 'ed-sig',
  ECDH: 'ec-kex',
  X25519: 'ec-kex',
};

export type WebCryptoKind = 'keygen' | 'usage';

/** subtle method → where the algorithm arg is, and whether the call confirms active usage. */
export const WEBCRYPTO_METHODS: Readonly<
  Record<string, { readonly algArgIndex: number; readonly kind: WebCryptoKind }>
> = {
  generateKey: { algArgIndex: 0, kind: 'keygen' },
  importKey: { algArgIndex: 2, kind: 'keygen' },
  sign: { algArgIndex: 0, kind: 'usage' },
  verify: { algArgIndex: 0, kind: 'usage' },
  deriveKey: { algArgIndex: 0, kind: 'usage' },
  deriveBits: { algArgIndex: 0, kind: 'usage' },
  encrypt: { algArgIndex: 0, kind: 'usage' },
  decrypt: { algArgIndex: 0, kind: 'usage' },
};

const SIG_MIGRATION = 'Move signing to ML-DSA (FIPS 204) via a PQC library until WebCrypto exposes it.';
const KEX_MIGRATION = 'Adopt ML-KEM (FIPS 203), ideally as a hybrid with the current curve.';

/** The outcome for a WebCrypto algorithm at a given operation, or null if not Shor-relevant. */
export function webcryptoOutcome(algName: string, kind: WebCryptoKind): AlgOutcome | null {
  const family = FAMILY[algName];
  if (!family) return null;

  switch (family) {
    case 'rsa-sig':
    case 'rsa-pss':
      return {
        severity: 'high',
        category: 'signature',
        algorithm: `${family === 'rsa-pss' ? 'RSA-PSS' : 'RSA'} (${algName})`,
        confidence: 'high',
        lifetimeSensitive: false,
        why: `WebCrypto ${algName} — RSA signatures are broken by Shor’s algorithm.`,
        migration: SIG_MIGRATION,
      };
    case 'rsa-enc':
      return {
        severity: 'high',
        category: 'kem',
        algorithm: 'RSA (RSA-OAEP)',
        confidence: 'high',
        lifetimeSensitive: true,
        why: 'WebCrypto RSA-OAEP — RSA encryption exposed to harvest-now-decrypt-later once Shor’s algorithm is practical.',
        migration: 'Encrypt with ML-KEM (FIPS 203) or a hybrid KEM for long-lived data.',
      };
    case 'ec-sig':
    case 'ed-sig': {
      const confirmed = kind === 'usage';
      return {
        severity: confirmed ? 'high' : 'medium',
        category: 'signature',
        algorithm: algName,
        confidence: 'high',
        lifetimeSensitive: false,
        why: `WebCrypto ${algName} — elliptic-curve signatures are broken by Shor’s algorithm.${confirmed ? '' : ' (Key generation — severity rises for a confirmed signing usage.)'}`,
        migration: SIG_MIGRATION,
      };
    }
    case 'ec-kex': {
      const confirmed = kind === 'usage';
      return {
        severity: confirmed ? 'high' : 'medium',
        category: 'key-exchange',
        algorithm: algName,
        confidence: 'high',
        lifetimeSensitive: confirmed,
        why: `WebCrypto ${algName} — elliptic-curve key agreement is broken by Shor’s algorithm${confirmed ? ', exposing recorded sessions to harvest-now-decrypt-later' : ' (key generation — severity rises for a confirmed key-agreement usage)'}.`,
        migration: KEX_MIGRATION,
      };
    }
  }
}
