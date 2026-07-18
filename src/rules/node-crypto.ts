import type { AstRule } from '../types.ts';

/**
 * Node.js `crypto` knowledge base for the AST scanner, expressed as typed rule
 * data. A rule fires when a call's callee resolves — through the binding layer,
 * regardless of the local variable name — to one of `exports` imported from one
 * of `modules`.
 *
 * Coverage (CLAUDE.md M2 checklist): createSign/createVerify, one-shot
 * sign/verify, generateKeyPair(Sync) across every key type, createECDH,
 * createDiffieHellman(Group), publicEncrypt/privateDecrypt.
 *
 * Confidence is `high`: unlike a manifest match, an AST match is a *confirmed
 * call site*. Where the exact primitive depends on a key we can't resolve
 * (createSign may sign with RSA or ECDSA), the finding is still certain — only
 * the `algorithm` string carries the "or" — so confidence stays high. The lone
 * exception is `generate-keypair` (unresolved type), a `review`-level fallback.
 *
 * Severity is `high`, not `critical`: these are confirmed Shor-breakable calls,
 * but `critical` in this tool is reserved for crypto we can confirm protects a
 * long-lived secret/signature (data-at-rest, certs past 2030). Static call sites
 * don't tell us data lifetime, so we do not inflate. `lifetimeSensitive` marks
 * the harvest-now-decrypt-later cases (key agreement, RSA encryption) for wording.
 */

const MODULES = ['crypto', 'node:crypto'] as const;
const KEYGEN_EXPORTS = ['generateKeyPair', 'generateKeyPairSync'] as const;

export const NODE_CRYPTO_RULES = [
  // --- Signatures: streaming createSign / createVerify --------------------
  {
    id: 'crypto/create-sign',
    title: 'crypto.createSign — classical asymmetric signing',
    modules: MODULES,
    exports: ['createSign'],
    severity: 'high',
    category: 'signature',
    algorithm: 'RSA/DSA/ECDSA',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'createSign produces classical asymmetric signatures (RSA, DSA, or ECDSA depending on the key) — all broken by Shor’s algorithm.',
    migration: 'Move signing to ML-DSA (FIPS 204), available in Node 24.7+ or via a PQC library.',
  },
  {
    id: 'crypto/create-verify',
    title: 'crypto.createVerify — classical asymmetric verification',
    modules: MODULES,
    exports: ['createVerify'],
    severity: 'high',
    category: 'signature',
    algorithm: 'RSA/DSA/ECDSA',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'createVerify checks classical asymmetric signatures (RSA/DSA/ECDSA) — the scheme it relies on is broken by Shor’s algorithm.',
    migration: 'Verify ML-DSA (FIPS 204) signatures instead, via Node 24.7+ or a PQC library.',
  },

  // --- Signatures: one-shot sign / verify ---------------------------------
  // crypto.sign / crypto.verify accept only asymmetric keys, but on Node 24.7+
  // that INCLUDES post-quantum ML-DSA (crypto.sign(null, data, mlDsaKey)). So
  // the signing operation is confirmed while the algorithm is not — a `review`,
  // not a confident classical finding. M3 resolves the key type to confirm, and
  // only then would a classical key become `high`. (createSign/createVerify stay
  // high: those streaming APIs are classical-only; ML-DSA runs only through the
  // one-shot form.)
  {
    id: 'crypto/sign',
    title: 'crypto.sign — one-shot asymmetric signing',
    modules: MODULES,
    exports: ['sign'],
    severity: 'review',
    category: 'signature',
    algorithm: 'RSA/DSA/ECDSA/EdDSA or ML-DSA',
    confidence: 'low',
    lifetimeSensitive: false,
    why: 'One-shot crypto.sign signs with an asymmetric key whose algorithm depends on the key — classical RSA/DSA/ECDSA/EdDSA (broken by Shor’s algorithm) or, on Node 24.7+, post-quantum ML-DSA. Confirm the key type.',
    migration: 'If the key is RSA/DSA/ECDSA/EdDSA, move to ML-DSA (FIPS 204); if it is already ML-DSA, this is post-quantum.',
  },
  {
    id: 'crypto/verify',
    title: 'crypto.verify — one-shot asymmetric verification',
    modules: MODULES,
    exports: ['verify'],
    severity: 'review',
    category: 'signature',
    algorithm: 'RSA/DSA/ECDSA/EdDSA or ML-DSA',
    confidence: 'low',
    lifetimeSensitive: false,
    why: 'One-shot crypto.verify checks an asymmetric signature whose algorithm depends on the key — classical RSA/DSA/ECDSA/EdDSA (broken by Shor’s algorithm) or, on Node 24.7+, post-quantum ML-DSA. Confirm the key type.',
    migration: 'If the key is RSA/DSA/ECDSA/EdDSA, move to ML-DSA (FIPS 204); if it is already ML-DSA, this is post-quantum.',
  },

  // --- Key exchange -------------------------------------------------------
  {
    id: 'crypto/create-ecdh',
    title: 'crypto.createECDH — elliptic-curve key agreement',
    modules: MODULES,
    exports: ['createECDH'],
    severity: 'high',
    category: 'key-exchange',
    algorithm: 'ECDH',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'createECDH performs elliptic-curve Diffie–Hellman key agreement — broken by Shor’s algorithm, exposing recorded sessions to harvest-now-decrypt-later.',
    migration: 'Adopt ML-KEM (FIPS 203), ideally as a hybrid ECDH+ML-KEM key exchange.',
  },
  {
    id: 'crypto/create-diffie-hellman',
    title: 'crypto.createDiffieHellman — classical DH key agreement',
    modules: MODULES,
    exports: ['createDiffieHellman'],
    severity: 'high',
    category: 'key-exchange',
    algorithm: 'DH',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'createDiffieHellman performs classical finite-field Diffie–Hellman key agreement — broken by Shor’s algorithm.',
    migration: 'Adopt ML-KEM (FIPS 203) or a hybrid DH+ML-KEM key exchange.',
  },
  {
    id: 'crypto/create-diffie-hellman-group',
    title: 'crypto.createDiffieHellmanGroup — fixed-prime classical DH',
    modules: MODULES,
    exports: ['createDiffieHellmanGroup'],
    severity: 'high',
    category: 'key-exchange',
    algorithm: 'DH',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'createDiffieHellmanGroup uses a fixed-prime classical Diffie–Hellman group — broken by Shor’s algorithm.',
    migration: 'Adopt ML-KEM (FIPS 203) or a hybrid DH+ML-KEM key exchange.',
  },

  // --- RSA encryption (harvest-now-decrypt-later) -------------------------
  {
    id: 'crypto/public-encrypt',
    title: 'crypto.publicEncrypt — RSA public-key encryption',
    modules: MODULES,
    exports: ['publicEncrypt'],
    severity: 'high',
    category: 'kem',
    algorithm: 'RSA',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'publicEncrypt encrypts with an RSA public key — anything encrypted now can be harvested and decrypted once Shor’s algorithm is practical.',
    migration: 'Use ML-KEM (FIPS 203) or a hybrid KEM to protect long-lived data.',
  },
  {
    id: 'crypto/private-decrypt',
    title: 'crypto.privateDecrypt — RSA private-key decryption',
    modules: MODULES,
    exports: ['privateDecrypt'],
    severity: 'high',
    category: 'kem',
    algorithm: 'RSA',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'privateDecrypt is the RSA decryption counterpart — its presence marks RSA-encrypted data exposed to harvest-now-decrypt-later.',
    migration: 'Use ML-KEM (FIPS 203) or a hybrid KEM to protect long-lived data.',
  },

  // --- Key generation: first argument selects the primitive ---------------
  // Every generateKeyPair type in Node is classical asymmetric crypto, so every
  // one is a finding; the type only changes the algorithm/category/wording.
  {
    id: 'crypto/generate-keypair-rsa',
    title: 'crypto.generateKeyPair(rsa) — RSA key generation',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'rsa',
    severity: 'high',
    category: 'kem',
    algorithm: 'RSA',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'Generates an RSA key pair — RSA (used for both encryption and signatures) is broken by Shor’s algorithm.',
    migration: 'Plan migration to ML-KEM (encryption) / ML-DSA (signatures) or a hybrid scheme.',
  },
  {
    id: 'crypto/generate-keypair-rsa-pss',
    title: 'crypto.generateKeyPair(rsa-pss) — RSA-PSS signing keys',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'rsa-pss',
    severity: 'high',
    category: 'signature',
    algorithm: 'RSA-PSS',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'Generates an RSA-PSS key pair for signatures — RSA is broken by Shor’s algorithm.',
    migration: 'Move signatures to ML-DSA (FIPS 204).',
  },
  {
    id: 'crypto/generate-keypair-dsa',
    title: 'crypto.generateKeyPair(dsa) — DSA key generation',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'dsa',
    severity: 'high',
    category: 'signature',
    algorithm: 'DSA',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'Generates a DSA key pair — DSA is broken by Shor’s algorithm.',
    migration: 'Move signatures to ML-DSA (FIPS 204).',
  },
  {
    id: 'crypto/generate-keypair-ec',
    title: 'crypto.generateKeyPair(ec) — elliptic-curve key generation',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'ec',
    severity: 'medium',
    category: 'signature',
    algorithm: 'ECDSA/ECDH',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'Generates an elliptic-curve key pair (ECDSA signatures or ECDH key agreement) — elliptic-curve crypto is broken by Shor’s algorithm.',
    migration: 'ML-DSA (FIPS 204) for signatures, ML-KEM (FIPS 203) for key exchange.',
  },
  {
    id: 'crypto/generate-keypair-ed25519',
    title: 'crypto.generateKeyPair(ed25519) — Ed25519 signing keys',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'ed25519',
    severity: 'medium',
    category: 'signature',
    algorithm: 'Ed25519',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'Generates an Ed25519 key pair — its elliptic-curve signatures are broken by Shor’s algorithm.',
    migration: 'Move signatures to ML-DSA (FIPS 204).',
  },
  {
    id: 'crypto/generate-keypair-ed448',
    title: 'crypto.generateKeyPair(ed448) — Ed448 signing keys',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'ed448',
    severity: 'medium',
    category: 'signature',
    algorithm: 'Ed448',
    confidence: 'high',
    lifetimeSensitive: false,
    why: 'Generates an Ed448 key pair — its elliptic-curve signatures are broken by Shor’s algorithm.',
    migration: 'Move signatures to ML-DSA (FIPS 204).',
  },
  {
    id: 'crypto/generate-keypair-x25519',
    title: 'crypto.generateKeyPair(x25519) — X25519 key-agreement keys',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'x25519',
    severity: 'medium',
    category: 'key-exchange',
    algorithm: 'X25519',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'Generates an X25519 key pair for key agreement — broken by Shor’s algorithm, exposing recorded sessions to harvest-now-decrypt-later.',
    migration: 'Adopt ML-KEM (FIPS 203) or a hybrid X25519+ML-KEM key exchange.',
  },
  {
    id: 'crypto/generate-keypair-x448',
    title: 'crypto.generateKeyPair(x448) — X448 key-agreement keys',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArg: 'x448',
    severity: 'medium',
    category: 'key-exchange',
    algorithm: 'X448',
    confidence: 'high',
    lifetimeSensitive: true,
    why: 'Generates an X448 key pair for key agreement — broken by Shor’s algorithm, exposing recorded sessions to harvest-now-decrypt-later.',
    migration: 'Adopt ML-KEM (FIPS 203) or a hybrid X448+ML-KEM key exchange.',
  },
  {
    id: 'crypto/generate-keypair',
    title: 'crypto.generateKeyPair — unresolved key type',
    modules: MODULES,
    exports: KEYGEN_EXPORTS,
    firstArgFallback: true,
    severity: 'review',
    category: 'signature',
    algorithm: 'asymmetric',
    confidence: 'low',
    lifetimeSensitive: false,
    why: 'Generates an asymmetric key pair, but the key type couldn’t be resolved statically — every generateKeyPair type in Node (RSA/DSA/EC/Ed/X) is broken by Shor’s algorithm, so confirm which this is.',
    migration: 'Identify the key type; migrate signatures to ML-DSA (FIPS 204) and encryption/key exchange to ML-KEM (FIPS 203).',
  },
] as const satisfies readonly AstRule[];
