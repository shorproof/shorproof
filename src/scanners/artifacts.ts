import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type { ArtifactContext, KeyInfo } from '../rules/artifacts.ts';
import {
  AKP_SAFE,
  ARTIFACT_CONFIDENCE,
  CURVE_LABELS,
  KEY_TYPES,
  QUANTUM_HORIZON,
  artifactLifetimeSensitive,
  artifactSeverity,
  jwkKeyType,
} from '../rules/artifacts.ts';
import type { ArtifactFinding, Scanner, ScanContext, ScanReport } from '../types.ts';
import { walkFiles } from '../walk.ts';

/**
 * The artifact scanner: JWKS/JWK files, PEM private/public keys, and X.509
 * certificates. Everything is parsed with native `node:crypto` — no new
 * dependency, and OpenSSL-backed parsers are built to handle untrusted input.
 * Every parse is guarded: a malformed key or cert is skipped, never crashed on
 * and never turned into a false positive. Regex is used only to split PEM blocks
 * and to gate JSON files (both artifact files, not source code — the AST-only
 * rule is about code).
 */

/** Extensions that may hold key/cert artifacts. `.json` is gated on a `"kty"` probe. */
const ARTIFACT_EXTENSIONS = ['.pem', '.crt', '.cer', '.key', '.pub', '.jwks', '.json'] as const;

/** Skip pathologically large files — a real JWKS/PEM is small; this bounds parse cost. */
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024;

/**
 * One PEM block: the BEGIN label plus its body. The lazy body with an
 * anchored, back-referenced END cannot catastrophically backtrack.
 */
const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+?)-----\r?\n([\s\S]*?)-----END \1-----/g;

// --- finding construction ------------------------------------------------

/** Curve/size-qualified algorithm label for the report. */
function describeAlgorithm(info: KeyInfo, details: KeyObject['asymmetricKeyDetails']): string {
  if (info.shorClass === 'rsa') {
    const bits = details?.modulusLength;
    return bits ? `${info.label}-${bits}` : info.label;
  }
  if (info.tag === 'ec') {
    const curve = details?.namedCurve;
    const label = curve ? (CURVE_LABELS[curve] ?? curve) : undefined;
    return label ? `${info.label} (${label})` : info.label;
  }
  return info.label;
}

/** Human title, e.g. "RSA X.509 certificate", "ECDSA private key". */
function titleFor(label: string, context: ArtifactContext): string {
  switch (context) {
    case 'certificate':
      return `${label} X.509 certificate`;
    case 'private-key':
      return `${label} private key`;
    case 'public-key':
      return `${label} public key`;
    case 'jwks':
      return `${label} JWKS key`;
  }
}

/** The context-specific clause appended to the family `why`. */
function contextClause(context: ArtifactContext, certValidTo?: Date, pastHorizon?: boolean): string {
  switch (context) {
    case 'private-key':
      return ' This is stored private-key material.';
    case 'public-key':
      return ' This is a published public key; the exposure is the corresponding long-lived private key.';
    case 'jwks':
      return ' This is deployed JWKS key infrastructure — migration needs coordinated rotation across issuers and verifiers.';
    case 'certificate': {
      const until = certValidTo ? ` The certificate is valid until ${certValidTo.toISOString().slice(0, 10)}` : '';
      return pastHorizon
        ? `${until}, past the ~2030 horizon where quantum attacks are anticipated.`
        : `${until}.`;
    }
  }
}

interface FindingInput {
  readonly info: KeyInfo;
  readonly context: ArtifactContext;
  readonly file: string;
  readonly line?: number;
  readonly algorithm: string;
  readonly detail?: string;
  readonly certValidTo?: Date;
  readonly pastHorizon?: boolean;
}

function makeFinding(input: FindingInput): ArtifactFinding {
  const { info, context, pastHorizon = false } = input;
  const severity = artifactSeverity(info.shorClass, context, pastHorizon);
  return {
    source: 'artifact',
    ruleId: `${ruleContextTag(context)}/${info.tag}`,
    severity,
    category: info.category,
    algorithm: input.algorithm,
    title: titleFor(info.label, context),
    why: info.why + contextClause(context, input.certValidTo, pastHorizon),
    migration: info.migration,
    confidence: ARTIFACT_CONFIDENCE,
    lifetimeSensitive: artifactLifetimeSensitive(info.shorClass, context, pastHorizon),
    location: { file: input.file, line: input.line },
    ...(input.detail ? { detail: input.detail } : {}),
  };
}

/** The ruleId context prefix: `x509`, `pem-key`, `pem-pub`, or `jwks`. */
function ruleContextTag(context: ArtifactContext): string {
  switch (context) {
    case 'certificate':
      return 'x509';
    case 'private-key':
      return 'pem-key';
    case 'public-key':
      return 'pem-pub';
    case 'jwks':
      return 'jwks';
  }
}

/** 1-based line of a character offset within `source`. */
function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

// --- PEM handling --------------------------------------------------------

function analyzePem(source: string, file: string): ArtifactFinding[] {
  const findings: ArtifactFinding[] = [];
  for (const match of source.matchAll(PEM_BLOCK)) {
    const label = match[1];
    if (label === undefined || match.index === undefined) continue;
    const line = lineOf(source, match.index);
    const pem = match[0];

    const finding = classifyPemBlock(label, pem, file, line);
    if (finding) findings.push(finding);
  }
  return findings;
}

function classifyPemBlock(
  label: string,
  pem: string,
  file: string,
  line: number,
): ArtifactFinding | null {
  if (label === 'CERTIFICATE') return classifyCertificate(pem, file, line);

  if (label === 'ENCRYPTED PRIVATE KEY') {
    // Can't determine the algorithm without the passphrase — inventory it as a
    // review item rather than guess.
    return {
      source: 'artifact',
      ruleId: 'pem-enc/unknown',
      severity: 'review',
      category: 'artifact',
      algorithm: 'unknown (encrypted)',
      title: 'Encrypted private key',
      why: 'An encrypted PEM private key is present; its algorithm cannot be determined statically without the passphrase. If it is RSA or an elliptic-curve key, it is Shor-breakable.',
      migration: 'Confirm the key algorithm; if classical asymmetric, plan migration to ML-DSA / ML-KEM.',
      confidence: 'low',
      lifetimeSensitive: true,
      location: { file, line },
    };
  }

  const isPrivate = label.endsWith('PRIVATE KEY'); // RSA/EC/generic PKCS#8
  const isPublic = label.endsWith('PUBLIC KEY'); // SPKI or PKCS#1 RSA public
  if (!isPrivate && !isPublic) return null; // params, CSRs, etc. — not a key

  let key: KeyObject;
  try {
    key = isPrivate ? createPrivateKey(pem) : createPublicKey(pem);
  } catch {
    return null; // malformed — skip, don't false-positive
  }

  const type = key.asymmetricKeyType;
  const info = type ? KEY_TYPES[type] : undefined;
  if (!info) return null; // symmetric or unrecognized — nothing Shor-breakable

  return makeFinding({
    info,
    context: isPrivate ? 'private-key' : 'public-key',
    file,
    line,
    algorithm: describeAlgorithm(info, key.asymmetricKeyDetails),
  });
}

function classifyCertificate(pem: string, file: string, line: number): ArtifactFinding | null {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch {
    return null;
  }

  const type = cert.publicKey.asymmetricKeyType;
  const info = type ? KEY_TYPES[type] : undefined;
  if (!info) return null;

  // `validToDate` (a Date) only exists on newer Node; parse the `validTo`
  // string, which is available back to our Node 20.12 floor. If it can't be
  // parsed we keep the base severity (no horizon elevation) rather than guess.
  const parsed = new Date(cert.validTo);
  const validTo = Number.isNaN(parsed.getTime()) ? undefined : parsed;
  const pastHorizon = validTo ? validTo.getTime() >= QUANTUM_HORIZON.getTime() : false;

  return makeFinding({
    info,
    context: 'certificate',
    file,
    line,
    algorithm: describeAlgorithm(info, cert.publicKey.asymmetricKeyDetails),
    detail: cert.subject.replace(/\r?\n/g, ' ').trim() || undefined,
    certValidTo: validTo,
    pastHorizon,
  });
}

// --- JWKS / JWK handling -------------------------------------------------

interface Jwk {
  readonly kty?: string;
  readonly crv?: string;
  readonly kid?: string;
  readonly alg?: string;
}

function analyzeJwks(source: string, file: string): ArtifactFinding[] {
  // Gate: a JWK always carries a `kty` member (RFC 7517). No `"kty"` substring
  // means this JSON cannot be a key set — skip without parsing.
  if (!source.includes('"kty"')) return [];

  let doc: unknown;
  try {
    doc = JSON.parse(source);
  } catch {
    return []; // not valid JSON — not our artifact
  }

  const keys = extractJwks(doc);
  if (keys.length === 0) return [];

  const findings: ArtifactFinding[] = [];
  keys.forEach((jwk, i) => {
    const finding = classifyJwk(jwk, file, i);
    if (finding) findings.push(finding);
  });
  return findings;
}

/** A JWKS (`{ keys: [...] }`) or a single bare JWK (`{ kty: ... }`). */
function extractJwks(doc: unknown): Jwk[] {
  if (typeof doc !== 'object' || doc === null) return [];
  const obj = doc as { keys?: unknown; kty?: unknown };
  if (Array.isArray(obj.keys)) {
    return obj.keys.filter((k): k is Jwk => typeof k === 'object' && k !== null);
  }
  if (typeof obj.kty === 'string') return [obj as Jwk];
  return [];
}

function classifyJwk(jwk: Jwk, file: string, index: number): ArtifactFinding | null {
  const kty = jwk.kty;
  if (kty === undefined) return null;

  const detail = jwk.kid ? `kid: ${jwk.kid}` : `key #${index}`;

  // Positive detection: kty: AKP is the RFC 9964 post-quantum key type.
  if (kty === 'AKP') {
    return {
      source: 'artifact',
      ruleId: AKP_SAFE.ruleId,
      severity: 'safe',
      category: 'signature',
      algorithm: jwk.alg ?? AKP_SAFE.algorithm,
      title: AKP_SAFE.title,
      why: AKP_SAFE.why,
      migration: AKP_SAFE.migration,
      confidence: 'high',
      lifetimeSensitive: false,
      location: { file },
      detail,
    };
  }

  if (kty === 'oct') return null; // symmetric key — not Shor-breakable

  const typeKey = jwkKeyType(kty, jwk.crv);
  const info = typeKey ? KEY_TYPES[typeKey] : undefined;
  if (!info) return null;

  return makeFinding({
    info,
    context: 'jwks',
    file,
    algorithm: describeJwkAlgorithm(info, jwk),
    detail,
  });
}

function describeJwkAlgorithm(info: KeyInfo, jwk: Jwk): string {
  if (info.tag === 'ec' && jwk.crv) return `${info.label} (${jwk.crv})`;
  if (info.shorClass === 'rsa') {
    const bits = rsaJwkBits(jwk);
    return bits ? `${info.label}-${bits}` : info.label;
  }
  return info.label;
}

/** Best-effort RSA modulus size from a JWK, via native parsing (falls back to none). */
function rsaJwkBits(jwk: Jwk): number | undefined {
  try {
    const input = { key: jwk, format: 'jwk' } as Parameters<typeof createPublicKey>[0];
    return createPublicKey(input).asymmetricKeyDetails?.modulusLength;
  } catch {
    return undefined;
  }
}

// --- scanner -------------------------------------------------------------

const PEM_EXTS = new Set(['.pem', '.crt', '.cer', '.key', '.pub']);

export const artifactsScanner: Scanner = {
  name: 'artifacts',
  scan({ root }: ScanContext): ScanReport {
    const files = walkFiles(root, { extensions: [...ARTIFACT_EXTENSIONS] });
    const findings: ArtifactFinding[] = [];

    for (const file of files) {
      let source: string;
      try {
        source = readFileSync(file, 'utf8');
      } catch {
        continue; // unreadable — degrade, don't abort
      }
      if (source.length > MAX_ARTIFACT_BYTES) continue;

      const ext = extname(file);
      if (PEM_EXTS.has(ext)) {
        // A `.pem`/`.crt` may hold a chain of blocks; a `.key` could be PEM.
        findings.push(...analyzePem(source, file));
      } else {
        // `.json` / `.jwks`
        findings.push(...analyzeJwks(source, file));
      }
    }

    return { findings };
  },
};

function extname(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot).toLowerCase() : '';
}
