import { randomUUID } from 'node:crypto';
import { relative, sep } from 'node:path';
import type { Category, Finding, ScanResult, Severity } from '../types.ts';

/**
 * CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) reporter.
 *
 * A CBOM is an *inventory*, not an alert stream: every detected crypto asset is
 * listed — vulnerable and already-post-quantum alike — as a
 * `cryptographic-asset` component with `cryptoProperties.algorithmProperties`
 * (primitive, parameter set / curve, cryptoFunctions, and the NIST quantum
 * security level). Identical assets are collapsed into one component carrying
 * every place they occur, which is the shape a CBOM consumer expects.
 *
 * Output validates against the CycloneDX 1.6 JSON schema (see cbom.test.ts).
 */

/** Our internal category → CycloneDX algorithm `primitive` (note the hyphenated enum values). */
const PRIMITIVE: Readonly<Record<Category, string>> = {
  signature: 'signature',
  kem: 'kem',
  'key-exchange': 'key-agree',
  hash: 'hash',
  symmetric: 'block-cipher',
  artifact: 'unknown',
};

/** Our internal category → CycloneDX `cryptoFunctions`. */
const FUNCTIONS: Readonly<Record<Category, readonly string[]>> = {
  signature: ['sign', 'verify'],
  kem: ['encapsulate', 'decapsulate'],
  'key-exchange': ['keyderive'],
  hash: ['digest'],
  symmetric: ['encrypt', 'decrypt'],
  artifact: ['unknown'],
};

/** NIST PQC security categories for the post-quantum algorithms we positively detect. */
const NIST_LEVEL: ReadonlyArray<readonly [RegExp, number]> = [
  [/ML-DSA-87|ML-KEM-1024|SLH-DSA-\w*256/i, 5],
  [/ML-DSA-65|ML-KEM-768/i, 3],
  [/ML-DSA-44/i, 2],
  [/ML-KEM-512/i, 1],
];

/**
 * The NIST quantum security level for a finding's algorithm. Shor-breakable
 * asymmetric primitives provide none (0). Post-quantum algorithms map to their
 * NIST category. Everything else (symmetric-safe, review) is left unset.
 */
function quantumLevel(f: Finding): number | undefined {
  if (f.severity === 'safe') {
    for (const [re, level] of NIST_LEVEL) if (re.test(f.algorithm)) return level;
    return undefined; // e.g. HS256 — symmetric, not an asymmetric PQC claim
  }
  if (f.category === 'signature' || f.category === 'kem' || f.category === 'key-exchange') {
    return 0; // classical asymmetric — Shor-breakable, no quantum security
  }
  return undefined;
}

/** Pull a parameter-set id (e.g. "2048", "65") or a curve (e.g. "P-256") out of the algorithm label. */
function algorithmParams(algorithm: string): { parameterSetIdentifier?: string; curve?: string } {
  const curve = /\(([^)]+)\)/.exec(algorithm)?.[1];
  // Parameter sets are numeric (2048, 256, 65) — avoids mis-reading "Diffie-Hellman".
  const size = /-(\d+)$/.exec(algorithm)?.[1];
  return {
    ...(curve ? { curve } : {}),
    ...(!curve && size ? { parameterSetIdentifier: size } : {}),
  };
}

function toLocation(file: string, root: string): string {
  return (relative(root, file) || file).split(sep).join('/');
}

interface Occurrence {
  readonly location: string;
  readonly line?: number;
}

/** A distinct crypto asset: one CycloneDX component, aggregating every occurrence. */
interface Asset {
  readonly ruleId: string;
  readonly algorithm: string;
  readonly category: Category;
  readonly severity: Severity;
  readonly source: Finding['source'];
  readonly occurrences: Occurrence[];
}

export function renderCbom(result: ScanResult): string {
  // Collapse identical (ruleId + algorithm) findings into one asset.
  const assets = new Map<string, Asset>();
  for (const f of result.findings) {
    const key = `${f.ruleId}|${f.algorithm}`;
    let asset = assets.get(key);
    if (!asset) {
      asset = {
        ruleId: f.ruleId,
        algorithm: f.algorithm,
        category: f.category,
        severity: f.severity,
        source: f.source,
        occurrences: [],
      };
      assets.set(key, asset);
    }
    asset.occurrences.push({
      location: toLocation(f.location.file, result.root),
      ...(f.location.line ? { line: f.location.line } : {}),
    });
  }

  const components = [...assets.values()].map((asset, i) => {
    const level = quantumLevelForAsset(asset);
    return {
      type: 'cryptographic-asset',
      'bom-ref': `crypto/${i}/${asset.ruleId}`,
      name: asset.algorithm,
      cryptoProperties: {
        assetType: 'algorithm',
        algorithmProperties: {
          primitive: PRIMITIVE[asset.category],
          ...algorithmParams(asset.algorithm),
          executionEnvironment: 'software-plain-ram',
          cryptoFunctions: [...FUNCTIONS[asset.category]],
          ...(level !== undefined ? { nistQuantumSecurityLevel: level } : {}),
        },
      },
      evidence: { occurrences: asset.occurrences },
      properties: [
        { name: 'shorproof:severity', value: asset.severity },
        { name: 'shorproof:source', value: asset.source },
        { name: 'shorproof:ruleId', value: asset.ruleId },
      ],
    };
  });

  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          {
            type: 'application',
            name: 'shorproof',
            version: result.version,
            description: 'Post-quantum readiness scanner',
          },
        ],
      },
    },
    components,
  };

  return JSON.stringify(doc, null, 2);
}

/** Representative quantum level for an asset, from a synthetic finding view. */
function quantumLevelForAsset(asset: Asset): number | undefined {
  return quantumLevel({
    severity: asset.severity,
    category: asset.category,
    algorithm: asset.algorithm,
  } as Finding);
}
