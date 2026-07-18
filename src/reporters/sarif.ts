import { relative } from 'node:path';
import { sep } from 'node:path';
import type { Finding, ScanResult, Severity } from '../types.ts';

/**
 * SARIF 2.1.0 reporter — the distribution hook. GitHub code scanning ingests
 * SARIF and renders findings inline on pull requests, so getting the rule
 * metadata and severity mapping right is what makes shorproof visible where
 * developers already work.
 *
 * The output validates as SARIF 2.1.0: one run, a `tool.driver` with a
 * de-duplicated `rules` array, and one `result` per finding referencing its
 * rule by index. Severity maps to both a SARIF `level` and GitHub's
 * `security-severity` property so alerts are classified correctly.
 */

const INFORMATION_URI = 'https://github.com/shorproof/shorproof';
const HELP_URI = 'https://github.com/shorproof/shorproof#readme';

/** SARIF result levels. Positive/inventory findings are `none` (informational, not an alert). */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const LEVEL_BY_SEVERITY: Readonly<Record<Severity, SarifLevel>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  review: 'note',
  safe: 'none',
  info: 'none',
};

/**
 * GitHub's `security-severity` is a CVSS-like number driving its own
 * critical/high/medium/low buckets (>=9 critical, 7–8.9 high, 4–6.9 medium,
 * <4 low). Safe/info carry none — they are not vulnerabilities.
 */
const SECURITY_SEVERITY: Readonly<Record<Severity, string | undefined>> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.0',
  review: '2.0',
  safe: undefined,
  info: undefined,
};

interface SarifRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly helpUri: string;
  readonly help: { readonly text: string };
  readonly defaultConfiguration: { readonly level: SarifLevel };
  readonly properties: { readonly tags: readonly string[]; readonly 'security-severity'?: string };
}

/** Normalize a path to a forward-slash relative URI for SARIF artifactLocation. */
function toUri(file: string, root: string): string {
  const rel = relative(root, file) || file;
  return rel.split(sep).join('/');
}

/** A PascalCase-ish rule name from the id, e.g. "jsonwebtoken/rs256" -> "JsonwebtokenRs256". */
function ruleName(id: string): string {
  return id
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join('');
}

/** Build a SARIF rule descriptor from the first finding seen for its ruleId. */
function ruleFromFinding(f: Finding): SarifRule {
  const securitySeverity = SECURITY_SEVERITY[f.severity];
  return {
    id: f.ruleId,
    name: ruleName(f.ruleId),
    shortDescription: { text: f.title },
    fullDescription: { text: f.why },
    helpUri: HELP_URI,
    help: { text: f.migration ? `${f.why}\n\nMigration: ${f.migration}` : f.why },
    defaultConfiguration: { level: LEVEL_BY_SEVERITY[f.severity] },
    properties: {
      tags: ['cryptography', 'post-quantum', f.category],
      ...(securitySeverity ? { 'security-severity': securitySeverity } : {}),
    },
  };
}

/** The one-line message for a result: the honest why, plus the migration hint. */
function messageText(f: Finding): string {
  const base = `${f.algorithm}: ${f.why}`;
  return f.migration ? `${base} → ${f.migration}` : base;
}

export function renderSarif(result: ScanResult): string {
  // De-duplicate rules by id, preserving first-seen metadata and assigning
  // each a stable index the results point back to.
  const ruleIndex = new Map<string, number>();
  const rules: SarifRule[] = [];
  for (const f of result.findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push(ruleFromFinding(f));
  }

  const results = result.findings.map((f) => {
    const line = f.location.line;
    const column = f.location.column;
    const region =
      line && line > 0
        ? { region: { startLine: line, ...(column && column > 0 ? { startColumn: column } : {}) } }
        : {};
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      level: LEVEL_BY_SEVERITY[f.severity],
      message: { text: messageText(f) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: toUri(f.location.file, result.root), uriBaseId: 'SRCROOT' },
            ...region,
          },
        },
      ],
      // Stable across runs so GitHub can track an alert as code moves.
      partialFingerprints: {
        shorproofId: `${f.ruleId}:${toUri(f.location.file, result.root)}:${line ?? 0}`,
      },
    };
  });

  const doc = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'shorproof',
            informationUri: INFORMATION_URI,
            version: result.version,
            rules,
          },
        },
        originalUriBaseIds: {
          SRCROOT: { uri: pathToFileUri(result.root) },
        },
        results,
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}

/** A `file://` URI (with trailing slash) for the scan root, for SARIF's uriBaseId. */
function pathToFileUri(root: string): string {
  const normalized = root.split(sep).join('/');
  const withSlash = normalized.endsWith('/') ? normalized : `${normalized}/`;
  // Windows absolute paths (C:/...) need a leading slash after file://.
  return /^[A-Za-z]:/.test(withSlash) ? `file:///${withSlash}` : `file://${withSlash}`;
}
