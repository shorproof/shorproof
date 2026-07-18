import { resolve } from 'node:path';
import type { Finding, Scanner, ScanResult, Severity, SeverityCounts } from './types.ts';
import { SEVERITIES, SEVERITY_RANK } from './types.ts';
import { depsScanner } from './scanners/deps.ts';
import { astScanner } from './scanners/ast.ts';
import { VERSION } from './version.ts';

/** The scanners that run by default. Grows as M3+ scanners land. */
export const DEFAULT_SCANNERS: readonly Scanner[] = [depsScanner, astScanner];

export interface ScanOptions {
  /** Directory to scan. Resolved against cwd. */
  readonly root: string;
  /** Override the scanner set (e.g. for tests or `--scanner` filtering). */
  readonly scanners?: readonly Scanner[];
}

function emptyCounts(): SeverityCounts {
  const counts = {} as Record<Severity, number>;
  for (const severity of SEVERITIES) counts[severity] = 0;
  return counts;
}

/**
 * Deterministic finding order: most severe first, then by file, line, column,
 * and finally rule id so output is stable across runs and platforms.
 */
function compareFindings(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    a.location.file.localeCompare(b.location.file) ||
    (a.location.line ?? 0) - (b.location.line ?? 0) ||
    (a.location.column ?? 0) - (b.location.column ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

/**
 * Run every scanner against the root and merge their findings into one sorted,
 * counted result set. Scanner errors (e.g. a malformed manifest) propagate so
 * the caller can map them to exit code 2.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const root = resolve(process.cwd(), options.root);
  const scanners = options.scanners ?? DEFAULT_SCANNERS;

  const findings: Finding[] = [];
  for (const scanner of scanners) {
    const produced = await scanner.scan({ root });
    findings.push(...produced);
  }

  findings.sort(compareFindings);

  const counts = emptyCounts();
  for (const finding of findings) counts[finding.severity]++;

  return {
    tool: 'shorproof',
    version: VERSION,
    root,
    findings,
    counts,
    scanners: scanners.map((s) => s.name),
  };
}
