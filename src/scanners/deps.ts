import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { DepFinding, DepRule, Scanner, ScanContext, ScanReport } from '../types.ts';
import { DEP_RULES } from '../rules/index.ts';

/** Package name -> rule, built once. */
const RULE_BY_PACKAGE: ReadonlyMap<string, DepRule> = new Map(
  DEP_RULES.map((rule) => [rule.package, rule]),
);

/** The manifest dependency sections we merge, mirroring v0.0.1. */
const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

interface Manifest {
  readonly dependencies?: Record<string, string>;
  readonly devDependencies?: Record<string, string>;
  readonly optionalDependencies?: Record<string, string>;
}

/** Merge the dependency sections into one name->range map (later sections win, matching v0.0.1's Object.assign order). */
function collectDependencies(pkg: Manifest): Map<string, string> {
  const deps = new Map<string, string>();
  for (const section of DEP_SECTIONS) {
    const entries = pkg[section];
    if (!entries) continue;
    for (const [name, range] of Object.entries(entries)) {
      deps.set(name, range);
    }
  }
  return deps;
}

/**
 * The dependency-manifest scanner — the v0.0.1 behaviour, now a pluggable
 * scanner over rule data. Reads `package.json` at the scan root and reports any
 * dependency that matches a known crypto-relevant package.
 *
 * A missing `package.json` is not an error here (in v0.1 a project may be
 * scanned for source usage alone); a *malformed* one is, and is thrown so the
 * CLI can exit 2.
 */
export const depsScanner: Scanner = {
  name: 'deps',
  scan({ root }: ScanContext): ScanReport {
    const pkgPath = join(root, 'package.json');

    let raw: string;
    try {
      raw = readFileSync(pkgPath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { findings: [] };
      throw new Error(`shorproof: could not read ${pkgPath}`, { cause: err });
    }

    let pkg: Manifest;
    try {
      pkg = JSON.parse(raw) as Manifest;
    } catch (err) {
      throw new Error(`shorproof: could not parse ${pkgPath}`, { cause: err });
    }

    const deps = collectDependencies(pkg);
    const findings: DepFinding[] = [];

    for (const [name, range] of deps) {
      const rule = RULE_BY_PACKAGE.get(name);
      if (!rule) continue;
      findings.push({
        source: 'deps',
        ruleId: rule.id,
        severity: rule.severity,
        category: rule.category,
        algorithm: rule.algorithm,
        title: rule.title,
        why: rule.why,
        migration: rule.migration,
        confidence: rule.confidence,
        lifetimeSensitive: rule.lifetimeSensitive,
        location: { file: pkgPath },
        package: name,
        range,
      });
    }

    return { findings };
  },
};
