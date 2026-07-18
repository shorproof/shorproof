import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative, sep } from 'node:path';
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine.ts';
import type { Finding } from '../src/types.ts';

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));

interface ExpectedFinding {
  readonly source: string;
  readonly ruleId: string;
  readonly severity: string;
  /** deps findings: the npm package name. */
  readonly package?: string;
  /** ast/artifact findings: path relative to the fixture root, forward slashes. */
  readonly file?: string;
}

/** Normalize an OS path to forward slashes so expectations are cross-platform. */
function toPosix(p: string): string {
  return p.split(sep).join('/');
}

/**
 * A stable identity for a finding, so comparisons are order-independent.
 * - deps: rule + package (line-independent; a manifest has no meaningful line).
 * - ast/artifact: rule + the file it was found in, relative to the fixture root.
 *   Line is deliberately excluded so adding a comment to a fixture doesn't break
 *   the expectation; fixtures keep each (ruleId, file) pair unique instead.
 */
function signature(f: Finding | ExpectedFinding, root: string): string {
  const base = `${f.source}|${f.ruleId}|${f.severity}`;
  if (f.source === 'deps') {
    return `${base}|${f.package ?? ''}`;
  }
  if ('location' in f) {
    return `${base}|${toPosix(relative(root, f.location.file))}`;
  }
  return `${base}|${f.file ?? ''}`;
}

function fixtureDirs(): string[] {
  return readdirSync(FIXTURES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(FIXTURES_DIR, d.name, 'expected.json')))
    .map((d) => d.name);
}

describe('fixture precision/recall', () => {
  for (const name of fixtureDirs()) {
    it(`matches expected findings: ${name}`, async () => {
      const root = join(FIXTURES_DIR, name);
      const expected = JSON.parse(
        readFileSync(join(root, 'expected.json'), 'utf8'),
      ) as { findings: ExpectedFinding[] };

      const result = await scan({ root });

      const produced = new Set(result.findings.map((f) => signature(f, root)));
      const wanted = new Set(expected.findings.map((f) => signature(f, root)));

      // Recall: everything expected was found.
      const missing = [...wanted].filter((s) => !produced.has(s));
      // Precision: nothing extra was produced.
      const extra = [...produced].filter((s) => !wanted.has(s));

      expect(missing, `missing findings in ${name}`).toEqual([]);
      expect(extra, `unexpected findings in ${name}`).toEqual([]);
    });
  }
});
