import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine.ts';
import type { Finding } from '../src/types.ts';

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));

interface ExpectedFinding {
  readonly source: string;
  readonly ruleId: string;
  readonly severity: string;
  readonly package?: string;
}

/** A stable identity for a finding, so comparisons are order-independent. */
function signature(f: Finding | ExpectedFinding): string {
  const base = `${f.source}|${f.ruleId}|${f.severity}`;
  const pkg = 'package' in f ? f.package : undefined;
  if (pkg) return `${base}|${pkg}`;
  const loc = 'location' in f ? f.location : undefined;
  return `${base}|${loc?.file ?? ''}:${loc?.line ?? ''}`;
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

      const produced = new Set(result.findings.map(signature));
      const wanted = new Set(expected.findings.map(signature));

      // Recall: everything expected was found.
      const missing = [...wanted].filter((s) => !produced.has(s));
      // Precision: nothing extra was produced.
      const extra = [...produced].filter((s) => !wanted.has(s));

      expect(missing, `missing findings in ${name}`).toEqual([]);
      expect(extra, `unexpected findings in ${name}`).toEqual([]);
    });
  }
});
