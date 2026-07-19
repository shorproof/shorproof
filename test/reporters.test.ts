import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine.ts';
import { renderJson, renderSarif, renderText } from '../src/reporters/index.ts';
import { SEVERITIES } from '../src/types.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/deps-basic', import.meta.url));
const ARTIFACTS = fileURLToPath(new URL('./fixtures/artifacts-jwks', import.meta.url));
const DUP_DECL = fileURLToPath(new URL('./fixtures/ast-dup-declaration', import.meta.url));

/** True if the string contains an ANSI SGR escape sequence (ESC + '['). */
const hasAnsi = (s: string): boolean => s.includes(`${String.fromCharCode(27)}[`);

describe('json reporter', () => {
  it('emits the stable public schema and consistent counts', async () => {
    const result = await scan({ root: FIXTURE });
    const doc = JSON.parse(renderJson(result)) as {
      tool: string;
      version: string;
      scanners: string[];
      summary: Record<string, number>;
      findings: Array<Record<string, unknown>>;
    };

    expect(doc.tool).toBe('shorproof');
    expect(doc.scanners).toContain('deps');
    expect(typeof doc.version).toBe('string');

    // summary totals reconcile with the findings array
    const summed = SEVERITIES.reduce((n, s) => n + (doc.summary[s] ?? 0), 0);
    expect(summed).toBe(doc.findings.length);

    // every deps finding carries the documented fields
    for (const f of doc.findings) {
      expect(f).toMatchObject({ source: 'deps' });
      for (const key of ['ruleId', 'severity', 'why', 'migration', 'package', 'range', 'location']) {
        expect(f, `finding missing ${key}`).toHaveProperty(key);
      }
    }
  });
});

describe('skipped-file reporting', () => {
  it('records un-analyzable files in the result and surfaces them in json + text', async () => {
    const result = await scan({ root: DUP_DECL });

    // The neighbour's finding survived, and the bad file is tracked, not swallowed.
    expect(result.findings.some((f) => f.ruleId === 'jsonwebtoken/rs256')).toBe(true);
    expect(result.skipped.length).toBe(1);
    expect(result.skipped[0]!.file).toContain('dup.js');
    expect(result.skipped[0]!.reason).toMatch(/Duplicate declaration/);

    // JSON exposes it as a stable array.
    const doc = JSON.parse(renderJson(result)) as { skipped: Array<{ file: string; reason: string }> };
    expect(doc.skipped.length).toBe(1);
    expect(doc.skipped[0]!.file).toContain('dup.js');

    // Text surfaces it in a footer.
    const text = renderText(result, { color: false });
    expect(text).toContain('could not be analyzed');
    expect(text).toContain('dup.js');
  });

  it('a clean scan reports an empty skipped array', async () => {
    const result = await scan({ root: FIXTURE });
    expect(result.skipped).toEqual([]);
    const doc = JSON.parse(renderJson(result)) as { skipped: unknown[] };
    expect(doc.skipped).toEqual([]);
  });
});

describe('sarif reporter', () => {
  it('emits valid SARIF 2.1.0 with deduped rules and correct level mapping', async () => {
    const result = await scan({ root: ARTIFACTS });
    const doc = JSON.parse(renderSarif(result)) as {
      version: string;
      $schema: string;
      runs: Array<{
        tool: {
          driver: {
            name: string;
            version: string;
            semanticVersion: string;
            rules: Array<Record<string, unknown>>;
          };
        };
        results: Array<{
          ruleId: string;
          ruleIndex: number;
          level: string;
          message: { text: string };
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
        }>;
      }>;
    };

    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toContain('sarif-2.1.0');
    const run = doc.runs[0]!;
    expect(run.tool.driver.name).toBe('shorproof');
    expect(run.tool.driver.semanticVersion).toBe(run.tool.driver.version);
    expect(run.tool.driver.semanticVersion.length).toBeGreaterThan(0);

    // one result per finding
    expect(run.results.length).toBe(result.findings.length);

    // rules are de-duplicated and every result's ruleIndex resolves to its rule
    const ids = run.tool.driver.rules.map((r) => r.id as string);
    expect(new Set(ids).size).toBe(ids.length);
    for (const res of run.results) {
      expect(run.tool.driver.rules[res.ruleIndex]!.id).toBe(res.ruleId);
      expect(res.locations[0]!.physicalLocation.artifactLocation.uri).not.toContain('\\');
    }

    // severity -> level mapping: this fixture has critical (error) and safe (none)
    const level = (rid: string) => run.results.find((r) => r.ruleId === rid)!.level;
    expect(level('jwks/rsa')).toBe('error'); // critical
    expect(level('jwks/ec')).toBe('error'); // high
    expect(level('jwks/akp')).toBe('none'); // safe — informational, not an alert

    // security-severity present for the vulnerable rule, absent for the safe one
    const rule = (rid: string) =>
      run.tool.driver.rules.find((r) => r.id === rid) as {
        properties: { 'security-severity'?: string };
        helpUri: string;
        shortDescription: { text: string };
      };
    expect(rule('jwks/rsa').properties['security-severity']).toBe('9.5');
    expect(rule('jwks/akp').properties['security-severity']).toBeUndefined();
    expect(rule('jwks/rsa').helpUri).toMatch(/^https?:\/\//);
    expect(rule('jwks/rsa').shortDescription.text.length).toBeGreaterThan(0);
  });
});

describe('text reporter', () => {
  it('has no ANSI codes when color is disabled', async () => {
    const result = await scan({ root: FIXTURE });
    const text = renderText(result, { color: false });
    expect(hasAnsi(text)).toBe(false);
    expect(text).toContain('shorproof');
    expect(text).toContain('HIGH (3)');
    expect(text).toContain('jsonwebtoken');
  });

  it('emits ANSI codes when color is enabled', async () => {
    const result = await scan({ root: FIXTURE });
    const text = renderText(result, { color: true });
    expect(hasAnsi(text)).toBe(true);
  });

  it('reports the clean case without findings', async () => {
    const clean = fileURLToPath(new URL('./fixtures/deps-clean', import.meta.url));
    const result = await scan({ root: clean });
    const text = renderText(result, { color: false });
    expect(text).toContain('No quantum-vulnerable cryptography found.');
  });
});
