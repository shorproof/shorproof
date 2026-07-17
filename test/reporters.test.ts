import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine.ts';
import { renderJson, renderText } from '../src/reporters/index.ts';
import { SEVERITIES } from '../src/types.ts';

const FIXTURE = fileURLToPath(new URL('./fixtures/deps-basic', import.meta.url));

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
