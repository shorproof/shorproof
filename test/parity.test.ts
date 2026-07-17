import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { scan } from '../src/engine.ts';

/**
 * v0.0.1 parity: the shipped legacy scanner (bin/shorproof.cjs) is the oracle.
 * We run it as a subprocess (it is plain CommonJS, so it runs on every Node in
 * the CI matrix) and compare its findings against the new engine's `deps`
 * findings, computed in-process. Equivalence here guarantees the port did not
 * silently change any user-visible finding: same packages, severities, and the
 * exact `reason`/`hint` text (now `why`/`migration`).
 *
 * We deliberately do NOT spawn the new TS CLI here — Node 20 cannot run
 * `.ts` natively. The compiled binary is smoke-tested separately in CI.
 */

const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url));
const FIXTURE = fileURLToPath(new URL('./fixtures/deps-basic', import.meta.url));

interface LegacyFinding {
  package: string;
  range: string;
  severity: string;
  reason: string;
  hint: string;
}

function runLegacy(): LegacyFinding[] {
  const stdout = execFileSync(process.execPath, ['bin/shorproof.cjs', FIXTURE, '--json'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });
  return (JSON.parse(stdout) as { findings: LegacyFinding[] }).findings;
}

describe('v0.0.1 parity (deps sub-scanner)', () => {
  it('produces the same set of flagged packages', async () => {
    const legacy = runLegacy();
    const result = await scan({ root: FIXTURE });
    const nextPkgs = result.findings
      .filter((f) => f.source === 'deps')
      .map((f) => f.package)
      .sort();
    expect(nextPkgs).toEqual(legacy.map((f) => f.package).sort());
  });

  it('preserves severity, reason (why), hint (migration) and range for every package', async () => {
    const legacy = runLegacy();
    const result = await scan({ root: FIXTURE });
    const byPackage = new Map(
      result.findings.filter((f) => f.source === 'deps').map((f) => [f.package, f]),
    );

    for (const old of legacy) {
      const current = byPackage.get(old.package);
      expect(current, `missing new finding for ${old.package}`).toBeDefined();
      expect(current!.severity, `severity for ${old.package}`).toBe(old.severity);
      expect(current!.why, `why/reason for ${old.package}`).toBe(old.reason);
      expect(current!.migration, `migration/hint for ${old.package}`).toBe(old.hint);
      expect(current!.range, `range for ${old.package}`).toBe(old.range);
    }
  });
});
