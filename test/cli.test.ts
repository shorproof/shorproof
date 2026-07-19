import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, it, expect } from 'vitest';

/**
 * End-to-end exit-code contract. The CLI's public promise is its exit codes, so
 * we drive the real compiled binary as a subprocess:
 *   0 — clean, or findings without --strict
 *   1 — --strict with a critical/high finding
 *   2 — usage/IO error (bad directory, unknown --format)
 *
 * We run dist/cli.js (not src/cli.ts) so this passes on every Node in the CI
 * matrix — Node 20 cannot type-strip .ts natively. `beforeAll` builds dist so
 * the test reflects current source and works locally without a prior build.
 */

const REPO_ROOT = fileURLToPath(new URL('../', import.meta.url));
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const TSC = fileURLToPath(new URL('../node_modules/typescript/lib/tsc.js', import.meta.url));
const DEPS_BASIC = fileURLToPath(new URL('./fixtures/deps-basic', import.meta.url));
const DEPS_CLEAN = fileURLToPath(new URL('./fixtures/deps-clean', import.meta.url));
const ARTIFACTS_X509 = fileURLToPath(new URL('./fixtures/artifacts-x509', import.meta.url));
const DUP_DECL = fileURLToPath(new URL('./fixtures/ast-dup-declaration', import.meta.url));

interface CliRun {
  status: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): CliRun {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  });
  return { status: res.status ?? -1, stdout: res.stdout, stderr: res.stderr };
}

beforeAll(() => {
  const build = spawnSync(process.execPath, [TSC], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (build.status !== 0) {
    throw new Error(`tsc build failed before CLI e2e tests:\n${build.stdout}\n${build.stderr}`);
  }
}, 60_000);

describe('CLI exit codes', () => {
  it('exits 0 on a clean project', () => {
    expect(runCli([DEPS_CLEAN]).status).toBe(0);
  });

  it('exits 0 when findings exist but --strict is not set', () => {
    expect(runCli([DEPS_BASIC]).status).toBe(0);
  });

  it('exits 1 with --strict when a high finding exists', () => {
    expect(runCli([DEPS_BASIC, '--strict']).status).toBe(1);
  });

  it('exits 0 with --strict when nothing critical/high is found', () => {
    expect(runCli([DEPS_CLEAN, '--strict']).status).toBe(0);
  });

  it('exits 0 with --fail-on critical when only high findings exist', () => {
    // deps-basic tops out at high — the critical threshold must not trip.
    expect(runCli([DEPS_BASIC, '--fail-on', 'critical']).status).toBe(0);
  });

  it('exits 1 with --fail-on medium when a high finding exists', () => {
    expect(runCli([DEPS_BASIC, '--fail-on', 'medium']).status).toBe(1);
  });

  it('exits 1 with --fail-on critical when a critical artifact finding exists', () => {
    // The RSA cert valid past 2030 is critical — end-to-end through the artifacts scanner.
    expect(runCli([ARTIFACTS_X509, '--fail-on', 'critical']).status).toBe(1);
  });

  it('exits 2 on an unknown --fail-on value', () => {
    const run = runCli([DEPS_BASIC, '--fail-on', 'bogus']);
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('unknown --fail-on');
  });

  it('survives an un-analyzable file: exits 0, still reports neighbours, notes the skip', () => {
    // dup.js makes Babel's scope builder throw; vuln.js has a real RS256 usage.
    const run = runCli([DUP_DECL, '--no-color']);
    expect(run.status).toBe(0); // not 2 — one bad file must not abort the scan
    expect(run.stdout).toContain('RS256'); // the neighbour's finding survives
    expect(run.stdout).toContain('could not be analyzed'); // the skip is surfaced, not swallowed
    expect(run.stdout).toContain('dup.js');
  });

  it('exits 2 on a non-existent directory', () => {
    const run = runCli(['./definitely-not-a-real-dir-xyz']);
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('shorproof:');
  });

  it('exits 2 on an unknown --format', () => {
    const run = runCli([DEPS_BASIC, '--format', 'bogus']);
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('unknown --format');
  });

  it('exits 0 and prints help for --help', () => {
    const run = runCli(['--help']);
    expect(run.status).toBe(0);
    expect(run.stdout).toContain('Usage:');
  });

  it('emits valid JSON with --json and exits 0', () => {
    const run = runCli([DEPS_BASIC, '--json']);
    expect(run.status).toBe(0);
    const doc = JSON.parse(run.stdout) as { tool: string; version: string };
    expect(doc.tool).toBe('shorproof');
    expect(doc.version).toBe('0.1.0');
  });
});
