#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { scan } from './engine.ts';
import type { ScanResult, Severity } from './types.ts';
import { SEVERITY_RANK } from './types.ts';
import { renderText, renderJson, renderSarif, renderCbom } from './reporters/index.ts';
import { REPORT_FORMATS, isReportFormat, type ReportFormat } from './reporters/index.ts';
import { VERSION } from './version.ts';

const HELP = `
shorproof v${VERSION} — post-quantum readiness scanner

Usage:
  npx shorproof [dir] [options]

Options:
  --format <text|json|sarif|cbom>  output format (default: text)
  --json                           shorthand for --format json
  --fail-on <severity>             exit 1 if any finding is at or above
                                   <critical|high|medium|review>
  --strict                         shorthand for --fail-on high
  --no-color                       disable colored output
  --version, -v                    print version
  --help, -h                       show this help

Scans dependency manifests, JS/TS source (AST), and key/cert artifacts
(JWKS/PEM/X.509). SARIF 2.1.0 output feeds GitHub code scanning; CBOM is
CycloneDX 1.6. Exit codes: 0 clean/reported, 1 threshold met, 2 usage/IO error.
`;

/** Severities a --fail-on threshold may name (safe/info are never failures). */
const FAIL_ON_SEVERITIES = ['critical', 'high', 'medium', 'review'] as const;

function isFailOnSeverity(value: string): value is (typeof FAIL_ON_SEVERITIES)[number] {
  return (FAIL_ON_SEVERITIES as readonly string[]).includes(value);
}

/** Serialize a scan result in the requested format (text is the only colored one). */
function render(result: ScanResult, format: ReportFormat, color: boolean): string {
  switch (format) {
    case 'json':
      return `${renderJson(result)}\n`;
    case 'sarif':
      return `${renderSarif(result)}\n`;
    case 'cbom':
      return `${renderCbom(result)}\n`;
    case 'text':
      return renderText(result, { color });
  }
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

// `--no-color` is handled manually — node:util parseArgs has no boolean negation.
const rawArgs = process.argv.slice(2);
const noColorFlag = rawArgs.includes('--no-color');
const args = rawArgs.filter((a) => a !== '--no-color');

let parsed;
try {
  parsed = parseArgs({
    args,
    allowPositionals: true,
    options: {
      format: { type: 'string' },
      json: { type: 'boolean', default: false },
      strict: { type: 'boolean', default: false },
      'fail-on': { type: 'string' },
      version: { type: 'boolean', short: 'v', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
} catch (err) {
  fail(`shorproof: ${(err as Error).message}`);
}

const { values, positionals } = parsed;

if (values.help) {
  process.stdout.write(HELP);
  process.exit(0);
}
if (values.version) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(0);
}

const requestedFormat = values.json ? 'json' : (values.format ?? 'text');
if (!isReportFormat(requestedFormat)) {
  fail(`shorproof: unknown --format '${requestedFormat}' (expected: ${REPORT_FORMATS.join(', ')})`);
}
const format: ReportFormat = requestedFormat;

// Failure threshold: --fail-on <severity> wins; --strict is shorthand for high;
// otherwise findings are reported but never fail the run.
let failOn: Severity | null = null;
if (values['fail-on'] !== undefined) {
  if (!isFailOnSeverity(values['fail-on'])) {
    fail(
      `shorproof: unknown --fail-on '${values['fail-on']}' (expected: ${FAIL_ON_SEVERITIES.join(', ')})`,
    );
  }
  failOn = values['fail-on'];
} else if (values.strict) {
  failOn = 'high';
}

const dir = positionals[0] ?? '.';
const root = resolve(process.cwd(), dir);

try {
  const stat = statSync(root);
  if (!stat.isDirectory()) fail(`shorproof: not a directory: ${root}`);
} catch {
  fail(`shorproof: no such directory: ${root}`);
}

const useColor =
  format === 'text' &&
  process.stdout.isTTY === true &&
  !('NO_COLOR' in process.env) &&
  !noColorFlag;

try {
  const result = await scan({ root });
  process.stdout.write(render(result, format, useColor));

  // Exit 1 when any finding is at or above the chosen threshold. safe/info rank
  // below every allowed threshold, so they can never fail a run.
  if (failOn !== null) {
    const limit = SEVERITY_RANK[failOn];
    if (result.findings.some((f) => SEVERITY_RANK[f.severity] <= limit)) {
      process.exit(1);
    }
  }
} catch (err) {
  fail(`shorproof: ${(err as Error).message}`);
}
