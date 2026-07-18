#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { scan } from './engine.ts';
import { renderText, renderJson } from './reporters/index.ts';
import { REPORT_FORMATS, isReportFormat, type ReportFormat } from './reporters/index.ts';
import { VERSION } from './version.ts';

const HELP = `
shorproof v${VERSION} — post-quantum readiness scanner

Usage:
  npx shorproof [dir] [options]

Options:
  --format <text|json>   output format (default: text)
  --json                 shorthand for --format json
  --strict               exit 1 if any critical/high finding exists
  --no-color             disable colored output
  --version, -v          print version
  --help, -h             show this help

This build scans dependency manifests (package.json). AST source scanning,
CycloneDX CBOM and SARIF output are in development for v0.1.
`;

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
  const output = format === 'json' ? `${renderJson(result)}\n` : renderText(result, { color: useColor });
  process.stdout.write(output);

  // M1 exit-code policy (v0.0.1 parity): --strict fails on critical/high.
  // Full --fail-on threshold logic lands in M4.
  if (values.strict && result.counts.critical + result.counts.high > 0) {
    process.exit(1);
  }
} catch (err) {
  fail(`shorproof: ${(err as Error).message}`);
}
