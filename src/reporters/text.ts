import { styleText } from 'node:util';
import { relative } from 'node:path';
import type { Finding, ScanResult, Severity } from '../types.ts';
import { SEVERITIES } from '../types.ts';

type Format = Parameters<typeof styleText>[0];

/** Per-severity color. Calm, not alarmist — critical is the only bold-red. */
const SEVERITY_FORMAT: Readonly<Record<Severity, Format>> = {
  critical: ['red', 'bold'],
  high: 'red',
  medium: 'yellow',
  review: 'cyan',
  safe: 'green',
  info: 'gray',
};

/** Human labels for the summary line and group headers. */
const SEVERITY_LABEL: Readonly<Record<Severity, string>> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  review: 'review',
  safe: 'safe',
  info: 'info',
};

function makePaint(color: boolean) {
  // The CLI already decided whether color is appropriate (TTY, NO_COLOR,
  // --no-color), so when told to paint we emit unconditionally. Without
  // `validateStream: false`, styleText re-checks process.stdout and would strip
  // colors whenever output is piped — overriding the caller's explicit intent.
  return (format: Format, text: string): string =>
    color ? styleText(format, text, { validateStream: false }) : text;
}

/** The one-line subject for a finding, which differs by scanner. */
function subject(finding: Finding): string {
  switch (finding.source) {
    case 'deps':
      return `${finding.package} ${finding.range}`.trim();
    case 'ast':
      return finding.snippet.trim();
    case 'artifact':
      return finding.detail ?? finding.title;
  }
}

/** Where a finding points, relative to the scan root when possible. */
function locationLine(finding: Finding, root: string): string {
  const file = relative(root, finding.location.file) || finding.location.file;
  const line = finding.location.line;
  return line ? `${file}:${line}` : file;
}

export interface TextReportOptions {
  readonly color: boolean;
}

/**
 * Render a scan result as grouped, calm terminal text: findings under severity
 * headers, each with its subject, location, honest `why`, and migration hint.
 */
export function renderText(result: ScanResult, options: TextReportOptions): string {
  const paint = makePaint(options.color);
  const out: string[] = [];

  out.push('');
  out.push(
    `${paint('bold', 'shorproof')} v${result.version} ${paint('dim', '— post-quantum readiness scanner')}`,
  );
  out.push(paint('dim', `Scanned ${result.root}`));
  out.push('');

  if (result.findings.length === 0) {
    out.push(paint('green', 'No quantum-vulnerable cryptography found.'));
    out.push('');
    appendSkipped(out, result, paint);
    return out.join('\n');
  }

  for (const severity of SEVERITIES) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;

    const header = `${SEVERITY_LABEL[severity].toUpperCase()} (${group.length})`;
    out.push(`  ${paint(SEVERITY_FORMAT[severity], header)}`);

    for (const finding of group) {
      out.push(`    ${paint('bold', subject(finding))}  ${paint('dim', finding.algorithm)}`);
      out.push(`      ${paint('dim', locationLine(finding, result.root))}`);
      out.push(`      ${finding.why}`);
      if (finding.migration) out.push(`      ${paint('dim', `→ ${finding.migration}`)}`);
      out.push('');
    }
  }

  appendSkipped(out, result, paint);
  out.push(`  ${summaryLine(result, paint)}`);
  out.push('');
  return out.join('\n');
}

/**
 * Footer listing files that could not be analyzed. Surfaced, never swallowed: a
 * silent skip is a blind spot, and this must show even when there are zero
 * findings (a skipped file could be the one that mattered).
 */
function appendSkipped(
  out: string[],
  result: ScanResult,
  paint: ReturnType<typeof makePaint>,
): void {
  if (result.skipped.length === 0) return;
  const n = result.skipped.length;
  out.push(`  ${paint('yellow', `⚠ ${n} file${n === 1 ? '' : 's'} could not be analyzed`)}`);
  for (const s of result.skipped) {
    const file = relative(result.root, s.file) || s.file;
    out.push(`      ${paint('dim', `${file} — ${s.reason}`)}`);
  }
  out.push('');
}

function summaryLine(result: ScanResult, paint: ReturnType<typeof makePaint>): string {
  const parts: string[] = [];
  for (const severity of SEVERITIES) {
    const count = result.counts[severity];
    if (count > 0) {
      parts.push(paint(SEVERITY_FORMAT[severity], `${count} ${SEVERITY_LABEL[severity]}`));
    }
  }
  return parts.join(paint('dim', ' · '));
}
