import type { ScanResult } from '../types.ts';

/**
 * The stable, documented JSON schema. Treat this shape as a public API: field
 * names and semantics must not change without a version note in the README.
 *
 * `summary` mirrors v0.0.1's summary object (counts per severity); `findings`
 * carries the full discriminated-union shape so consumers can switch on
 * `source` and read scanner-specific fields.
 */
export function renderJson(result: ScanResult): string {
  const doc = {
    tool: result.tool,
    version: result.version,
    root: result.root,
    scanners: result.scanners,
    summary: result.counts,
    findings: result.findings,
  };
  return JSON.stringify(doc, null, 2);
}
