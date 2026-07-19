/**
 * Public library API. Importing `shorproof` gives you the engine, the reporters,
 * and the types — the same building blocks the CLI uses.
 */
export { scan, DEFAULT_SCANNERS } from './engine.ts';
export type { ScanOptions } from './engine.ts';
export { renderText, renderJson } from './reporters/index.ts';
export type { ReportFormat, TextReportOptions } from './reporters/index.ts';
export { depsScanner } from './scanners/deps.ts';
export { DEP_RULES } from './rules/index.ts';
export { VERSION } from './version.ts';
export type {
  Severity,
  Category,
  Confidence,
  Rule,
  DepRule,
  Finding,
  DepFinding,
  AstFinding,
  ArtifactFinding,
  Location,
  Scanner,
  ScanContext,
  ScanReport,
  ScanResult,
  SkippedFile,
  SeverityCounts,
} from './types.ts';
