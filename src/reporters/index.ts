/** Reporter registry. Text is the default; JSON, SARIF and CBOM are machine formats. */
export { renderText } from './text.ts';
export type { TextReportOptions } from './text.ts';
export { renderJson } from './json.ts';
export { renderSarif } from './sarif.ts';
export { renderCbom } from './cbom.ts';

export const REPORT_FORMATS = ['text', 'json', 'sarif', 'cbom'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** Narrow an untrusted string to a supported report format. */
export function isReportFormat(value: string): value is ReportFormat {
  return (REPORT_FORMATS as readonly string[]).includes(value);
}
