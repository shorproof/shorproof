/** Reporter registry. Text is the default; more reporters land in M4. */
export { renderText } from './text.ts';
export type { TextReportOptions } from './text.ts';
export { renderJson } from './json.ts';

export const REPORT_FORMATS = ['text', 'json'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

/** Narrow an untrusted string to a supported report format. */
export function isReportFormat(value: string): value is ReportFormat {
  return (REPORT_FORMATS as readonly string[]).includes(value);
}
