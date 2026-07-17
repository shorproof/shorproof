/** Reporter registry. Text is the default; more reporters land in M4. */
export { renderText } from './text.ts';
export type { TextReportOptions } from './text.ts';
export { renderJson } from './json.ts';

export const REPORT_FORMATS = ['text', 'json'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];
