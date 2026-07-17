import { readFileSync } from 'node:fs';

/**
 * The running tool version, read from package.json at runtime so it can never
 * drift from what npm published. Resolves the same whether we run from `src/`
 * (dev, native type-stripping) or `dist/` (published) — package.json sits one
 * directory up from both.
 */
const pkg = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as { version: string };

export const VERSION: string = pkg.version;
