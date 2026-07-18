import { parse } from '@babel/parser';
import type { ParseResult } from '@babel/parser';
import traverseImport from '@babel/traverse';
import type * as t from '@babel/types';

/**
 * The tool's entire Babel surface — its only two runtime dependencies
 * (@babel/parser, @babel/traverse) — isolated to this one module.
 *
 * @babel/traverse ships as CommonJS; under Node's ESM the default import
 * resolves to the module-exports object, so the callable traverse lives on
 * `.default`. TypeScript (nodenext) types that default import as the module
 * namespace too, so we reach through `.default` and restore the callable type
 * from the package's actual default-export type. Unwrapped once, here.
 */
type TraverseFn = NonNullable<(typeof traverseImport)['default']>;
export const traverse: TraverseFn =
  traverseImport.default ?? (traverseImport as unknown as TraverseFn);

/**
 * Parse source to an AST, or return null if it cannot be parsed. A scan should
 * degrade over a single unparseable file rather than abort the whole run.
 *
 * Options are fixed by CLAUDE.md: `sourceType: 'unambiguous'` (so one parser
 * handles ESM and CJS), plugins `typescript` + `jsx`. `errorRecovery` lets us
 * still inspect a file with a localized syntax error instead of losing it.
 */
export function parseSource(code: string): ParseResult<t.File> | null {
  try {
    return parse(code, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx'],
      errorRecovery: true,
    });
  } catch {
    return null;
  }
}
