import { extname } from 'node:path';
import { parse } from '@babel/parser';
import type { ParseResult, ParserPlugin } from '@babel/parser';
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
 * Babel plugins for a file, chosen by extension. The `jsx` plugin makes `<` the
 * start of a JSX element, which collides with TypeScript angle-bracket casts
 * (`<T>x`) — legacy syntax, but common in exactly the older codebases we target,
 * and a parse failure there loses every finding in the file. So `.ts`/`.mts`/
 * `.cts` parse WITHOUT jsx, `.tsx` with both, and plain JS/JSX with jsx only. A
 * missing filename (e.g. an ad-hoc snippet in a test) is treated as plain JS.
 */
function pluginsFor(filename: string | undefined): ParserPlugin[] {
  switch (filename ? extname(filename).toLowerCase() : '') {
    case '.ts':
    case '.mts':
    case '.cts':
      return ['typescript'];
    case '.tsx':
      return ['typescript', 'jsx'];
    default:
      return ['jsx'];
  }
}

/**
 * Parse source to an AST, or return null if it cannot be parsed. A scan should
 * degrade over a single unparseable file rather than abort the whole run.
 * `sourceType: 'unambiguous'` lets one parser handle both ESM and CJS;
 * `errorRecovery` lets us still inspect a file with a localized syntax error.
 */
export function parseSource(code: string, filename?: string): ParseResult<t.File> | null {
  try {
    return parse(code, {
      sourceType: 'unambiguous',
      plugins: pluginsFor(filename),
      errorRecovery: true,
    });
  } catch {
    return null;
  }
}
