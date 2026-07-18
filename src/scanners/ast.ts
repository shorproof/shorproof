import { readFileSync } from 'node:fs';
import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';
import type { AstFinding, AstRule, Scanner, ScanContext } from '../types.ts';
import { NODE_CRYPTO_RULES } from '../rules/index.ts';
import { walkFiles } from '../walk.ts';
import { parseSource, traverse } from '../babel.ts';
import { resolveCallTarget } from './binding.ts';

/** Source extensions the AST scanner parses. */
const SOURCE_EXTENSIONS = ['.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts', '.tsx'] as const;

/** All AST rules the scanner consumes. Grows as M3 adds JWT/WebCrypto groups. */
const AST_RULES: readonly AstRule[] = NODE_CRYPTO_RULES;

/** The first argument of a call, if it is a plain string literal. */
function firstStringArg(call: t.CallExpression): string | null {
  const arg = call.arguments[0];
  return arg?.type === 'StringLiteral' ? arg.value : null;
}

/**
 * The rules that fire for a resolved call. Unconditional rules (the API itself
 * is the finding) always fire. For a family whose rules discriminate on the
 * first argument (generateKeyPair), the matching `firstArg` rule fires; if the
 * argument can't be resolved to any known value, the `firstArgFallback` rule
 * fires instead as a review-level finding. This dispatch is driven entirely by
 * the rule data — the engine stays generic.
 */
function matchRules(module: string, exportName: string, call: t.CallExpression): AstRule[] {
  const family = AST_RULES.filter(
    (rule) => rule.modules.includes(module) && rule.exports.includes(exportName),
  );
  if (family.length === 0) return [];

  const matched: AstRule[] = [];
  const argValue = firstStringArg(call);
  let hasConditional = false;
  let conditionalHit = false;

  for (const rule of family) {
    if (rule.firstArgFallback) continue; // considered only if nothing else matched
    if (rule.firstArg === undefined) {
      matched.push(rule);
      continue;
    }
    hasConditional = true;
    if (argValue !== null && rule.firstArg === argValue) {
      matched.push(rule);
      conditionalHit = true;
    }
  }

  if (hasConditional && !conditionalHit) {
    const fallback = family.find((rule) => rule.firstArgFallback);
    if (fallback) matched.push(fallback);
  }

  return matched;
}

/** A one-line, whitespace-collapsed excerpt of the call, for the report. */
function snippetOf(call: t.CallExpression, source: string): string {
  const { start, end } = call;
  if (typeof start !== 'number' || typeof end !== 'number') return '';
  const raw = source.slice(start, end).replace(/\s+/g, ' ').trim();
  return raw.length > 100 ? `${raw.slice(0, 99)}…` : raw;
}

function toFinding(rule: AstRule, file: string, call: t.CallExpression, source: string): AstFinding {
  const start = call.loc?.start;
  return {
    source: 'ast',
    ruleId: rule.id,
    severity: rule.severity,
    category: rule.category,
    algorithm: rule.algorithm,
    title: rule.title,
    why: rule.why,
    migration: rule.migration,
    confidence: rule.confidence,
    lifetimeSensitive: rule.lifetimeSensitive,
    location: {
      file,
      line: start?.line,
      // Babel columns are 0-based; report 1-based to match editors.
      column: start ? start.column + 1 : undefined,
    },
    snippet: snippetOf(call, source),
  };
}

/**
 * Scan one source string. Exposed (beyond the Scanner) so tests can exercise the
 * binding layer + rule matching on a snippet without touching the filesystem.
 */
export function scanSource(file: string, source: string): AstFinding[] {
  const ast = parseSource(source, file);
  if (!ast) return [];

  const findings: AstFinding[] = [];
  traverse(ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      const target = resolveCallTarget(path);
      if (!target) return;
      for (const rule of matchRules(target.module, target.exportName, path.node)) {
        findings.push(toFinding(rule, file, path.node, source));
      }
    },
  });
  return findings;
}

/**
 * The AST source scanner. Walks source files under the root, parses each with
 * Babel, and reports confirmed quantum-vulnerable call sites. A crypto import
 * alone is never a finding — only a confirmed vulnerable *usage* is.
 */
export const astScanner: Scanner = {
  name: 'ast',
  scan({ root }: ScanContext): AstFinding[] {
    const findings: AstFinding[] = [];
    for (const file of walkFiles(root, { extensions: SOURCE_EXTENSIONS })) {
      let source: string;
      try {
        source = readFileSync(file, 'utf8');
      } catch {
        continue; // unreadable file — skip, don't abort the scan
      }
      findings.push(...scanSource(file, source));
    }
    return findings;
  },
};
