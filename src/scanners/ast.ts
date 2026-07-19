import { readFileSync } from 'node:fs';
import type { NodePath, Scope } from '@babel/traverse';
import type { ParseResult } from '@babel/parser';
import type * as t from '@babel/types';
import type {
  AlgOutcome,
  AstFinding,
  AstRule,
  Category,
  Confidence,
  JwtCallRule,
  Scanner,
  ScanContext,
  ScanReport,
  Severity,
  SkippedFile,
} from '../types.ts';
import {
  NODE_CRYPTO_RULES,
  JSONWEBTOKEN_RULES,
  JWT_MIDDLEWARE_RULES,
  JOSE_RULES,
  JOSE_SIGN_BUILDERS,
  JOSE_BUILDER_REVIEW,
  WEBCRYPTO_METHODS,
  webcryptoOutcome,
} from '../rules/index.ts';
import { JWA_ALGS } from '../rules/jwa.ts';
import { walkFiles } from '../walk.ts';
import { parseSource, traverse } from '../babel.ts';
import { resolveCallTarget, resolveCallee, type CallTarget } from './binding.ts';
import { objectProperty, resolveObject, resolveString, resolveStringArray } from './constprop.ts';

/** Source extensions the AST scanner parses. */
const SOURCE_EXTENSIONS = ['.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts', '.tsx'] as const;

/** Everything needed to build a finding, independent of which analyzer produced it. */
interface FindingParts {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly category: Category;
  readonly algorithm: string;
  readonly confidence: Confidence;
  readonly lifetimeSensitive: boolean;
  readonly why: string;
  readonly migration: string;
}

/** A one-line, whitespace-collapsed excerpt of the call, for the report. */
function snippetOf(call: t.CallExpression, source: string): string {
  const { start, end } = call;
  if (typeof start !== 'number' || typeof end !== 'number') return '';
  const raw = source.slice(start, end).replace(/\s+/g, ' ').trim();
  return raw.length > 100 ? `${raw.slice(0, 99)}…` : raw;
}

function makeAstFinding(
  parts: FindingParts,
  file: string,
  call: t.CallExpression,
  source: string,
): AstFinding {
  const start = call.loc?.start;
  return {
    source: 'ast',
    ruleId: parts.ruleId,
    severity: parts.severity,
    category: parts.category,
    algorithm: parts.algorithm,
    title: parts.title,
    why: parts.why,
    migration: parts.migration,
    confidence: parts.confidence,
    lifetimeSensitive: parts.lifetimeSensitive,
    location: {
      file,
      line: start?.line,
      // Babel columns are 0-based; report 1-based to match editors.
      column: start ? start.column + 1 : undefined,
    },
    snippet: snippetOf(call, source),
  };
}

// --- node:crypto analyzer -----------------------------------------------

const AST_RULES: readonly AstRule[] = NODE_CRYPTO_RULES;

/** The first argument of a call, if it is a plain string literal. */
function firstStringArg(call: t.CallExpression): string | null {
  const arg = call.arguments[0];
  return arg?.type === 'StringLiteral' ? arg.value : null;
}

/**
 * The node:crypto rules that fire for a resolved call. Unconditional rules (the
 * API itself is the finding) always fire. For a family that discriminates on the
 * first argument (generateKeyPair), the matching `firstArg` rule fires; if the
 * argument can't be resolved, the `firstArgFallback` rule fires as review.
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
    if (rule.firstArgFallback) continue;
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

function ruleParts(rule: AstRule): FindingParts {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.category,
    algorithm: rule.algorithm,
    confidence: rule.confidence,
    lifetimeSensitive: rule.lifetimeSensitive,
    why: rule.why,
    migration: rule.migration,
  };
}

function analyzeNodeCrypto(
  target: CallTarget,
  path: NodePath<t.CallExpression>,
  file: string,
  source: string,
): AstFinding[] {
  return matchRules(target.module, target.exportName, path.node).map((rule) =>
    makeAstFinding(ruleParts(rule), file, path.node, source),
  );
}

// --- JWT analyzer (jsonwebtoken) ----------------------------------------

const JWT_RULES: readonly JwtCallRule[] = [
  ...JSONWEBTOKEN_RULES,
  ...JWT_MIDDLEWARE_RULES,
  ...JOSE_RULES,
];

function algParts(ruleIdPrefix: string, label: string, alg: string, outcome: AlgOutcome): FindingParts {
  return {
    ruleId: `${ruleIdPrefix}/${alg.toLowerCase()}`,
    title: `${label} — ${alg}`,
    severity: outcome.severity,
    category: outcome.category,
    algorithm: outcome.algorithm,
    confidence: outcome.confidence,
    lifetimeSensitive: outcome.lifetimeSensitive,
    why: outcome.why,
    migration: outcome.migration,
  };
}

function reviewParts(rule: JwtCallRule): FindingParts {
  return {
    ruleId: rule.reviewRuleId,
    title: rule.reviewTitle,
    severity: 'review',
    category: 'signature',
    algorithm: 'unresolved',
    confidence: 'low',
    lifetimeSensitive: false,
    why: rule.reviewWhy,
    migration: rule.reviewMigration,
  };
}

/** The options object of a JWT call, resolved through a const binding if needed. */
function optionsObject(
  path: NodePath<t.CallExpression>,
  arg: t.Expression | t.SpreadElement | t.ArgumentPlaceholder,
): t.ObjectExpression | null {
  if (arg.type === 'ObjectExpression') return arg;
  if (arg.type === 'Identifier') return resolveObject(path.scope, arg);
  return null;
}

function analyzeJwt(
  target: CallTarget,
  path: NodePath<t.CallExpression>,
  file: string,
  source: string,
): AstFinding[] {
  const rule = JWT_RULES.find(
    (r) => r.modules.includes(target.module) && r.export === target.exportName,
  );
  if (!rule) return [];

  const arg = path.node.arguments[rule.algArgIndex];
  // No arg, or a callback in the options slot — nothing to confirm (jsonwebtoken
  // defaults to safe HS256). Stay quiet.
  if (!arg || arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') return [];

  let algNode: t.Node;
  if (rule.algOptionKey !== undefined) {
    // Options-object mode (jsonwebtoken): the alg is a key of an options object.
    const obj = optionsObject(path, arg);
    if (!obj) return []; // unresolvable non-object (e.g. a callback var) — avoid a false positive
    const found = objectProperty(obj, rule.algOptionKey);
    if (!found) return []; // no algorithm key → default → nothing to confirm
    algNode = found;
  } else {
    // Direct-arg mode (jose generateKeyPair): the argument itself is the alg.
    algNode = arg;
  }

  const algValues = rule.algIsArray
    ? resolveStringArray(path.scope, algNode)
    : [resolveString(path.scope, algNode)];

  const findings: AstFinding[] = [];
  const seen = new Set<string>();
  let resolvedAny = false;
  let unresolvedAny = false;

  for (const alg of algValues ?? [null]) {
    if (alg === null) {
      unresolvedAny = true;
      continue;
    }
    const outcome = JWA_ALGS[alg];
    if (!outcome) {
      unresolvedAny = true;
      continue;
    }
    resolvedAny = true;
    if (seen.has(alg)) continue;
    seen.add(alg);
    const label = `${rule.ruleIdPrefix}.${rule.export}`;
    findings.push(makeAstFinding(algParts(rule.ruleIdPrefix, label, alg, outcome), file, path.node, source));
  }

  if (unresolvedAny && !resolvedAny) {
    findings.push(makeAstFinding(reviewParts(rule), file, path.node, source));
  }
  return findings;
}

// --- jose builder analyzer (SignJWT etc.) -------------------------------

const JOSE_BUILDERS = new Set(JOSE_SIGN_BUILDERS);

/** Does an expression chain root at `new <JoseSignBuilder>(…)` bound to jose? */
function isJoseSignBuilder(node: t.Node, scope: Scope, depth = 0): boolean {
  if (depth > 8) return false;
  if (node.type === 'NewExpression') {
    const target = resolveCallee(scope, node.callee);
    return target?.module === 'jose' && JOSE_BUILDERS.has(target.exportName);
  }
  // chained builder method: X.method(...) → unwrap to X
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    return isJoseSignBuilder(node.callee.object, scope, depth + 1);
  }
  // a variable holding the builder: const s = new SignJWT(...)
  if (node.type === 'Identifier') {
    const binding = scope.getBinding(node.name);
    if (!binding || binding.path.node.type !== 'VariableDeclarator' || !binding.path.node.init) {
      return false;
    }
    return isJoseSignBuilder(binding.path.node.init, binding.scope, depth + 1);
  }
  return false;
}

function joseReviewParts(): FindingParts {
  return {
    ruleId: JOSE_BUILDER_REVIEW.ruleId,
    title: JOSE_BUILDER_REVIEW.title,
    severity: 'review',
    category: 'signature',
    algorithm: 'unresolved',
    confidence: 'low',
    lifetimeSensitive: false,
    why: JOSE_BUILDER_REVIEW.why,
    migration: JOSE_BUILDER_REVIEW.migration,
  };
}

/**
 * Detect `new SignJWT(payload).setProtectedHeader({ alg })` (and the other jose
 * signing builders). The alg is the `alg` key of setProtectedHeader's object,
 * resolved through const bindings. Unresolvable → review.
 */
function analyzeJoseBuilder(
  path: NodePath<t.CallExpression>,
  file: string,
  source: string,
): AstFinding[] {
  const callee = path.node.callee;
  if (
    callee.type !== 'MemberExpression' ||
    callee.computed ||
    callee.property.type !== 'Identifier' ||
    callee.property.name !== 'setProtectedHeader'
  ) {
    return [];
  }
  if (!isJoseSignBuilder(callee.object, path.scope)) return [];

  const arg = path.node.arguments[0];
  if (!arg || arg.type === 'SpreadElement' || arg.type === 'ArgumentPlaceholder') return [];

  const obj =
    arg.type === 'ObjectExpression'
      ? arg
      : arg.type === 'Identifier'
        ? resolveObject(path.scope, arg)
        : null;
  if (!obj) return [makeAstFinding(joseReviewParts(), file, path.node, source)];

  const algNode = objectProperty(obj, 'alg');
  if (!algNode) return []; // no alg key in the header — nothing to confirm

  const alg = resolveString(path.scope, algNode);
  if (alg === null) return [makeAstFinding(joseReviewParts(), file, path.node, source)];

  const outcome = JWA_ALGS[alg];
  if (!outcome) return [makeAstFinding(joseReviewParts(), file, path.node, source)];

  return [makeAstFinding(algParts('jose', 'jose signer', alg, outcome), file, path.node, source)];
}

// --- WebCrypto analyzer (crypto.subtle.*) -------------------------------

const GLOBAL_HOSTS = new Set(['globalThis', 'self', 'window', 'global']);

function isNodeWebcrypto(target: CallTarget | null): boolean {
  return (
    target !== null &&
    (target.module === 'node:crypto' || target.module === 'crypto') &&
    target.exportName === 'webcrypto'
  );
}

/** Is `node` a WebCrypto-bearing crypto object (global crypto, globalThis.crypto, node:crypto.webcrypto)? */
function isWebCryptoHost(node: t.Node, scope: Scope): boolean {
  if (node.type === 'Identifier') {
    // A free `crypto` is the WebCrypto global; a bound name may be node:crypto's webcrypto.
    if (!scope.getBinding(node.name)) return node.name === 'crypto';
    return isNodeWebcrypto(resolveCallee(scope, node));
  }
  if (node.type === 'MemberExpression' && !node.computed && node.property.type === 'Identifier') {
    if (
      node.property.name === 'crypto' &&
      node.object.type === 'Identifier' &&
      GLOBAL_HOSTS.has(node.object.name) &&
      !scope.getBinding(node.object.name)
    ) {
      return true; // globalThis.crypto / self.crypto / window.crypto
    }
    return isNodeWebcrypto(resolveCallee(scope, node)); // <ns>.webcrypto
  }
  return false;
}

/** The algorithm name from a WebCrypto algorithm arg: 'X', { name: 'X' }, or a const of either. */
function webcryptoAlgName(scope: Scope, arg: t.Node | undefined): string | null {
  if (!arg) return null;
  const obj = resolveObject(scope, arg);
  if (obj) {
    const nameNode = objectProperty(obj, 'name');
    return nameNode ? resolveString(scope, nameNode) : null;
  }
  return resolveString(scope, arg);
}

/**
 * Detect `crypto.subtle.<method>(algorithm, …)`. The host must be a WebCrypto
 * object (binding-checked, so a local `crypto` isn't it). Only Shor-relevant
 * algorithms produce a finding; an unresolved algorithm stays quiet, because a
 * WebCrypto alg is just as likely symmetric (AES/HMAC) — no false alarms.
 */
function analyzeWebCrypto(
  path: NodePath<t.CallExpression>,
  file: string,
  source: string,
): AstFinding[] {
  const callee = path.node.callee;
  if (callee.type !== 'MemberExpression' || callee.computed || callee.property.type !== 'Identifier') {
    return [];
  }
  const rule = WEBCRYPTO_METHODS[callee.property.name];
  if (!rule) return [];

  const subtleExpr = callee.object;
  if (
    subtleExpr.type !== 'MemberExpression' ||
    subtleExpr.computed ||
    subtleExpr.property.type !== 'Identifier' ||
    subtleExpr.property.name !== 'subtle'
  ) {
    return [];
  }
  if (!isWebCryptoHost(subtleExpr.object, path.scope)) return [];

  const arg = path.node.arguments[rule.algArgIndex];
  const algArg = arg && arg.type !== 'SpreadElement' && arg.type !== 'ArgumentPlaceholder' ? arg : undefined;
  const algName = webcryptoAlgName(path.scope, algArg);
  if (algName === null) return [];

  const outcome = webcryptoOutcome(algName, rule.kind);
  if (!outcome) return []; // AES / SHA / HMAC / PBKDF2 / HKDF — not Shor-relevant

  const label = `crypto.subtle.${callee.property.name}`;
  return [makeAstFinding(algParts('webcrypto', label, algName, outcome), file, path.node, source)];
}

// --- scanner ------------------------------------------------------------

/** Traverse a parsed AST and collect findings. May throw if Babel's scope builder rejects the tree. */
function analyzeAst(ast: ParseResult<t.File>, file: string, source: string): AstFinding[] {
  const findings: AstFinding[] = [];
  traverse(ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      // jose builders and WebCrypto are method calls on an instance/host, not
      // resolved module-export calls — analyze them directly.
      findings.push(...analyzeJoseBuilder(path, file, source));
      findings.push(...analyzeWebCrypto(path, file, source));

      const target = resolveCallTarget(path);
      if (!target) return;
      findings.push(...analyzeNodeCrypto(target, path, file, source));
      findings.push(...analyzeJwt(target, path, file, source));
    },
  });
  return findings;
}

/**
 * Scan one source string. Exposed (beyond the Scanner) so tests can exercise the
 * binding layer + rule matching on a snippet without touching the filesystem.
 * Returns no findings for an unparseable snippet; may throw if traversal does.
 */
export function scanSource(file: string, source: string): AstFinding[] {
  const ast = parseSource(source, file);
  if (!ast) return [];
  return analyzeAst(ast, file, source);
}

/**
 * The AST source scanner. Walks source files under the root, parses each with
 * Babel, and reports confirmed quantum-vulnerable call sites. A crypto import
 * alone is never a finding — only a confirmed vulnerable *usage* is.
 *
 * A file that cannot be parsed, or whose traversal throws (e.g. Babel's scope
 * builder rejecting a duplicate declaration in a vendored/concatenated file), is
 * recorded in `skipped` and does not abort the scan — one bad file must never
 * hide the findings in the rest of the tree, and the skip is reported, not
 * swallowed.
 */
export const astScanner: Scanner = {
  name: 'ast',
  scan({ root }: ScanContext): ScanReport {
    const findings: AstFinding[] = [];
    const skipped: SkippedFile[] = [];
    for (const file of walkFiles(root, { extensions: SOURCE_EXTENSIONS })) {
      let source: string;
      try {
        source = readFileSync(file, 'utf8');
      } catch {
        continue; // unreadable file — skip, don't abort the scan
      }

      const ast = parseSource(source, file);
      if (!ast) {
        skipped.push({ file, reason: 'parse error' });
        continue;
      }
      try {
        findings.push(...analyzeAst(ast, file, source));
      } catch (err) {
        skipped.push({ file, reason: `analysis error: ${(err as Error).message}` });
      }
    }
    return { findings, skipped };
  },
};
