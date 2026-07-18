import type { Binding, NodePath, Scope } from '@babel/traverse';
import type * as t from '@babel/types';

/**
 * The binding layer — the core engineering idea of shorproof.
 *
 * Competing scanners match crypto calls by the literal object name (their
 * `jwt.sign` pattern fires only if the variable is named `jwt`). We instead
 * resolve the *binding* behind a call's callee: what module an identifier
 * actually refers to, regardless of the local name and regardless of whether it
 * arrived via default/named/renamed/namespace ESM import, `require`, or a
 * dynamic `import()`. Scope is honored (a shadowing local is not the module),
 * because we ask Babel's scope for the binding at the call site.
 *
 * The resolver is deliberately library-agnostic: it reports which module and
 * export a call resolves to; the scanner decides whether that module is tracked.
 */

/** A call resolved to a specific export of a specific module. */
export interface CallTarget {
  readonly module: string;
  readonly exportName: string;
}

/**
 * A binding classified as pointing at a module:
 * - `namespace`: the local name is the whole module object (default import for a
 *   builtin, `import *`, whole-module `require`, awaited dynamic `import`);
 *   member access on it yields an export.
 * - `named`: the local name IS a specific export (named/renamed import,
 *   destructured require, `require('m').foo`).
 */
type ResolvedBinding =
  | { readonly module: string; readonly kind: 'namespace' }
  | { readonly module: string; readonly kind: 'named'; readonly name: string };

/** The module string of a `require('m')` / `import('m')` / `await import('m')` node, else null. */
function moduleFromRequireLike(node: t.Node): string | null {
  const call = node.type === 'AwaitExpression' ? node.argument : node;
  if (call.type !== 'CallExpression') return null;
  const callee = call.callee;
  const isRequire = callee.type === 'Identifier' && callee.name === 'require';
  const isImport = callee.type === 'Import';
  if (!isRequire && !isImport) return null;
  const arg = call.arguments[0];
  return arg?.type === 'StringLiteral' ? arg.value : null;
}

/** For `const { key: local } = …`, the imported (`key`) name behind a given local name. */
function importedNameFromObjectPattern(pattern: t.ObjectPattern, localName: string): string | null {
  for (const prop of pattern.properties) {
    if (prop.type !== 'ObjectProperty' || prop.computed) continue;
    const { value, key } = prop;
    if (value.type !== 'Identifier' || value.name !== localName) continue;
    if (key.type === 'Identifier') return key.name;
    if (key.type === 'StringLiteral') return key.value;
  }
  return null;
}

/** Max binding hops to follow (`const c2 = c; const c3 = c2; …`) before giving up — cycle/blowup guard. */
const MAX_BINDING_DEPTH = 8;

/**
 * Classify what module (if any) a binding refers to, following simple
 * re-bindings up to a depth limit. Recursion resolves method extraction
 * (`const g = c.foo`) and namespace aliasing (`const c2 = c`).
 */
function classifyBinding(binding: Binding, depth = 0): ResolvedBinding | null {
  if (depth > MAX_BINDING_DEPTH) return null;
  const node = binding.path.node;

  // ESM: import D from 'm'  /  import * as N from 'm'
  if (node.type === 'ImportDefaultSpecifier' || node.type === 'ImportNamespaceSpecifier') {
    const decl = binding.path.parent;
    return decl.type === 'ImportDeclaration'
      ? { module: decl.source.value, kind: 'namespace' }
      : null;
  }

  // ESM: import { foo } from 'm'  /  import { foo as bar } from 'm'
  if (node.type === 'ImportSpecifier') {
    const decl = binding.path.parent;
    if (decl.type !== 'ImportDeclaration') return null;
    const { imported } = node;
    const name = imported.type === 'Identifier' ? imported.name : imported.value;
    return { module: decl.source.value, kind: 'named', name };
  }

  if (node.type === 'VariableDeclarator' && node.init) {
    return classifyDeclarator(binding, node, depth);
  }

  return null;
}

/** Classify `const … = <init>` initializers: require/import, member access, or a plain alias. */
function classifyDeclarator(
  binding: Binding,
  node: t.VariableDeclarator,
  depth: number,
): ResolvedBinding | null {
  const init = node.init;
  if (!init) return null;

  // const x = require('m') | await import('m')  — whole module or destructured
  const mod = moduleFromRequireLike(init);
  if (mod) {
    if (node.id.type === 'Identifier') return { module: mod, kind: 'namespace' };
    if (node.id.type === 'ObjectPattern') {
      const name = importedNameFromObjectPattern(node.id, binding.identifier.name);
      if (name) return { module: mod, kind: 'named', name };
    }
    return null;
  }

  // const foo = <expr>.prop  — require('m').foo, or member access on a namespace binding
  if (init.type === 'MemberExpression') {
    const propName = memberName(init);
    if (propName === null) return null;
    const reqMod = moduleFromRequireLike(init.object);
    if (reqMod) return { module: reqMod, kind: 'named', name: propName };
    if (init.object.type === 'Identifier') {
      const obj = resolveBindingName(binding, init.object.name, depth);
      if (obj?.kind === 'namespace') return { module: obj.module, kind: 'named', name: propName };
    }
    return null;
  }

  // const c2 = c  — a plain re-binding of another identifier
  if (init.type === 'Identifier') {
    return resolveBindingName(binding, init.name, depth);
  }

  return null;
}

/** Resolve an identifier referenced inside a declarator, from that declarator's own scope. */
function resolveBindingName(binding: Binding, name: string, depth: number): ResolvedBinding | null {
  const ref = binding.path.scope.getBinding(name);
  return ref ? classifyBinding(ref, depth + 1) : null;
}

/**
 * Resolve a call expression to the module export it invokes, or null if the
 * callee doesn't trace back to a module binding. Handles both direct calls of a
 * named binding (`foo(...)`) and member calls on a namespace binding
 * (`ns.foo(...)`). Uses scope, so a local shadow is correctly not the module.
 */
export function resolveCallTarget(path: NodePath<t.CallExpression>): CallTarget | null {
  return resolveCallee(path.scope, path.node.callee);
}

/**
 * Resolve a call or construct callee to the module export it names, or null.
 * Handles `foo(...)` / `new Foo(...)` (a named binding) and `ns.foo(...)` /
 * `new ns.Foo(...)` (a member on a namespace binding). Shared by the call and
 * the jose-builder analyzers.
 */
export function resolveCallee(scope: Scope, callee: t.Node): CallTarget | null {
  if (callee.type === 'Identifier') {
    const resolved = resolveName(scope, callee.name);
    return resolved?.kind === 'named'
      ? { module: resolved.module, exportName: resolved.name }
      : null;
  }

  if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
    const exportName = memberName(callee);
    if (exportName === null) return null;
    const resolved = resolveName(scope, callee.object.name);
    return resolved?.kind === 'namespace'
      ? { module: resolved.module, exportName }
      : null;
  }

  return null;
}

/**
 * The export name behind a member access: `obj.foo` (dot) or `obj['foo']`
 * (computed with a string literal). Computed access with a non-literal key
 * (`obj[dynamic]`) is unresolvable and returns null.
 */
function memberName(member: t.MemberExpression): string | null {
  const { property, computed } = member;
  if (!computed && property.type === 'Identifier') return property.name;
  if (computed && property.type === 'StringLiteral') return property.value;
  return null;
}

function resolveName(scope: Scope, name: string): ResolvedBinding | null {
  const binding = scope.getBinding(name);
  return binding ? classifyBinding(binding) : null;
}
