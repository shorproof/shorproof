import type { Binding, NodePath } from '@babel/traverse';
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

/** Classify what module (if any) a binding refers to. */
function classifyBinding(binding: Binding): ResolvedBinding | null {
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

  // CJS / dynamic: const … = require('m') | await import('m') | require('m').foo
  if (node.type === 'VariableDeclarator' && node.init) {
    const { init, id } = node;

    // const foo = require('m').foo
    if (init.type === 'MemberExpression' && !init.computed && init.property.type === 'Identifier') {
      const mod = moduleFromRequireLike(init.object);
      if (mod) return { module: mod, kind: 'named', name: init.property.name };
    }

    const mod = moduleFromRequireLike(init);
    if (mod) {
      if (id.type === 'Identifier') return { module: mod, kind: 'namespace' };
      if (id.type === 'ObjectPattern') {
        const name = importedNameFromObjectPattern(id, binding.identifier.name);
        if (name) return { module: mod, kind: 'named', name };
      }
    }
  }

  return null;
}

/**
 * Resolve a call expression to the module export it invokes, or null if the
 * callee doesn't trace back to a module binding. Handles both direct calls of a
 * named binding (`foo(...)`) and member calls on a namespace binding
 * (`ns.foo(...)`). Uses scope, so a local shadow is correctly not the module.
 */
export function resolveCallTarget(path: NodePath<t.CallExpression>): CallTarget | null {
  const { callee } = path.node;

  if (callee.type === 'Identifier') {
    const resolved = resolveIdentifier(path, callee.name);
    return resolved?.kind === 'named'
      ? { module: resolved.module, exportName: resolved.name }
      : null;
  }

  if (
    callee.type === 'MemberExpression' &&
    !callee.computed &&
    callee.object.type === 'Identifier' &&
    callee.property.type === 'Identifier'
  ) {
    const resolved = resolveIdentifier(path, callee.object.name);
    return resolved?.kind === 'namespace'
      ? { module: resolved.module, exportName: callee.property.name }
      : null;
  }

  return null;
}

function resolveIdentifier(path: NodePath<t.CallExpression>, name: string): ResolvedBinding | null {
  const binding = path.scope.getBinding(name);
  return binding ? classifyBinding(binding) : null;
}
