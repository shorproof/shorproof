import type { Binding, Scope } from '@babel/traverse';
import type * as t from '@babel/types';

/**
 * Best-effort constant propagation for the JWT/WebCrypto analyzers.
 *
 * Options objects and algorithm names are often written inline
 * (`{ algorithm: 'RS256' }`) but just as often reach a call through a `const`
 * (`const OPTS = { algorithm: ALG }`). These helpers resolve a node to its
 * literal value by following `const`/`let`/`var` identifier bindings, up to a
 * depth limit. "Best-effort" is deliberate: anything we can't resolve returns
 * null, and the caller degrades to a `review` finding rather than guessing.
 */

const MAX_DEPTH = 8;

/** The initializer of a variable-declarator binding, or null. */
function declaratorInit(binding: Binding): t.Expression | null {
  const node = binding.path.node;
  return node.type === 'VariableDeclarator' && node.init ? node.init : null;
}

/** Resolve a node to a string constant, following const identifier bindings. */
export function resolveString(scope: Scope, node: t.Node, depth = 0): string | null {
  if (depth > MAX_DEPTH) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'Identifier') {
    const binding = scope.getBinding(node.name);
    const init = binding && declaratorInit(binding);
    return init ? resolveString(binding.scope, init, depth + 1) : null;
  }
  return null;
}

/** Resolve a node to an object expression, following const identifier bindings. */
export function resolveObject(scope: Scope, node: t.Node, depth = 0): t.ObjectExpression | null {
  if (depth > MAX_DEPTH) return null;
  if (node.type === 'ObjectExpression') return node;
  if (node.type === 'Identifier') {
    const binding = scope.getBinding(node.name);
    const init = binding && declaratorInit(binding);
    return init ? resolveObject(binding.scope, init, depth + 1) : null;
  }
  return null;
}

/**
 * Resolve a node to an array of string constants (each element resolved
 * independently; unresolvable elements are null). Follows const bindings.
 */
export function resolveStringArray(scope: Scope, node: t.Node, depth = 0): (string | null)[] | null {
  if (depth > MAX_DEPTH) return null;
  if (node.type === 'ArrayExpression') {
    return node.elements.map((el) =>
      el && el.type !== 'SpreadElement' ? resolveString(scope, el, depth + 1) : null,
    );
  }
  if (node.type === 'Identifier') {
    const binding = scope.getBinding(node.name);
    const init = binding && declaratorInit(binding);
    return init ? resolveStringArray(binding.scope, init, depth + 1) : null;
  }
  return null;
}

/** The value node of a non-computed object property by key, or null. */
export function objectProperty(obj: t.ObjectExpression, key: string): t.Node | null {
  for (const prop of obj.properties) {
    if (prop.type !== 'ObjectProperty' || prop.computed) continue;
    const k = prop.key;
    const name = k.type === 'Identifier' ? k.name : k.type === 'StringLiteral' ? k.value : null;
    if (name === key) return prop.value;
  }
  return null;
}
