import { describe, it, expect } from 'vitest';
import type { NodePath } from '@babel/traverse';
import type * as t from '@babel/types';
import { parseSource, traverse } from '../src/babel.ts';
import { resolveCallTarget, type CallTarget } from '../src/scanners/binding.ts';

/** Every call target the binding layer resolves in a snippet. */
function targets(source: string): CallTarget[] {
  const ast = parseSource(source);
  if (!ast) throw new Error('snippet failed to parse');
  const found: CallTarget[] = [];
  traverse(ast, {
    CallExpression(path: NodePath<t.CallExpression>) {
      const target = resolveCallTarget(path);
      if (target) found.push(target);
    },
  });
  return found;
}

const GEN = { module: 'node:crypto', exportName: 'generateKeyPairSync' } as const;

// The six binding styles ARE the spec: the same vulnerable node:crypto call must
// resolve identically whether reached via default/renamed/destructured/namespace
// import, require, or dynamic import — regardless of the local variable name.
describe('binding layer resolves node:crypto through every import style', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['default import', `import crypto from 'node:crypto'; crypto.generateKeyPairSync('rsa');`],
    ['renamed named import', `import { generateKeyPairSync as mk } from 'node:crypto'; mk('rsa');`],
    ['destructured require', `const { generateKeyPairSync } = require('node:crypto'); generateKeyPairSync('rsa');`],
    ['namespace import', `import * as c from 'node:crypto'; c.generateKeyPairSync('rsa');`],
    ['whole-module require', `const nc = require('node:crypto'); nc.generateKeyPairSync('rsa');`],
    ['dynamic import()', `const m = await import('node:crypto'); m.generateKeyPairSync('rsa');`],
  ];

  for (const [label, code] of cases) {
    it(label, () => {
      expect(targets(code)).toContainEqual(GEN);
    });
  }
});

describe('binding layer honors scope and rejects non-module bindings', () => {
  it('a local object literal named crypto is not the module', () => {
    expect(targets(`const crypto = { generateKeyPairSync() {} }; crypto.generateKeyPairSync('rsa');`)).toEqual([]);
  });

  it('a block-scoped shadow overrides the real import', () => {
    const code = `import crypto from 'node:crypto';
      export function f() {
        const crypto = { generateKeyPairSync() {} };
        return crypto.generateKeyPairSync('rsa');
      }`;
    expect(targets(code)).toEqual([]);
  });

  it('a function parameter named crypto is not the module', () => {
    expect(targets(`export function f(crypto) { return crypto.generateKeyPairSync('rsa'); }`)).toEqual([]);
  });

  it('the method on a createSign() result is not node:crypto.sign', () => {
    const code = `import { createSign } from 'node:crypto';
      const signer = createSign('sha256');
      signer.sign(key);`;
    // Only createSign resolves; signer.sign(...) is a method on a local value.
    expect(targets(code)).toEqual([{ module: 'node:crypto', exportName: 'createSign' }]);
  });
});

describe('binding layer keeps the imported export name across renames', () => {
  it('renamed destructure resolves to the original export', () => {
    const code = `const { generateKeyPairSync: gk } = require('node:crypto'); gk('rsa');`;
    expect(targets(code)).toContainEqual(GEN);
  });

  it('require member access resolves the accessed export', () => {
    const code = `const cs = require('node:crypto').createSign; cs('sha256');`;
    expect(targets(code)).toContainEqual({ module: 'node:crypto', exportName: 'createSign' });
  });
});
