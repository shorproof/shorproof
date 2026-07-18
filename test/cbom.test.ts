import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import type { ValidateFunction } from 'ajv';
import { scan } from '../src/engine.ts';
import { renderCbom } from '../src/reporters/index.ts';

const schemaUrl = (name: string): string =>
  fileURLToPath(new URL(`./schemas/cyclonedx/${name}`, import.meta.url));

function loadSchema(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(schemaUrl(name), 'utf8')) as Record<string, unknown>;
}

const fixture = (name: string): string => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

let validate: ValidateFunction;

beforeAll(() => {
  // draft-07 schema; strict off because the CycloneDX schema uses vocabulary
  // (e.g. non-standard formats) ajv doesn't need to enforce for our purposes.
  // logger:false silences ajv's compile-time "unknown format" notices for
  // CycloneDX vocabulary (iri-reference etc.); validation errors still surface.
  const ajv = new Ajv({ strict: false, allErrors: true, logger: false });
  addFormats(ajv);
  // The BOM schema references these two by relative URI, resolved against their $id.
  ajv.addSchema(loadSchema('spdx.schema.json'));
  ajv.addSchema(loadSchema('jsf-0.82.schema.json'));
  validate = ajv.compile(loadSchema('bom-1.6.schema.json'));
});

describe('cbom reporter', () => {
  // Cover every finding source: artifacts (+ a safe PQC asset), deps, and AST.
  for (const name of ['artifacts-jwks', 'deps-basic', 'ast-jose']) {
    it(`emits schema-valid CycloneDX 1.6 for ${name}`, async () => {
      const result = await scan({ root: fixture(name) });
      const doc = JSON.parse(renderCbom(result)) as Record<string, unknown>;

      const ok = validate(doc);
      if (!ok) {
        throw new Error(
          `CBOM failed CycloneDX 1.6 schema:\n${JSON.stringify(validate.errors, null, 2)}`,
        );
      }
      expect(ok).toBe(true);
      expect(doc.bomFormat).toBe('CycloneDX');
      expect(doc.specVersion).toBe('1.6');
    });
  }

  it('collapses identical assets and records occurrences and quantum levels', async () => {
    const result = await scan({ root: fixture('artifacts-jwks') });
    const doc = JSON.parse(renderCbom(result)) as {
      components: Array<{
        type: string;
        name: string;
        cryptoProperties: {
          assetType: string;
          algorithmProperties: { primitive: string; nistQuantumSecurityLevel?: number };
        };
        evidence: { occurrences: Array<{ location: string }> };
        properties: Array<{ name: string; value: string }>;
      }>;
    };

    for (const c of doc.components) {
      expect(c.type).toBe('cryptographic-asset');
      expect(c.cryptoProperties.assetType).toBe('algorithm');
      expect(c.evidence.occurrences.length).toBeGreaterThan(0);
    }

    const byRule = (rid: string) =>
      doc.components.find((c) => c.properties.some((p) => p.name === 'shorproof:ruleId' && p.value === rid))!;

    // RSA JWKS: classical asymmetric -> NIST quantum level 0.
    expect(byRule('jwks/rsa').cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(0);
    // ML-DSA-65 (kty: AKP): post-quantum -> NIST category 3.
    expect(byRule('jwks/akp').cryptoProperties.algorithmProperties.nistQuantumSecurityLevel).toBe(3);
  });
});
