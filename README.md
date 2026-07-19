# shorproof

> Is your code **Shor-proof**? A post-quantum readiness scanner for JavaScript & TypeScript.

[![npm version](https://img.shields.io/npm/v/shorproof.svg)](https://www.npmjs.com/package/shorproof)
[![CI](https://github.com/shorproof/shorproof/actions/workflows/ci.yml/badge.svg)](https://github.com/shorproof/shorproof/actions/workflows/ci.yml)
[![node](https://img.shields.io/node/v/shorproof.svg)](https://www.npmjs.com/package/shorproof)
[![license](https://img.shields.io/npm/l/shorproof.svg)](./LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20deps-2-brightgreen.svg)](./package.json)

`shorproof` finds the **quantum-vulnerable cryptography** in your project — the RSA, ECDSA, ECDH and elliptic-curve usage that [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) breaks once large-scale quantum computers arrive — and points you to the NIST post-quantum replacements (ML-KEM / FIPS 203, ML-DSA / FIPS 204).

It scans **source code, dependencies, JWT/JWKS, and PEM/X.509 key material**, and reports findings as text, JSON, **SARIF** (GitHub code scanning) or a **CycloneDX 1.6 CBOM**.

**Why it's different:** auth/JWT-first, **binding-aware** (it tracks the real import, not a variable named `jwt`), **near-zero dependency** (exactly two), and built so every finding survives review by a cryptographer — **no fear-mongering, no false positives by design.** It even tells you what you've *already* done right: ML-KEM / ML-DSA usage is reported as `safe` ✓.

## Quick start

```bash
# No install needed
npx shorproof                      # scan the current project
npx shorproof ./api                # scan a specific directory

# Output formats
npx shorproof --json               # stable machine-readable JSON
npx shorproof --format sarif       # SARIF 2.1.0 for GitHub code scanning
npx shorproof --format cbom        # CycloneDX 1.6 Cryptographic BOM

# CI gating
npx shorproof --fail-on high       # exit 1 on any high+ finding
npx shorproof --strict             # shorthand for --fail-on high
```

Or add it as a dev dependency:

```bash
npm install --save-dev shorproof
```

Requires Node.js **≥ 20.12** (tested on 20, 22, 24).

## Example

```text
shorproof v0.1.0 — post-quantum readiness scanner
Scanned /srv/api

  CRITICAL (1)
    keys/tls.key  RSA-2048
      keys/tls.key:1
      RSA is broken by Shor's algorithm… This is stored private-key material.
      → Migrate to ML-DSA (FIPS 204) for signatures and ML-KEM (FIPS 203)…

  HIGH (2)
    sign(payload, key, { algorithm: 'RS256' })  RS256
      src/auth/token.ts:42
      RS256 signs with RSA, which Shor's algorithm breaks…
      → ML-DSA via jose ≥ v6 or Node 24.7+

  SAFE (1)
    new SignJWT(...).setProtectedHeader({ alg: 'ML-DSA-65' })  ML-DSA-65
      src/auth/pq.ts:8
      ML-DSA (FIPS 204) is a NIST post-quantum signature standard — already quantum-safe.

  1 critical · 2 high · 1 safe
```

## What it scans

| Scanner | Looks at | How |
| --- | --- | --- |
| **deps** | `package.json` dependencies | curated knowledge base of crypto packages |
| **ast** | JS/TS source | Babel AST, **binding-aware** — keys off the resolved import (any alias, `require`, namespace, dynamic `import()`), and confirms a vulnerable *usage* before reporting |
| **artifacts** | JWKS/JWK, PEM keys, X.509 certs | parsed with native `node:crypto`; certs valid past ~2030 are elevated |

The AST scanner covers Node `crypto` (sign/verify, `generateKeyPair`, ECDH, DH, `publicEncrypt`/`privateDecrypt`), **WebCrypto** `crypto.subtle.*`, and the JWT stack — `jsonwebtoken`, `jose` (incl. the `SignJWT` builder) and `express-jwt` — resolving algorithm options by constant propagation and recognizing **ML-DSA-44/65/87 as already post-quantum**. Importing a crypto library is never, by itself, a finding.

## GitHub Action (code scanning)

Upload SARIF so findings show up in your repo's **Security → Code scanning** tab and on PRs. A ready-to-copy workflow lives in [`examples/github-action.yml`](./examples/github-action.yml):

```yaml
name: shorproof
on: [push, pull_request]
permissions:
  security-events: write   # required to upload SARIF
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx shorproof@0.1 . --format sarif > shorproof.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shorproof.sarif
```

## Severity philosophy (the honest part)

Severity turns on **lifetime and harvest-now-decrypt-later (HNDL) exposure**, not on drama. Equal Shor-breakability can carry different severity:

- **critical** — Shor-breakable crypto protecting long-lived secrets/signatures: encryption of stored data, certs valid past 2030, JWKS keys, private-key files.
- **high** — Shor-breakable usage with typical exposure: JWT signing (RS/ES/EdDSA), TLS-adjacent key material.
- **medium** — quantum-*weakened* but manageable (AES-128 via Grover — use AES-256), or classically weak already (MD5/SHA-1 — said honestly: broken today, not a quantum issue). Bare EC key generation lands here.
- **review** — a crypto-capable surface whose usage couldn't be confirmed statically.
- **safe** — AES-256, SHA-256/SHA-3, bcrypt/argon2, and **ML-KEM/ML-DSA/SLH-DSA** — positively reported as "already post-quantum ✓".

SHA-256 is never flagged as a risk, and symmetric crypto is never implied to be Shor-broken. Every finding's `why` is one honest sentence a cryptographer would sign off on.

## Output formats

- **text** (default) — grouped by severity with file:line, the honest `why`, and a concrete migration hint. Colors auto-disable on non-TTY / `NO_COLOR`.
- **json** — stable, documented schema (below); treat it as a public API.
- **sarif** — SARIF 2.1.0 so GitHub code scanning renders findings on PRs. Severity maps to SARIF level and GitHub's `security-severity`; post-quantum/inventory findings are informational, not alerts.
- **cbom** — CycloneDX 1.6 Cryptographic Bill of Materials: a full inventory (vulnerable and post-quantum alike) with `algorithmProperties` and NIST quantum security levels. Validated against the CycloneDX 1.6 schema.

### JSON schema

```jsonc
{
  "tool": "shorproof",
  "version": "0.1.0",
  "root": "/abs/scan/root",
  "scanners": ["deps", "ast", "artifacts"],
  "summary": { "critical": 0, "high": 2, "medium": 1, "review": 0, "safe": 1, "info": 0 },
  "findings": [
    {
      "source": "ast",                // "deps" | "ast" | "artifact"
      "ruleId": "jsonwebtoken/rs256",
      "severity": "high",
      "category": "signature",        // signature|kem|key-exchange|hash|symmetric|artifact
      "algorithm": "RS256",
      "title": "…", "why": "…", "migration": "…",
      "confidence": "high",           // high|medium|low
      "lifetimeSensitive": true,
      "location": { "file": "src/auth.ts", "line": 12, "column": 3 }
      // source-specific: deps → package,range | ast → snippet | artifact → detail
    }
  ]
}
```

## Exit codes

- `0` — clean, or findings reported without a `--fail-on`/`--strict` threshold.
- `1` — a finding at or above the `--fail-on` severity (`--strict` = `--fail-on high`). `safe`/`info` never fail a run.
- `2` — usage or I/O error (bad directory, unknown `--format`/`--fail-on`).

## Why "shorproof"?

Peter Shor's 1994 algorithm is the reason post-quantum cryptography exists: on a large enough quantum computer it breaks RSA, Diffie-Hellman and elliptic-curve crypto — the math behind most of today's TLS, JWTs and signatures. NIST's replacement standards (FIPS 203/204/205) are final, migration deadlines are set (RSA/ECC deprecated ~2030, disallowed ~2035), and every migration starts with knowing where your vulnerable crypto lives.

That first step is what this tool is for. Make your code Shor-proof.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).

## License

[MIT](./LICENSE) © Usama Amjid
