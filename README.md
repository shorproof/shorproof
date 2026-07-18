# shorproof

> Is your code **Shor-proof**? Post-quantum readiness scanner for JavaScript/TypeScript.

`shorproof` finds quantum-vulnerable cryptography in your project — the RSA, ECDSA and elliptic-curve usage that [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) will break once large-scale quantum computers arrive — and points you toward the NIST post-quantum replacements (ML-KEM / FIPS 203, ML-DSA / FIPS 204).

Auth/JWT-first, near-zero-dependency, and built so every finding survives review by a cryptographer: **no fear-mongering, no false positives by design.**

**Status: v0.1 in active development.** The published `shorproof@0.0.1` is the dependency-manifest scanner; the source (AST), artifact and reporter features below are on the 0.1 line.

## Usage

```bash
npx shorproof                      # scan the current project
npx shorproof ./api                # scan a specific directory
npx shorproof --json               # machine-readable output
npx shorproof --format sarif       # SARIF 2.1.0 for GitHub code scanning
npx shorproof --format cbom        # CycloneDX 1.6 CBOM
npx shorproof --fail-on high       # exit 1 on any high+ finding (CI gate)
npx shorproof --strict             # shorthand for --fail-on high
```

## What it scans

| Scanner | Looks at | How |
| --- | --- | --- |
| **deps** | `package.json` dependencies | curated knowledge base of crypto packages |
| **ast** | JS/TS source | Babel AST with **binding-aware** detection — keys off the resolved import, never the variable name, and confirms a vulnerable *usage* before reporting |
| **artifacts** | JWKS/JWK, PEM keys, X.509 certs | parsed with native `node:crypto`; certs valid past ~2030 are elevated |

The AST scanner covers Node `crypto` (sign/verify, `generateKeyPair`, ECDH, DH, `publicEncrypt`/`privateDecrypt`), WebCrypto `crypto.subtle.*`, and the JWT stack (`jsonwebtoken`, `jose`, `express-jwt`) — resolving algorithm options by constant propagation and recognizing **ML-DSA as already post-quantum**. Importing a library is never itself a finding.

## Severity philosophy (the honest part)

Severity turns on **lifetime and harvest-now-decrypt-later (HNDL) exposure**, not on drama. Equal Shor-breakability can carry different severity:

- **critical** — Shor-breakable crypto protecting long-lived secrets/signatures: encryption of stored data, certs valid past 2030, JWKS keys, private-key files.
- **high** — Shor-breakable usage with typical exposure: JWT signing (RS/ES/EdDSA), TLS-adjacent key material.
- **medium** — quantum-*weakened* but manageable (AES-128 via Grover — use AES-256), or classically weak already (MD5/SHA-1 — said honestly: broken today, not a quantum issue). Bare EC key generation lands here.
- **review** — a crypto-capable surface whose usage couldn't be confirmed statically.
- **safe** — AES-256, SHA-256/SHA-3, bcrypt/argon2, and **ML-KEM/ML-DSA/SLH-DSA** — positively reported as "already post-quantum ✓".

SHA-256 is never flagged as a risk, and symmetric crypto is never implied to be Shor-broken.

## Output formats

- **text** (default) — grouped by severity with file:line, the honest `why`, and a concrete migration hint. Colors auto-disable on non-TTY / `NO_COLOR`.
- **json** — stable, documented schema (below); treat as a public API.
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

## License

MIT
