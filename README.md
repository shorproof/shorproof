# shorproof

> Is your code **Shor-proof**? Post-quantum readiness scanner for JavaScript/TypeScript.

`shorproof` finds quantum-vulnerable cryptography in your project — the RSA, ECDSA and elliptic-curve usage that [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) will break once large-scale quantum computers arrive — and points you toward the NIST post-quantum replacements (ML-KEM, ML-DSA).

**Status: early preview (v0.0.x).** The name is live and the tool does one honest thing today; the real scanner is in active development. Watch this space.

## Usage

```bash
npx shorproof            # scan the current project
npx shorproof ./api      # scan a specific directory
npx shorproof --json     # machine-readable output
npx shorproof --strict   # exit 1 if any HIGH finding (CI-friendly)
```

## What it does today (v0.0.x)

Scans your `package.json` dependencies against a curated knowledge base of crypto-related packages and reports:

- **HIGH** — classical asymmetric crypto (RSA/ECDSA) is the package's core job
- **MEDIUM** — elliptic-curve based; quantum-vulnerable, review lifetimes
- **REVIEW** — crypto-adjacent; safety depends on how you use it
- **SAFE** — unaffected by Shor's algorithm (password hashing, PQC libraries)

## Roadmap (v0.1)

- **AST source scanning** — detect `crypto.createSign('RSA-...')`, `jwt.sign(..., RS256)`, WebCrypto ECDSA/RSA-OAEP and friends, with import tracking to avoid false positives
- **CycloneDX CBOM output** — the cryptographic bill of materials that PCI DSS 4.0-era audits ask for
- **SARIF output + GitHub Action** — findings directly in your PR's Security tab
- **JWT/JWKS deep checks** — algorithm inventory for your token infrastructure

## Why "shorproof"?

Peter Shor's 1994 algorithm is the reason post-quantum cryptography exists: on a large enough quantum computer it breaks RSA, Diffie-Hellman and elliptic-curve crypto — the math behind most of today's TLS, JWTs and signatures. NIST's replacement standards (FIPS 203/204/205) are final, migration deadlines are set (RSA/ECC deprecated ~2030, disallowed ~2035), and every migration starts with knowing where your vulnerable crypto lives.

That first step is what this tool is for. Make your code Shor-proof.

## License

MIT
