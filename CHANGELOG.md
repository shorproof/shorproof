# Changelog

All notable changes to **shorproof** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-19

The first real scanner release. v0.0.1 was a dependency-manifest checker; 0.1.0
adds AST source scanning, artifact scanning, and four reporters — while keeping
the two-runtime-dependency footprint and the "no false positives by design"
promise.

### Added

- **AST source scanner** with **binding-aware detection** — keys off the
  resolved import binding, never the local variable name, and confirms a
  quantum-vulnerable *usage* before reporting. Recognizes all import styles
  (default, named, namespace, renamed, `require`, dynamic `import()`) and
  follows aliasing and method-extraction through the scope.
  - Node `crypto`: `createSign`/`createVerify`, `generateKeyPair(Sync)`
    (`rsa`, `rsa-pss`, `dsa`, `ec`, `ed25519`, `ed448`, `x25519`, `x448`),
    `createECDH`, `createDiffieHellman(Group)`, `publicEncrypt`/`privateDecrypt`,
    and one-shot `crypto.sign`/`verify` (as `review` — the same API signs ML-DSA
    on Node 24.7+).
  - **WebCrypto** `crypto.subtle.*` (`generateKey`/`importKey`/`sign`/`verify`/
    `deriveKey`/`deriveBits`/`encrypt`/`decrypt`) for RSA/ECDSA/ECDH/Ed25519,
    with operation-aware severity.
  - **JWT stack**: `jsonwebtoken`, `jose` (incl. `SignJWT` builder),
    `express-jwt` — algorithm options resolved by best-effort constant
    propagation, with **ML-DSA-44/65/87 recognized as post-quantum (safe)**.
- **Artifact scanner** for JWKS/JWK, PEM private/public keys, and X.509
  certificates, parsed with native `node:crypto`. `kty: AKP` (RFC 9964, ML-DSA)
  is positively detected as safe; certificates valid past ~2030 are elevated.
- **Reporters**: `text` (default), `json` (stable documented schema),
  **`sarif`** (SARIF 2.1.0 for GitHub code scanning), and **`cbom`**
  (CycloneDX 1.6 Cryptographic Bill of Materials, validated against the schema).
- **`--fail-on <critical|high|medium|review>`** exit-code threshold
  (`--strict` is shorthand for `--fail-on high`). Exit codes: `0` clean/reported,
  `1` threshold met, `2` usage/IO error.
- **Positive detection**: ML-KEM/ML-DSA/SLH-DSA usage is reported as `safe`
  ("already post-quantum ✓"), not silently ignored.
- **Resilient scanning**: a file that can't be parsed, or whose AST traversal
  throws (e.g. a duplicate declaration in a vendored/concatenated bundle), is
  recorded in `skipped` and surfaced (text footer + JSON `skipped` array) — never
  silently dropped, and never aborting the scan. One un-analyzable file can't hide
  its neighbours' findings. SARIF `tool.driver.semanticVersion` is populated.
- Fixture-based precision **and** recall test suite, including a dedicated
  false-positive suite (safe-usage, comment/string, shadowing, non-tracked libs).

### Changed

- The v0.0.1 dependency-manifest scan is now the `deps` sub-scanner and merges
  into combined results — existing behavior is preserved.
- Severity encodes the harvest-now-decrypt-later / lifetime philosophy
  consistently across scanners: the RSA family stays `high`+ (encryption-leaning,
  long-lived), while bare elliptic-curve key generation is `medium`; a confirmed
  long-lived or auth usage escalates.

### Security

- Untrusted PEM/JWKS/X.509 input is parsed only with OpenSSL-backed native
  `node:crypto`; every parse is guarded so malformed input is skipped, never
  crashed on and never turned into a false positive.

## [0.0.1] — 2025

### Added

- Initial release: dependency-manifest scanner. Reads `package.json` and reports
  quantum-vulnerable crypto packages against a curated knowledge base. Zero
  dependencies.

[0.1.0]: https://github.com/shorproof/shorproof/releases/tag/v0.1.0
[0.0.1]: https://github.com/shorproof/shorproof/releases/tag/v0.0.1
