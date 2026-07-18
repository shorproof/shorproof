# shorproof — CLAUDE.md

## What this project is

`shorproof` is a post-quantum readiness scanner for JavaScript/TypeScript: it finds quantum-vulnerable cryptography (RSA, ECDSA/ECDH, classical DH — everything Shor's algorithm breaks) in a codebase and reports it with migration guidance toward NIST PQC standards (ML-KEM / FIPS 203, ML-DSA / FIPS 204).

**Positioning (do not drift from this):** auth/JWT/enterprise-first. Our depth is JWTs, JWKS, token infrastructure, key files, and fintech-style backend code. Existing scanners in this space skew blockchain/web3; we do not chase that niche. Trust through *correctness* is the brand: no fear-mongering, no false positives by design.

- Published: `shorproof@0.0.1` on npm (dependency-manifest scanner, zero deps). v0.0.1 behavior must keep working — it becomes the `deps` sub-scanner and merges into combined results.
- License: MIT. Author: Usama Amjid.
- Repo hygiene: this file is committed; `COMPETITORS.md` is local-only (gitignored); the npm tarball is controlled by the `files` whitelist in package.json and ships only `dist`, `README.md`, `LICENSE`.

## v0.1 goal

Ship an AST-based source scanner with a rules-as-data knowledge base, artifact scanning (JWKS/PEM), and four reporters (text, JSON, SARIF, CycloneDX 1.6 CBOM), with a fixture-based precision/recall test suite.

## Locked architecture decisions

- **Language:** TypeScript 5.8+, pure ESM (`"type": "module"`), compiled with `tsc` for publishing. **`erasableSyntaxOnly: true`** — no `enum`, no `namespace`, no parameter properties; use `as const` objects + derived union types instead. The same source runs natively on Node 22.18+/24 during development (`node src/cli.ts`) and compiles for distribution. Published output is always compiled JS + `.d.ts` (Node does not type-strip inside `node_modules`).
- **Runtime floor:** `engines: ">=20.12"`. Rationale: the codebases that most need a PQ audit are legacy systems on older Node — don't block the target market at the door. CI test matrix: Node 20, 22, 24. Runtime code uses only APIs available in 20.12; syntax modernity is free via tsc.
- **Dependencies — hard cap:** direct runtime dependencies are **exactly two: `@babel/parser` and `@babel/traverse`** (AST, `sourceType: 'unambiguous'`; parser plugins chosen **by file extension** — `.ts`/`.mts`/`.cts` → `['typescript']`, `.tsx` → `['typescript', 'jsx']`, JS/JSX → `['jsx']` — because the `jsx` plugin turns `<` into a JSX element and so breaks TypeScript angle-bracket casts (`<T>x`) in `.ts` files, silently dropping every finding in that file; legacy TS in older codebases is exactly our target). Everything else is native: CLI args via `node:util` `parseArgs`, terminal colors via `node:util` `styleText` (with a NO_COLOR/non-TTY fallback), file discovery via a small recursive `fs.readdir` walker (skip `node_modules`, `.git`, `dist`, configurable ignores). No tree-sitter, no WASM, no commander, no chalk, no glob. A near-zero-dependency supply-chain security tool is a headline feature — adding any runtime dependency requires explicit human approval.
- **Dev tooling:** vitest, eslint (flat config), tsc. No bundler for v0.1.
- **tsconfig baseline:** `module: "nodenext"`, `moduleResolution: "nodenext"`, `target: "es2023"`, `strict: true`, `verbatimModuleSyntax: true`, `erasableSyntaxOnly: true`, `isolatedModules: true`, `noUncheckedIndexedAccess: true`, `declaration: true`, `outDir: "dist"`.
- **Modern syntax conventions:** `node:`-prefixed builtin imports; `satisfies` on the rule registry (keeps literal types while enforcing shape); discriminated unions for findings with exhaustive `switch` + `never` checks; `readonly` types and frozen knowledge bases; `Error` with `cause` for wrapped errors; top-level await in the CLI entry; optional chaining/nullish coalescing over manual guards.
- **Rules are data, not code.** Each rule is a typed object: `id`, `title`, `severity`, `category` (signature | kem | key-exchange | hash | symmetric | artifact), `algorithm`, `confidence`, `why` (one honest sentence), `migration` (concrete hint, e.g. "ML-DSA via jose ≥ v6 or Node 24.7+"), `lifetimeSensitive` (boolean — see severity philosophy). Detection logic consumes rules; contributors add rules without touching the engine.
- **Layout:**
  ```
  src/
    cli.ts
    engine.ts            # orchestrates scanners, merges findings
    scanners/
      deps.ts            # port of v0.0.1 manifest scan
      ast.ts             # Babel-based source scanner
      artifacts.ts       # JWKS / PEM / cert files
    rules/
      index.ts           # rule registry (satisfies Rule[])
      *.ts               # rule groups (jwt.ts, node-crypto.ts, webcrypto.ts, libs.ts, ...)
    reporters/
      text.ts  json.ts  sarif.ts  cbom.ts
  test/
    fixtures/            # small fake projects (see Quality bar)
  ```

## The technical differentiator: binding-aware detection

This is the core engineering idea of the whole tool. Existing scanners in this space match calls by **literal object name** (their `jwt.sign` pattern only fires if the variable is literally named `jwt`) and flag **imports wholesale** (importing a JWT library = finding, even if the code only uses post-quantum algorithms). We do the opposite:

1. **Resolve import bindings.** Use Babel scope/binding info to know that `const j = require('jsonwebtoken')`, `import { sign } from 'jsonwebtoken'`, `import * as J from 'jose'` (any local name, destructured or namespaced, `require` or ESM, including dynamic `import()`) all refer to the library. Detection keys off the *binding*, never the variable name.
2. **Usage-confirmed findings.** A crypto-capable library import alone is at most an `info`-level inventory item. It becomes a real finding only when a quantum-vulnerable *usage* is confirmed (e.g. `sign(..., { algorithm: 'RS256' })`, `new SignJWT(...).setProtectedHeader({ alg: 'ES256' })`, `generateKeyPair('rsa')`). Track option objects passed as identifiers when they're const object literals in the same scope (best-effort constant propagation; if the value can't be resolved, emit a lower-confidence "review" finding, never a confident one).
3. **Positive detection.** ML-DSA / ML-KEM / hybrid usage is reported as `safe` ("already post-quantum ✓"). A scanner that can say "this part is done right" earns trust.
4. **AST-only on source code. No bare-string regex over code.** String-matching `RS256` anywhere fires on comments and test fixtures — a known noise pattern in this tool category. We never do that. (Regex is fine for *artifact* files like PEM headers.)

## Detection coverage for v0.1 (checklist)

Node `crypto`: `createSign` / `createVerify` (RSA/DSA/ECDSA digests), one-shot `crypto.sign` / `crypto.verify` with RSA/EC KeyObjects where resolvable, `generateKeyPair(Sync)` (`rsa`, `rsa-pss`, `dsa`, `ec`, `ed25519`, `ed448`, `x25519`, `x448`), `createECDH`, `createDiffieHellman(Group)`, `publicEncrypt` / `privateDecrypt`.
WebCrypto: `crypto.subtle.generateKey` / `importKey` / `sign` / `verify` / `deriveKey` with `RSASSA-PKCS1-v1_5`, `RSA-PSS`, `RSA-OAEP`, `ECDSA`, `ECDH`, `Ed25519`. (Competing tools have zero WebCrypto coverage — this is a headline gap we close.)
JWT layer (our specialty): `jsonwebtoken` `sign`/`verify` algorithm options (RS*/PS*/ES*/EdDSA vs HS* vs none), `jose` `SignJWT`/`jwtVerify`/`generateKeyPair` alg values incl. recognizing `ML-DSA-44/65/87` as safe (RFC 9964), `express-jwt`, `passport-jwt`, `@fastify/jwt`, `koa-jwt` configs where cheap.
Libraries (usage-confirmed where possible, inventory otherwise): `node-rsa`, `elliptic`, `tweetnacl`, `libsodium-wrappers`, `node-forge`, `jsrsasign`, `openpgp`, `ssh2`, `@noble/curves|ed25519|secp256k1`, `crypto-js` (honest: AES-256 fine, AES-128 note), `@noble/post-quantum` (safe).
Artifacts (`artifacts.ts`): JWKS files (`kty: RSA|EC` → finding; `kty: AKP` → safe, RFC 9964), PEM/CRT via built-in `crypto.X509Certificate` (algorithm + key size + expiry — a cert expiring after ~2030 with RSA/EC is elevated), `.pem` private key headers.

## Severity philosophy (this is a brand asset — encode it)

- `critical` — Shor-breakable asymmetric crypto protecting long-lived secrets or long-lived signatures (encryption of stored data, certs valid past 2030, JWKS keys).
- `high` — Shor-breakable usage with typical exposure (JWT signing with RS/ES algs, TLS-adjacent key material).
- `medium` — quantum-weakened but manageable (AES-128 via Grover — recommend AES-256) or classically weak already (MD5/SHA-1 — say so honestly: "broken today, not a quantum issue").
- `review` — crypto-capable library where usage couldn't be confirmed statically.
- `safe` — AES-256, SHA-256/SHA-3, password hashing (bcrypt/argon2), ML-KEM/ML-DSA/SLH-DSA, HS256 with proper key management.
- **Never flag SHA-256 as a risk** (a competing tool does — it is factually wrong). Never imply symmetric crypto is Shor-broken. Each finding's `why` must survive review by a cryptographer.
- Signatures vs harvest-now-decrypt-later nuance: short-lived signature usage is about the *signing key's* lifetime and compliance clocks; encryption of stored data is about *data* lifetime. Reflect via `lifetimeSensitive` and wording; don't inflate severity for drama.
- **Equal Shor-breakability, severity split by lifetime/HNDL exposure — applied consistently across scanners (deps *and* AST).** The RSA family stays `high`: its dominant use is encryption and long-lived keys/certs — a harvest-now-decrypt-later time bomb. The EC family (ECDSA/ECDH/EdDSA/X25519/X448) at *bare key generation* is `medium`: the dominant JS use is signatures and ephemeral ECDH, where the lifetime clock is soft. Hence `generateKeyPair('rsa')` = high but `generateKeyPair('ec'|'ed25519'|'x25519'|…)` = medium, matching `elliptic`/`tweetnacl`/`@noble` in the deps KB. Escalation is **context-driven, not primitive-driven**: a *confirmed* long-lived or auth usage (e.g. ES256 JWT signing — already `high` above) escalates; bare keygen ≠ confirmed usage.

## Reporters

- `text` (default): grouped by severity, file:line, snippet, `why`, `migration`. Calm tone. Colors via `util.styleText`, disabled on non-TTY/NO_COLOR.
- `json`: stable machine schema (document it in README; treat as public API).
- `sarif`: SARIF 2.1.0 so GitHub code scanning renders findings on PRs — this is the distribution hook; get rule metadata (helpUri, shortDescription) right.
- `cbom`: CycloneDX **1.6** with `crypto-asset` components and `cryptoProperties` (assetType, algorithmProperties primitive/variant/cryptoFunctions). Validate against the CycloneDX 1.6 schema in tests.
- Exit codes: `0` clean/info, `1` findings at/above `--fail-on` threshold (default: only with `--strict`), `2` usage/IO error. CI-friendly and documented.

## Quality bar (non-negotiable)

- **Fixture projects** under `test/fixtures/`, each a tiny fake app with a manifest of expected findings (`expected.json`). Engine output is diffed against expectations — this measures precision AND recall.
- **False-positive suite is as important as detection:** fixtures where the correct answer is *no finding* — `jose` used only with `ML-DSA-65`; the string `"RS256"` in a comment/test data; a variable coincidentally named `jwt` that isn't the library; `createHash('sha256')`; bcrypt usage.
- Alias-torture fixture: same vulnerable `jsonwebtoken` usage via default import, renamed import, destructuring, namespace import, `require`, and dynamic `import()` — all six must be caught.
- Every rule ships with at least one positive fixture. Negatives are organized by **failure-mode class** (comment/string, shadowing, non-tracked lib, safe-usage) rather than one sterile dir per rule, under two hard conditions: every rule *family* has ≥ 1 negative, and every newly discovered false-positive **or miss** class becomes a permanent fixture (documented expected-misses live in `test/fixtures/known-gaps/` and act as canaries — they flip to real findings when a later milestone closes the gap). A PR adding a rule without a positive fixture, or a discovered gap without a regression fixture, is incomplete.
- Vitest + eslint must pass on Node 20/22/24; keep `npx shorproof` cold start under ~1.5s on a medium repo — startup speed is a feature (and a consequence of the two-dependency rule).

## Non-goals for v0.1 (do not build these yet)

Live network/TLS endpoint scanning (skip rather than half-do), languages beyond JS/TS, auto-fix/codemods, numeric "readiness scores" (arbitrary weights destroy credibility), plugin loading of external rule packs (design the rule interface so it's *possible* later, don't build the loader now).

## Conventions

- Conventional commits; small focused PRs; semver (next release: 0.1.0).
- **Git division of labor:** Claude Code commits and pushes **feature branches** autonomously; **merge-to-main and `npm publish` are always human gates**. Review happens before merge anyway, so gating feature-branch pushes only costs velocity without reducing risk.
- Never publish without the author present: publishing requires npm 2FA (WebAuthn) — Claude Code must never attempt `npm publish`.
- README updates accompany user-visible changes. Keep the "Why shorproof / honest severities" story intact.
- When uncertain about crypto facts, stop and flag for human review instead of guessing — a wrong `why` string is worse than a missing rule.
