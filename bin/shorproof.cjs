#!/usr/bin/env node
'use strict';

/*
 * shorproof — post-quantum readiness scanner (early preview)
 * v0.0.x scans dependency manifests for crypto-related packages that
 * commonly involve quantum-vulnerable (Shor-breakable) cryptography.
 * AST source scanning, CBOM and SARIF output land in v0.1.
 */

const fs = require('fs');
const path = require('path');

const VERSION = '0.0.1';

// --- tiny color helper (zero deps, respects NO_COLOR / non-TTY) ---
const useColor = process.stdout.isTTY && !('NO_COLOR' in process.env);
const paint = (code) => (s) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);
const red = paint('31');
const yellow = paint('33');
const green = paint('32');
const cyan = paint('36');
const dim = paint('2');
const bold = paint('1');

// --- knowledge base: package name -> assessment ---
// severity: high = classical asymmetric crypto (Shor-breakable) is the package's core job
//           medium = elliptic-curve based; quantum-vulnerable but often transitional
//           review = crypto-adjacent; safety depends on how you use it
//           safe   = not affected by Shor's algorithm (symmetric / hashing / PQC)
const KB = {
  'jsonwebtoken': {
    severity: 'high',
    reason: 'JWTs are typically signed with RS256/ES256 (RSA/ECDSA) — breakable by Shor\u2019s algorithm.',
    hint: 'Review your alg choices. ML-DSA (post-quantum) signing exists in `jose` and Node 24.7+.'
  },
  'node-rsa': {
    severity: 'high',
    reason: 'RSA key generation/encryption/signing — directly breakable by Shor\u2019s algorithm.',
    hint: 'Plan migration to ML-KEM (encryption) / ML-DSA (signatures) or hybrid schemes.'
  },
  'jsrsasign': {
    severity: 'high',
    reason: 'RSA/ECDSA signing and X.509 tooling — classical asymmetric crypto throughout.',
    hint: 'Inventory where certificates/signatures produced here have a long lifetime.'
  },
  'ursa': {
    severity: 'high',
    reason: 'RSA-only library (also long unmaintained).',
    hint: 'Migrate off — both for quantum readiness and basic maintenance risk.'
  },
  'elliptic': {
    severity: 'medium',
    reason: 'Elliptic-curve cryptography (ECDSA/ECDH) — quantum-vulnerable via Shor\u2019s algorithm.',
    hint: 'Check what depends on it and whether signatures/keys outlive the quantum timeline.'
  },
  'tweetnacl': {
    severity: 'medium',
    reason: 'Ed25519/X25519 (elliptic-curve) signatures and key exchange — quantum-vulnerable.',
    hint: 'Fine for short-lived operations today; plan hybrid (ECC + PQC) for anything long-lived.'
  },
  'libsodium-wrappers': {
    severity: 'medium',
    reason: 'Ed25519/X25519 based signing and key exchange — quantum-vulnerable primitives.',
    hint: 'Plan hybrid (ECC + ML-KEM/ML-DSA) for long-lived data or signatures.'
  },
  '@noble/curves': {
    severity: 'medium',
    reason: 'Elliptic-curve primitives — quantum-vulnerable via Shor\u2019s algorithm.',
    hint: 'Same author ships @noble/post-quantum with hybrid constructions — natural migration path.'
  },
  '@noble/ed25519': {
    severity: 'medium',
    reason: 'Ed25519 signatures (elliptic-curve) — quantum-vulnerable.',
    hint: 'Consider hybrid signing for long-lived artifacts.'
  },
  '@noble/secp256k1': {
    severity: 'medium',
    reason: 'secp256k1 (elliptic-curve) — quantum-vulnerable.',
    hint: 'Relevant mostly if keys/signatures must stay valid for many years.'
  },
  'openpgp': {
    severity: 'medium',
    reason: 'OpenPGP uses RSA/ECC key material — encrypted data is exposed to harvest-now-decrypt-later.',
    hint: 'Long-retention encrypted archives are the priority to re-protect.'
  },
  'ssh2': {
    severity: 'review',
    reason: 'SSH host/user keys are typically RSA or ECDSA/Ed25519 (classical asymmetric).',
    hint: 'Key rotation policy matters more than the library itself.'
  },
  'node-forge': {
    severity: 'review',
    reason: 'General-purpose TLS/RSA/X.509 toolkit — most common uses involve classical asymmetric crypto.',
    hint: 'Identify which forge features you actually use.'
  },
  'jose': {
    severity: 'review',
    reason: 'Supports both classical algs (RS256/ES256 \u2014 vulnerable) and post-quantum ML-DSA (RFC 9964).',
    hint: 'You\u2019re on the right library — check which `alg` values you actually use.'
  },
  'jwk-to-pem': {
    severity: 'review',
    reason: 'Converts JWKs \u2014 usually RSA/EC key material in classical formats.',
    hint: 'Signals classical asymmetric keys in your pipeline; trace where they\u2019re used.'
  },
  'crypto-js': {
    severity: 'review',
    reason: 'Mostly symmetric crypto (AES \u2014 quantum-resilient at 256-bit), but check key sizes and modes.',
    hint: 'AES-128 \u2192 prefer AES-256 for long-lived data (Grover\u2019s algorithm halves effective strength).'
  },
  'bcrypt': {
    severity: 'safe',
    reason: 'Password hashing — not affected by Shor\u2019s algorithm.',
    hint: ''
  },
  'bcryptjs': {
    severity: 'safe',
    reason: 'Password hashing — not affected by Shor\u2019s algorithm.',
    hint: ''
  },
  'argon2': {
    severity: 'safe',
    reason: 'Password hashing — not affected by Shor\u2019s algorithm.',
    hint: ''
  },
  '@noble/post-quantum': {
    severity: 'safe',
    reason: 'ML-KEM / ML-DSA / SLH-DSA — NIST post-quantum algorithms. Good.',
    hint: ''
  }
};

const ORDER = { high: 0, medium: 1, review: 2, safe: 3 };
const LABEL = {
  high: (s) => red(bold(s)),
  medium: (s) => yellow(bold(s)),
  review: (s) => cyan(bold(s)),
  safe: (s) => green(bold(s))
};

function printHelp() {
  console.log(`
${bold('shorproof')} v${VERSION} — post-quantum readiness scanner ${dim('(early preview)')}

Usage:
  npx shorproof [dir] [options]

Options:
  --json      machine-readable output
  --strict    exit with code 1 if any HIGH finding exists
  --version   print version
  --help      show this help

v0.0.x scans dependency manifests (package.json) only.
Coming in v0.1: AST scanning of crypto API usage, CycloneDX CBOM,
SARIF output + GitHub Action.
`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) return printHelp();
  if (args.includes('--version') || args.includes('-v')) return console.log(VERSION);

  const asJson = args.includes('--json');
  const strict = args.includes('--strict');
  const dirArg = args.find((a) => !a.startsWith('-')) || '.';
  const root = path.resolve(process.cwd(), dirArg);
  const pkgPath = path.join(root, 'package.json');

  if (!fs.existsSync(pkgPath)) {
    console.error(`shorproof: no package.json found at ${root}`);
    process.exit(2);
  }

  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  } catch (e) {
    console.error(`shorproof: could not parse ${pkgPath}: ${e.message}`);
    process.exit(2);
  }

  const deps = Object.assign(
    {},
    pkg.dependencies || {},
    pkg.devDependencies || {},
    pkg.optionalDependencies || {}
  );

  const findings = [];
  for (const [name, range] of Object.entries(deps)) {
    if (KB[name]) {
      findings.push({ package: name, range, severity: KB[name].severity, reason: KB[name].reason, hint: KB[name].hint });
    }
  }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.package.localeCompare(b.package));

  const counts = { high: 0, medium: 0, review: 0, safe: 0 };
  for (const f of findings) counts[f.severity]++;

  if (asJson) {
    console.log(JSON.stringify({
      tool: 'shorproof',
      version: VERSION,
      scannedManifest: pkgPath,
      dependenciesChecked: Object.keys(deps).length,
      findings,
      summary: counts
    }, null, 2));
  } else {
    console.log(`\n${bold('shorproof')} v${VERSION} — post-quantum readiness scanner ${dim('(early preview)')}\n`);
    console.log(dim(`Scanning ${pkgPath}`));
    console.log(dim(`${Object.keys(deps).length} dependencies checked\n`));

    if (findings.length === 0) {
      console.log(green('No known crypto-related dependencies found.'));
      console.log(dim('Note: built-in `crypto` / WebCrypto usage is not visible from manifests —'));
      console.log(dim('source-level (AST) scanning lands in v0.1.\n'));
    } else {
      for (const f of findings) {
        console.log(`  ${LABEL[f.severity](f.severity.toUpperCase().padEnd(7))} ${bold(f.package)} ${dim(f.range)}`);
        console.log(`          ${f.reason}`);
        if (f.hint) console.log(`          ${dim('\u2192 ' + f.hint)}`);
        console.log('');
      }
      const parts = [];
      if (counts.high) parts.push(red(`${counts.high} high`));
      if (counts.medium) parts.push(yellow(`${counts.medium} medium`));
      if (counts.review) parts.push(cyan(`${counts.review} review`));
      if (counts.safe) parts.push(green(`${counts.safe} safe`));
      console.log(`  ${parts.join(dim(' \u00b7 '))}\n`);
      console.log(dim('  v0.0.x scans dependency manifests only. AST source scanning,'));
      console.log(dim('  CycloneDX CBOM and SARIF output land in v0.1.\n'));
    }
  }

  if (strict && counts.high > 0) process.exit(1);
}

main();
