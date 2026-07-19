// Cold-start benchmark for the compiled CLI.
//
// Startup speed is a feature (and a consequence of the two-dependency rule):
// CLAUDE.md targets `npx shorproof` under ~1.5s on a medium repo. This spawns
// the built CLI as a fresh process each run — the real cold-start path a user
// hits — and reports the median wall-clock over several runs.
//
//   npm run build && npm run bench            # scan this repo
//   node scripts/bench.mjs <dir> <runs>       # custom target / run count
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

const target = process.argv[2] ?? ROOT;
const runs = Number(process.argv[3] ?? 7);
const BUDGET_MS = 1500;

if (!existsSync(CLI)) {
  console.error('dist/cli.js not found — run `npm run build` first.');
  process.exit(2);
}

/** One cold spawn of the CLI; returns elapsed milliseconds. */
function timeOnce() {
  const start = process.hrtime.bigint();
  const res = spawnSync(process.execPath, [CLI, target, '--json'], { stdio: 'ignore' });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  if (res.status === 2) throw new Error('CLI exited 2 (usage/IO error) during benchmark');
  return ms;
}

// One warm-up (filesystem cache, JIT) then the measured runs.
timeOnce();
const samples = Array.from({ length: runs }, timeOnce).sort((a, b) => a - b);
const median = samples[Math.floor(samples.length / 2)];
const min = samples[0];
const max = samples[samples.length - 1];

const fmt = (n) => `${n.toFixed(0)}ms`;
console.log(`shorproof cold start — target: ${target}`);
console.log(`  runs: ${runs}  min: ${fmt(min)}  median: ${fmt(median)}  max: ${fmt(max)}`);
console.log(`  budget: ${BUDGET_MS}ms — ${median <= BUDGET_MS ? 'PASS ✓' : 'OVER BUDGET ✗'}`);

process.exit(median <= BUDGET_MS ? 0 : 1);
