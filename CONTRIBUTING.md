# Contributing to shorproof

Thanks for helping make more codebases quantum-ready. shorproof earns its keep through **correctness** — the most valuable contributions are new detections and honest severity/`why` wording that a cryptographer would sign off on.

## Ground rules (these are the brand)

- **No false positives by design.** A finding must be usage-confirmed, not just an import. If you can't confirm usage statically, it's `review`, not a confident finding.
- **Two runtime dependencies, hard cap.** Exactly `@babel/parser` and `@babel/traverse`. Everything else uses Node built-ins. **Adding any runtime dependency needs explicit maintainer approval** — a near-zero-dependency supply-chain tool is a headline feature.
- **Honest severities.** Severity turns on lifetime / harvest-now-decrypt-later exposure, not drama. Never flag SHA-256 as a risk; never imply symmetric crypto is Shor-broken. See the severity model in the [README](./README.md#severity-philosophy-the-honest-part).
- **When unsure about a crypto fact, stop and ask.** A wrong `why` string is worse than a missing rule — open an issue instead of guessing.

## Dev setup

Requires Node.js **>= 20.12** (source runs natively on Node 22.18+/24; it compiles for older Node).

```bash
npm install
npm run dev -- ./some/dir   # run the CLI from source (node src/cli.ts)
npm test                    # vitest
npm run typecheck           # tsc --noEmit
npm run lint                # eslint
npm run bench               # cold-start benchmark
```

`npm test`, `npm run typecheck`, and `npm run lint` must all pass on Node 20/22/24 before a PR merges (CI enforces this).

## Rules are data, not code

Detection logic consumes rules; you add a rule **without touching the engine**. A rule is a typed object — `id`, `title`, `severity`, `category`, `algorithm`, `confidence`, `why` (one honest sentence), `migration` (a concrete hint), `lifetimeSensitive`. Rule groups live in [`src/rules/`](./src/rules/) (e.g. `jsonwebtoken.ts`, `node-crypto.ts`, `webcrypto.ts`, `artifacts.ts`).

## Every rule ships with a fixture — no exceptions

The test suite measures **precision and recall** by diffing engine output against per-fixture `expected.json` under [`test/fixtures/`](./test/fixtures/). A PR that adds a rule **must** include:

1. **At least one positive fixture** — a tiny fake project where the rule should fire, with the expected finding in `expected.json`.
2. **A negative where it matters** — every rule *family* needs ≥ 1 fixture where the correct answer is *no finding* (safe usage, the algorithm name in a comment/string, a shadowed variable, a non-tracked lib).

Any newly discovered false positive **or miss** also becomes a permanent regression fixture. Documented expected-misses live in `test/fixtures/known-gaps/` and flip to real findings when a later change closes the gap.

## Good first issues

Adding a knowledge-base entry for a crypto package or a new algorithm alias is the ideal first contribution — it's self-contained, exercises the fixture workflow, and directly grows coverage. Look for issues labeled [`good first issue`](https://github.com/shorproof/shorproof/labels/good%20first%20issue), or open one proposing a package/algorithm you'd like covered.

## Pull requests

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`…), small and focused.
- Update the README when behavior visible to users changes.
- Update [`CHANGELOG.md`](./CHANGELOG.md) under an `## [Unreleased]` heading.

## License

By contributing, you agree your contributions are licensed under the [MIT License](./LICENSE).
