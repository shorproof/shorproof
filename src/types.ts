/**
 * Core shared types for shorproof.
 *
 * Everything here is data-shaped, not behavioural: rules are typed data objects
 * consumed by scanners; findings are a discriminated union that reporters walk
 * with exhaustive `switch` statements. Keep this file dependency-free.
 */

// --- Severity ------------------------------------------------------------

/**
 * Severity ladder, most severe first. Encodes the brand's severity philosophy:
 * - critical: Shor-breakable asymmetric crypto protecting long-lived secrets/signatures.
 * - high:     Shor-breakable usage with typical exposure (JWT signing, TLS-adjacent keys).
 * - medium:   quantum-weakened but manageable, or classically-weak-already.
 * - review:   crypto-capable surface where usage could not be confirmed statically.
 * - safe:     verified post-quantum / symmetric-at-strength / password hashing.
 * - info:     inventory only — a crypto-capable import with no confirmed vulnerable usage.
 */
export const SEVERITIES = ['critical', 'high', 'medium', 'review', 'safe', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Numeric rank for sorting and threshold comparison. Lower = more severe. */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  review: 3,
  safe: 4,
  info: 5,
});

// --- Category ------------------------------------------------------------

/**
 * The cryptographic function a rule concerns. Fixed set — contributors classify
 * every rule into one of these so reporters (esp. CBOM) can map cleanly.
 */
export const CATEGORIES = [
  'signature',
  'kem',
  'key-exchange',
  'hash',
  'symmetric',
  'artifact',
] as const;
export type Category = (typeof CATEGORIES)[number];

// --- Confidence ----------------------------------------------------------

/**
 * How sure we are the finding is real. Deliberately a coarse enum, not a number:
 * fake-precise numeric scores are a competitor anti-pattern we reject.
 */
export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

// --- Rules ---------------------------------------------------------------

/**
 * Shared metadata every rule carries. Scanner-specific rule types extend this
 * with their matching criteria (e.g. a package name, an API signature). The
 * engine and reporters only ever depend on this shared shape.
 */
export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly category: Category;
  /** The concrete algorithm/primitive, e.g. "RSA", "ECDSA", "ML-DSA-65". */
  readonly algorithm: string;
  readonly confidence: Confidence;
  /** One honest sentence a cryptographer would sign off on. */
  readonly why: string;
  /** Concrete migration hint, e.g. "ML-DSA via jose >= v6 or Node 24.7+". */
  readonly migration: string;
  /**
   * True when severity turns on a *lifetime* clock (data-at-rest that must stay
   * secret for years, or signatures/certs valid past the migration deadline)
   * rather than on immediate exposure. Drives wording, not drama.
   */
  readonly lifetimeSensitive: boolean;
}

/** A dependency-manifest rule: matches an exact npm package name. */
export interface DepRule extends Rule {
  /** The npm package name this rule fires on. */
  readonly package: string;
}

/**
 * An AST source rule. Fires when a call expression's callee resolves — through
 * the binding layer, regardless of local variable name — to one of `exports`
 * imported from one of `modules`.
 *
 * Most rules fire on the call unconditionally (the API itself is the finding).
 * A few APIs select their primitive via the first argument (Node's
 * `generateKeyPair('rsa', …)`); those are expressed as sibling rules that share
 * an export and differ by `firstArg`, plus one `firstArgFallback` rule that
 * fires only when the argument can't be resolved to a known value. This keeps
 * argument dispatch in the rule data, not the engine.
 */
export interface AstRule extends Rule {
  /** Module specifiers the export may come from, e.g. ['crypto', 'node:crypto']. */
  readonly modules: readonly string[];
  /** Exported function name(s) this rule matches, e.g. ['generateKeyPair', 'generateKeyPairSync']. */
  readonly exports: readonly string[];
  /** If set, fire only when the call's first argument is exactly this string literal. */
  readonly firstArg?: string;
  /**
   * Family fallback: fire only when the same export has `firstArg` siblings but
   * the call's first argument couldn't be resolved to any of them (e.g. a
   * computed key type). Lower confidence by nature — a review-level finding.
   */
  readonly firstArgFallback?: boolean;
}

/**
 * Outcome metadata for a specific JWA/COSE algorithm value (e.g. 'RS256',
 * 'ML-DSA-65'), shared across JWT libraries so one algorithm knowledge base
 * serves jsonwebtoken and jose alike. Post-quantum algs carry `severity: 'safe'`
 * — positive detection ("already post-quantum ✓"), not silence.
 */
export interface AlgOutcome {
  readonly severity: Severity;
  readonly category: Category;
  readonly algorithm: string;
  readonly confidence: Confidence;
  readonly lifetimeSensitive: boolean;
  readonly why: string;
  readonly migration: string;
}

/**
 * How a JWT library call carries its algorithm. The AST scanner reads the
 * argument at `algArgIndex` — either the algorithm directly (jose
 * `generateKeyPair('ES256')`) or, when `algOptionKey` is set, that key of an
 * options object (jsonwebtoken `sign(…, { algorithm })`); an array when
 * `algIsArray` (jsonwebtoken `verify(…, { algorithms: [] })`). Values are
 * resolved by best-effort constant propagation and looked up in the shared JWA
 * table. A confirmed call whose algorithm can't be resolved yields a `review`
 * finding, never a confident classical one.
 */
export interface JwtCallRule {
  readonly modules: readonly string[];
  readonly export: string;
  readonly algArgIndex: number;
  /** If set, the alg is `options[algArgIndex][algOptionKey]`; if omitted, the arg itself is the alg. */
  readonly algOptionKey?: string;
  readonly algIsArray: boolean;
  /** ruleId prefix (`<prefix>/<alg>`) and review-finding metadata. */
  readonly ruleIdPrefix: string;
  readonly reviewRuleId: string;
  readonly reviewTitle: string;
  readonly reviewWhy: string;
  readonly reviewMigration: string;
}

// --- Findings ------------------------------------------------------------

export interface Location {
  /** Absolute or repo-relative path of the file the finding lives in. */
  readonly file: string;
  readonly line?: number;
  readonly column?: number;
}

/** Fields shared by every finding, regardless of which scanner produced it. */
interface FindingBase {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly category: Category;
  readonly algorithm: string;
  readonly title: string;
  readonly why: string;
  readonly migration: string;
  readonly confidence: Confidence;
  readonly lifetimeSensitive: boolean;
  readonly location: Location;
}

/** A finding from the dependency-manifest scanner. */
export interface DepFinding extends FindingBase {
  readonly source: 'deps';
  readonly package: string;
  readonly range: string;
}

/** A finding from the AST source scanner (M2+). */
export interface AstFinding extends FindingBase {
  readonly source: 'ast';
  readonly snippet: string;
}

/** A finding from the artifact scanner — JWKS/PEM/certs (M4+). */
export interface ArtifactFinding extends FindingBase {
  readonly source: 'artifact';
  readonly detail?: string;
}

/** Discriminated union of all finding kinds. Switch on `source`. */
export type Finding = DepFinding | AstFinding | ArtifactFinding;

// --- Scanner plug-in contract -------------------------------------------

/** Everything a scanner needs to do its work. Grows as scanners are added. */
export interface ScanContext {
  /** Absolute path to the scan root. */
  readonly root: string;
}

/** A pluggable scanner. The engine runs each registered scanner and merges output. */
export interface Scanner {
  /** Stable identifier, e.g. "deps". Used in diagnostics and `--scanner` filtering. */
  readonly name: string;
  scan(ctx: ScanContext): Promise<Finding[]> | Finding[];
}

/** Aggregate counts by severity for summaries and exit-code decisions. */
export type SeverityCounts = Record<Severity, number>;

/** The merged result of a full scan. */
export interface ScanResult {
  readonly tool: 'shorproof';
  readonly version: string;
  readonly root: string;
  readonly findings: readonly Finding[];
  readonly counts: SeverityCounts;
  /** Names of the scanners that ran. */
  readonly scanners: readonly string[];
}
