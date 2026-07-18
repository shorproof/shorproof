import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Directory names never worth descending into. Matches CLAUDE.md: the walker
 * skips node_modules, .git, and dist by default; callers may add more.
 */
export const DEFAULT_IGNORE_DIRS = ['node_modules', '.git', 'dist'] as const;

export interface WalkOptions {
  /** File extensions to return, dot-prefixed and lowercase, e.g. ['.js', '.ts']. */
  readonly extensions: readonly string[];
  /** Extra directory names to skip, on top of DEFAULT_IGNORE_DIRS. */
  readonly ignoreDirs?: readonly string[];
}

/**
 * Recursively collect files under `root` whose extension is in `extensions`.
 * Synchronous and dependency-free (just node:fs) — the two-dependency cap means
 * no glob library. Symlinked directories are not followed, so the walk can't
 * cycle. Unreadable directories are skipped rather than throwing: a scan should
 * degrade, not abort, on one bad permission.
 */
export function walkFiles(root: string, options: WalkOptions): string[] {
  const ignore = new Set<string>([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const extensions = new Set(options.extensions);
  const files: string[] = [];
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop();
    if (dir === undefined) break;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory — skip, don't abort the scan
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!ignore.has(entry.name)) stack.push(join(dir, entry.name));
      } else if (entry.isFile() && extensions.has(extname(entry.name))) {
        files.push(join(dir, entry.name));
      }
    }
  }

  return files;
}

/** Lowercased extension including the dot, or '' if none. Avoids node:path just for this. */
function extname(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot).toLowerCase() : '';
}
