import { readdirSync } from "node:fs";
import { join } from "node:path";

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".idea",
  ".vscode",
  "coverage",
  "__pycache__",
  ".next",
  "target",
  ".cache",
  ".gradle",
  "bower_components",
]);

/** Depth-first file walk in deterministic order; symlinked dirs are not followed. */
export function* walk(root: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of entries) {
    const full = join(root, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(full);
    } else if (e.isFile()) {
      yield full;
    }
  }
}
