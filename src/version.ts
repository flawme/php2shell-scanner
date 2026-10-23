import { PHP2SHELL, type Status, type Ver } from "./types.js";

/**
 * Interval over the (major, minor, patch) lattice.
 * `low` is inclusive, `high` is inclusive only when `highIncl` is true.
 * A null bound is unbounded on that side.
 */
export interface Interval {
  readonly low: Ver | null;
  readonly high: Ver | null;
  readonly highIncl: boolean;
}

/** A parsed composer-style constraint: a union of intervals plus parse completeness. */
export interface ParsedConstraint {
  readonly intervals: readonly Interval[];
  /** false when some `||` branch could not be parsed; SAFE verdicts then stay conservative. */
  readonly allParsed: boolean;
}

export interface Verdict {
  readonly status: Status;
  readonly detail: string;
}

const v = (major: number, minor: number, patch: number): Ver => [major, minor, patch];

export function cmp(a: Ver, b: Ver): number {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

type Operand =
  | { readonly any: true }
  | { readonly major: number; readonly minor?: number; readonly patch?: number };

/**
 * "8.3.12" → exact; "8.3" and "8.3.*" both float the patch inside the minor;
 * "8" and "8.*" float the minor; "*" matches anything. Collapsing "8.3.*" onto
 * "8.3" is safe: both denote [8.3.0, 8.4.0).
 */
function parseOperand(tok: string): Operand | null {
  const t = tok.trim();
  if (t === "*" || t === "x" || t === "X" || t === "*.*" || t === "*.*.*") return { any: true };
  let m = /^(\d+)\.(\d+)\.(\d+)$/.exec(t);
  if (m) return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
  m = /^(\d+)\.(\d+)\.\*$/.exec(t);
  if (m) return { major: Number(m[1]), minor: Number(m[2]) };
  m = /^(\d+)\.(\d+)$/.exec(t);
  if (m) return { major: Number(m[1]), minor: Number(m[2]) };
  m = /^(\d+)\.\*$/.exec(t);
  if (m) return { major: Number(m[1]) };
  m = /^(\d+)$/.exec(t);
  if (m) return { major: Number(m[1]) };
  return null;
}

/** Lowest version an operand can denote. */
function lowBound(o: Operand): Ver {
  if ("any" in o) return v(0, 0, 0);
  if (o.patch !== undefined) return v(o.major, o.minor ?? 0, o.patch);
  if (o.minor !== undefined) return v(o.major, o.minor, 0);
  return v(o.major, 0, 0);
}

/** Exclusive upper bound: the version just past the operand's own granularity. */
function bumpGran(o: Operand): Ver {
  if ("any" in o) return v(0, 0, 0); // callers treat `any` as unbounded before reaching this
  if (o.patch !== undefined) return v(o.major, o.minor ?? 0, o.patch + 1);
  if (o.minor !== undefined) return v(o.major, o.minor + 1, 0);
  return v(o.major + 1, 0, 0);
}

function condInterval(op: string, o: Operand): Interval {
  if ("any" in o) return { low: null, high: null, highIncl: false };
  const lo = lowBound(o);
  switch (op) {
    case ">=":
      return { low: lo, high: null, highIncl: false };
    case ">":
      return { low: bumpGran(o), high: null, highIncl: false };
    case "<":
      return { low: null, high: lo, highIncl: false };
    case "<=":
      // <=8.4 means everything below 8.5.0; <=8.4.27 stops right at 8.4.27.
      return { low: null, high: bumpGran(o), highIncl: false };
    case "^":
      // composer caret: anything below the next major — this is why ^8.4.27 is
      // still exposed: it admits 8.5.0 through 8.5.11.
      return { low: lo, high: v(o.major + 1, 0, 0), highIncl: false };
    case "~":
      // composer tilde: next bump at the operand's own precision
      return {
        low: lo,
        high: o.minor !== undefined ? v(o.major, o.minor + 1, 0) : v(o.major + 1, 0, 0),
        highIncl: false,
      };
    default:
      // bare version or `=`: the range [x, x+1) at the operand's precision
      return { low: lo, high: bumpGran(o), highIncl: false };
  }
}

function overlaps(a: Interval, b: Interval): boolean {
  if (a.low && b.high && (cmp(a.low, b.high) > 0 || (cmp(a.low, b.high) === 0 && !b.highIncl))) {
    return false;
  }
  if (b.low && a.high && (cmp(b.low, a.high) > 0 || (cmp(b.low, a.high) === 0 && !a.highIncl))) {
    return false;
  }
  return true;
}

function intersect(a: Interval, b: Interval): Interval | null {
  const low = a.low === null ? b.low : b.low === null ? a.low : cmp(a.low, b.low) >= 0 ? a.low : b.low;
  let high: Ver | null = null;
  let highIncl = false;
  if (a.high === null) {
    high = b.high;
    highIncl = b.highIncl;
  } else if (b.high === null) {
    high = a.high;
    highIncl = a.highIncl;
  } else {
    const c = cmp(a.high, b.high);
    if (c < 0) {
      high = a.high;
      highIncl = a.highIncl;
    } else if (c > 0) {
      high = b.high;
      highIncl = b.highIncl;
    } else {
      high = a.high;
      highIncl = a.highIncl && b.highIncl;
    }
  }
  if (low !== null && high !== null && (cmp(low, high) > 0 || (cmp(low, high) === 0 && !highIncl))) {
    return null;
  }
  return { low, high, highIncl };
}

interface BranchResult {
  readonly iv: Interval | null;
  readonly parsed: boolean;
}

/**
 * Parse one `||`-free branch: conditions separated by spaces/commas mean AND,
 * `a - b` is a hyphen range, `!=` exclusions are ignored (dropping single
 * versions never makes a range safe, so ignoring them is conservative).
 */
function parseBranch(branch: string): BranchResult {
  // glue operators to their operand when split by a space (">= 8.2" → ">=8.2")
  const norm = branch.replace(/(>=|<=|!=|==|=|>|<|\^|~)\s+/g, "$1");
  const words = norm.split(/[\s,]+/).filter(Boolean);
  let acc: Interval = { low: null, high: null, highIncl: false };
  let parsed = false;

  for (let i = 0; i < words.length; i++) {
    const w = words[i]!;
    if (w === "-") continue; // consumed together with its left operand below
    if (words[i + 1] === "-" && words[i + 2] !== undefined) {
      const a = parseOperand(w);
      const b = parseOperand(words[i + 2]!);
      if (!a || !b || "any" in a || "any" in b) return { iv: null, parsed: false };
      // left side inclusive from its low bound; right side inclusive at its own precision
      const high = b.patch !== undefined ? v(b.major, b.minor ?? 0, b.patch) : bumpGran(b);
      const next = intersect(acc, {
        low: lowBound(a),
        high,
        highIncl: b.patch !== undefined,
      });
      if (!next) return { iv: null, parsed: true }; // parsed but empty branch
      acc = next;
      parsed = true;
      i += 2;
      continue;
    }
    const m = /^(>=|<=|!=|==|=|>|<|\^|~)?(.*)$/.exec(w)!;
    const op = m[1] ?? "";
    const operand = parseOperand(m[2] ?? "");
    if (!operand) return { iv: null, parsed: false };
    parsed = true;
    if (op === "!=") continue; // ignored: removing a point never un-exposes a range
    const next = intersect(acc, condInterval(op, operand));
    if (!next) return { iv: null, parsed: true }; // parsed but empty branch
    acc = next;
  }
  return { iv: acc, parsed };
}

export function parseConstraint(input: string): ParsedConstraint | null {
  const s = input.trim();
  if (!s) return null;
  const branches = s
    .split("||")
    .map((b) => b.trim())
    .filter(Boolean);
  const intervals: Interval[] = [];
  let allParsed = true;
  let anyParsed = false;
  for (const br of branches) {
    const r = parseBranch(br);
    if (!r.parsed) {
      allParsed = false;
      continue;
    }
    anyParsed = true;
    if (r.iv) intervals.push(r.iv);
  }
  if (!anyParsed) return null;
  return { intervals, allParsed };
}

const FIX_NOTE = PHP2SHELL.fixed.map((f) => f.join(".")).join(" / ");

/**
 * Verdict for a composer-style constraint. Precedence is deliberate:
 * a definite window hit outranks parse gaps; only a proven-clean parse is SAFE.
 */
export function evaluate(pc: ParsedConstraint): Verdict {
  const hits: string[] = [];
  for (const f of PHP2SHELL.fixed) {
    const window: Interval = { low: v(f[0], f[1], 0), high: f, highIncl: false };
    if (pc.intervals.some((iv) => overlaps(iv, window))) {
      hits.push(`${f[0]}.${f[1]}.x below ${f.join(".")}`);
    }
  }
  if (hits.length > 0) {
    return { status: "VULNERABLE", detail: `can resolve to unpatched PHP: ${hits.join("; ")}` };
  }
  const eol: Interval = { low: null, high: PHP2SHELL.supportedFloor, highIncl: false };
  if (pc.intervals.some((iv) => overlaps(iv, eol))) {
    return {
      status: "UNSUPPORTED",
      detail: `includes PHP below ${PHP2SHELL.supportedFloor.join(".")} — EOL branch, no PHP2Shell patch exists; upgrade required`,
    };
  }
  if (!pc.allParsed) {
    return {
      status: "UNKNOWN",
      detail: "part of the constraint could not be parsed — cannot prove it avoids unpatched ranges",
    };
  }
  return { status: "SAFE", detail: `every version matching this constraint is patched (fixes: ${FIX_NOTE})` };
}

export interface TagVersion {
  readonly major?: number;
  readonly minor?: number;
  readonly patch?: number;
}

const FLOAT_KEYWORDS = /^(latest|stable|fpm|cli|apache|zts|alpine|nightly)/i;

/** Extract a PHP version from a Docker tag / setup-php input like "8.3.12-fpm-alpine". */
export function parseTagVersion(tag: string): TagVersion | null {
  const t = tag.trim();
  if (FLOAT_KEYWORDS.test(t)) return {}; // floating tag: whatever the newest build is
  if (!/^\d/.test(t)) return null;
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(t);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: m[2] !== undefined ? Number(m[2]) : undefined,
    patch: m[3] !== undefined ? Number(m[3]) : undefined,
  };
}

function latestPatch(major: number, minor: number): Ver | null {
  return PHP2SHELL.fixed.find((x) => x[0] === major && x[1] === minor) ?? null;
}

/**
 * Verdict for a Docker/CI/version-file token. Unpinned tokens are FLOATING, not
 * VULNERABLE: they resolve to the newest patch today (all patched branches got
 * their fix as the latest release), but a rebuild can silently drift.
 */
export function classifyTag(token: string): Verdict {
  if (token.includes("${")) {
    return {
      status: "UNKNOWN",
      detail: "version comes from a CI matrix variable — not statically resolvable; resolve and pin it",
    };
  }
  const tv = parseTagVersion(token);
  if (tv === null) {
    return { status: "UNKNOWN", detail: `could not parse version token "${token}"` };
  }
  if (tv.major === undefined) {
    return {
      status: "FLOATING",
      detail: "no explicit version — resolves to the newest PHP release, 8.5.12 today (patched 2026-10-21); pin an exact version",
    };
  }
  const minor = tv.minor ?? 0;
  if (tv.patch !== undefined) {
    const f = latestPatch(tv.major, minor);
    const ver = v(tv.major, minor, tv.patch);
    if (!f) {
      if (tv.major < 8 || (tv.major === 8 && minor < 2)) {
        return {
          status: "UNSUPPORTED",
          detail: `PHP ${ver.join(".")} is on an EOL branch — no PHP2Shell patch exists; upgrade required`,
        };
      }
      return { status: "FLOATING", detail: `PHP ${ver.join(".")} is on a branch with no PHP2Shell advisory — verify directly` };
    }
    return cmp(ver, f) < 0
      ? {
          status: "VULNERABLE",
          detail: `${ver.join(".")} is unpatched — first fix in the ${tv.major}.${minor} branch is ${f.join(".")}`,
        }
      : { status: "SAFE", detail: `${ver.join(".")} >= ${f.join(".")} — patched` };
  }
  if (tv.minor !== undefined && (tv.major < 8 || tv.minor < 2)) {
    return {
      status: "UNSUPPORTED",
      detail: `PHP ${tv.major}.${tv.minor} is on an EOL branch — no PHP2Shell patch exists; upgrade required`,
    };
  }
  if (tv.minor === undefined) {
    return {
      status: "FLOATING",
      detail: "major-only tag — resolves to the newest 8.x release, 8.5.12 today; pin the exact version",
    };
  }
  const f = latestPatch(tv.major, minor);
  if (!f) {
    return {
      status: "FLOATING",
      detail: `PHP ${tv.major}.${minor} is a branch with no PHP2Shell advisory (future or unusual) — verify directly`,
    };
  }
  return {
    status: "FLOATING",
    detail: `unpinned — currently resolves to ${f.join(".")} (patched 2026-10-21); pin the exact version so a rebuild cannot drift`,
  };
}
