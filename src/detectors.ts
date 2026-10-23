import type { AmplifierFinding, Finding, Source, Status, VersionFinding } from "./types.js";
import { classifyTag, evaluate, parseConstraint } from "./version.js";

/** Above this size, source files (php/ini) are skipped — minified blobs are noise. */
const MAX_SCAN_BYTES = 2 * 1024 * 1024;

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) line++;
  }
  return line;
}

function vf(
  source: Source,
  file: string,
  line: number,
  constraint: string,
  status: Status,
  detail: string,
): VersionFinding {
  return { kind: "version", file, line, source, constraint, status, detail };
}

function constraintFinding(
  source: Source,
  file: string,
  line: number,
  constraint: string,
  note: string,
): VersionFinding {
  const pc = parseConstraint(constraint);
  if (!pc) {
    return vf(source, file, line, constraint, "UNKNOWN", `${note} - could not parse the version constraint`);
  }
  const { status, detail } = evaluate(pc);
  return vf(source, file, line, constraint, status, `${note} - ${detail}`);
}

function tagFinding(
  source: Source,
  file: string,
  line: number,
  token: string,
  note: string,
): VersionFinding {
  const { status, detail } = classifyTag(token);
  return vf(source, file, line, token, status, `${note} - ${detail}`);
}

/** Which composer.json key a matched "php" entry sits under. */
function composerContext(before: string): string {
  let best = "php";
  let bestIdx = -1;
  for (const key of ["require-dev", "require", "platform"]) {
    const idx = before.lastIndexOf(`"${key}"`);
    if (idx > bestIdx) {
      bestIdx = idx;
      best = key;
    }
  }
  return best;
}

function composerJson(file: string, text: string): Finding[] {
  try {
    JSON.parse(text);
  } catch {
    return [
      vf(
        "composer.json",
        file,
        1,
        "(unparseable)",
        "UNKNOWN",
        "composer.json is not valid JSON - cannot read its php constraint",
      ),
    ];
  }
  const out: Finding[] = [];
  const notes: Record<string, string> = {
    require: "require.php (runtime)",
    "require-dev": "require-dev.php (dev-only)",
    platform: "config.platform.php (build platform lock)",
    php: "php key",
  };
  const re = /"php"\s*:\s*"([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const ctx = composerContext(text.slice(0, m.index));
    out.push(constraintFinding("composer.json", file, lineOf(text, m.index), m[1] ?? "", notes[ctx] ?? notes.php));
  }
  return out;
}

function composerLock(file: string, text: string): Finding[] {
  const out: Finding[] = [];
  const re = /"platform"\s*:\s*\{[^{}]*"php"\s*:\s*"([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push(
      constraintFinding(
        "composer.lock",
        file,
        lineOf(text, m.index),
        m[1] ?? "",
        "composer.lock platform override - the authoritative pin for deploys",
      ),
    );
  }
  return out;
}

function dockerfile(file: string, text: string): Finding[] {
  const out: Finding[] = [];
  const args = new Map<string, string>();
  const argRe = /(?:^|\n)\s*(?:ARG|ENV)\s+PHP_VERSION\s*=?\s*"?([\w.]*)"?/g;
  let m: RegExpExecArray | null;
  while ((m = argRe.exec(text)) !== null) {
    const val = m[1] ?? "";
    if (/\d/.test(val)) {
      args.set("PHP_VERSION", val);
      out.push(tagFinding("dockerfile", file, lineOf(text, m.index + 1), val, "ARG/ENV PHP_VERSION"));
    }
  }
  // 0-2 registry/path segments before the image name: matches `php:`,
  // `docker.io/library/php:`, and `ghcr.io/org/php:`; `dunglas/frankenphp:` is
  // left to its own detector below.
  const fromRe = /^FROM\s+(?:--[\w-]+=\S+\s+)?(?:(?:[\w.-]+(?::\d+)?\/){0,2})php:([^\s]+)/gm;
  while ((m = fromRe.exec(text)) !== null) {
    let tag = m[1] ?? "";
    if (/\$\{?PHP_VERSION\}?/.test(tag)) {
      const val = args.get("PHP_VERSION");
      if (val) {
        tag = tag.replace(/\$\{?PHP_VERSION\}?/g, val);
      } else {
        out.push(
          vf(
            "dockerfile",
            file,
            lineOf(text, m.index),
            tag,
            "UNKNOWN",
            "FROM php:<PHP_VERSION> - the version comes from a build variable that is not set in this file",
          ),
        );
        continue;
      }
    }
    out.push(tagFinding("dockerfile", file, lineOf(text, m.index), tag, "base image"));
  }
  // FrankenPHP images carry the embedded PHP runtime in the tag, e.g. `1.13.2-php8-trixie`.
  const frankenRe = /^FROM\s+(?:--[\w-]+=\S+\s+)?(?:[\w.-]+(?::\d+)?\/)?dunglas\/frankenphp:(\S+)/gm;
  while ((m = frankenRe.exec(text)) !== null) {
    const v = /php-?(\d+(?:\.\d+)*)/i.exec(m[1] ?? "");
    if (v) {
      out.push(
        tagFinding("dockerfile", file, lineOf(text, m.index), v[1] ?? "", "frankenphp runtime image (embedded PHP)"),
      );
    }
  }
  // Distro packages pin only the branch: alpine `php84`/`php85`, debian `php8.4-fpm`.
  // One finding per branch; FROM lines report via their tag instead.
  const pkg = new Map<string, number>();
  const pkgRe = /\bphp(\d)\.?(\d)\b/g;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*FROM\b/.test(lines[i] ?? "")) continue;
    let pm: RegExpExecArray | null;
    pkgRe.lastIndex = 0;
    while ((pm = pkgRe.exec(lines[i] ?? "")) !== null) {
      const ver = `${pm[1]}.${pm[2]}`;
      if (!pkg.has(ver)) pkg.set(ver, i + 1);
    }
  }
  for (const [ver, line] of pkg) {
    out.push(
      tagFinding(
        "dockerfile",
        file,
        line,
        ver,
        "PHP branch pinned via distro packages (apk/apt) or image metadata - patch level floats on rebuild",
      ),
    );
  }
  return out;
}

function imageYml(source: Source, file: string, text: string): Finding[] {
  const out: Finding[] = [];
  const re = /(?:^|\n)\s*image\s*:\s*["']?php:([^\s"'#]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    out.push(tagFinding(source, file, lineOf(text, m.index + 1), m[1] ?? "", "container image"));
  }
  const bare = /(?:^|\n)\s*image\s*:\s*["']?php\s*$/gm;
  while ((m = bare.exec(text)) !== null) {
    out.push(tagFinding(source, file, lineOf(text, m.index + 1), "latest", "container image with no tag"));
  }
  return out;
}

// Tokens that can plausibly denote a PHP version in a workflow file. Filters out
// dorny/paths-filter globs (a `php:` key listing file paths) and list openers
// ("-", "[") that follow `php-version:` keys.
const VERSIONISH = /^(?:\d|\$\{\{|(?:latest|stable|nightly|current|rc|alpha|beta))/i;

function githubActions(file: string, text: string): Finding[] {
  const out: VersionFinding[] = [];
  const seen = new Set<string>();
  const push = (line: number, token: string): void => {
    if (!token || !VERSIONISH.test(token)) return; // path globs / list openers are not versions
    const key = `${line}:${token}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(tagFinding("github-actions", file, line, token, "CI php-version"));
  };

  let m: RegExpExecArray | null;
  const scalar = /php-version\s*:\s*['"]?(\$\{\{[^}]*\}\}|[^'"\s#]+)/g;
  while ((m = scalar.exec(text)) !== null) {
    push(lineOf(text, m.index), m[1] ?? "");
  }
  const inline = /(?:php-versions?|matrix\.php)\s*:\s*\[([^\]]*)\]/g;
  while ((m = inline.exec(text)) !== null) {
    for (const raw of (m[1] ?? "").split(",")) {
      const tok = raw.trim().replace(/^['"]|['"]$/g, "");
      if (tok) push(lineOf(text, m.index), tok);
    }
  }
  // block form:  php:\n    - 8.2\n    - 8.3
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const key = /^(\s*)(?:php|php-versions?)\s*:\s*$/.exec(lines[i] ?? "");
    if (!key) continue;
    const indent = key[1]!.length;
    for (let j = i + 1; j < lines.length; j++) {
      const item = new RegExp(`^\\s{${indent + 2},}-\\s*['"]?(\\$\\{\\{[^}]*\\}\\}|[^'"\\s#]+)`).exec(lines[j] ?? "");
      if (!item) break;
      push(j + 1, item[1] ?? "");
    }
  }
  return out;
}

function phpVersionFile(file: string, text: string): Finding[] {
  const tok = (text.trim().split(/\r?\n/)[0] ?? "").trim();
  if (!tok) return [];
  return [tagFinding("php-version-file", file, 1, tok, ".php-version")];
}

function toolVersions(file: string, text: string): Finding[] {
  const m = /^php\s+(\S+)/m.exec(text);
  if (!m) return [];
  return [tagFinding("php-version-file", file, lineOf(text, m.index), m[1] ?? "", ".tool-versions (asdf)")];
}

const ON_VALUES = new Set(["1", "on", "true", "yes", "enabled"]);

function isOn(val: string): boolean {
  return ON_VALUES.has(val.trim().toLowerCase());
}

function parseBytesLimit(val: string): number | null {
  const m = /^(-?\d+)([kmg]?)$/i.exec(val.trim());
  if (!m) return null;
  const mult: Record<string, number> = { "": 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 };
  return Number(m[1]) * (mult[m[2]!.toLowerCase()] ?? 1);
}

function memoryLimitFinding(source: Source, file: string, line: number, val: string): AmplifierFinding {
  if (val.trim() === "-1") {
    return {
      kind: "amplifier",
      file,
      line,
      source,
      rule: "memory_limit",
      severity: "INFO",
      detail: "memory_limit is unlimited - OOM still reachable via real memory exhaustion (CVE-2026-109618 trigger)",
    };
  }
  const bytes = parseBytesLimit(val);
  if (bytes !== null && bytes > 0 && bytes <= 128 * 1024 ** 2) {
    return {
      kind: "amplifier",
      file,
      line,
      source,
      rule: "memory_limit",
      severity: "MEDIUM",
      detail: `memory_limit = ${val.trim()} - low enough that one cheap request can force the OOM at the heart of CVE-2026-109618`,
    };
  }
  return {
    kind: "amplifier",
    file,
    line,
    source,
    rule: "memory_limit",
    severity: "INFO",
    detail: `memory_limit = ${val.trim()} is set explicitly - verify request input cannot trivially exhaust it (CVE-2026-109618 trigger path)`,
  };
}

function ini(file: string, text: string): Finding[] {
  const out: Finding[] = [];
  let m: RegExpExecArray | null;
  const up = /^\s*session\.upload_progress\.enabled\s*=\s*(\S+)/gim;
  while ((m = up.exec(text)) !== null) {
    if (isOn(m[1] ?? "")) {
      out.push({
        kind: "amplifier",
        file,
        line: lineOf(text, m.index),
        source: "ini",
        rule: "session.upload_progress.enabled",
        severity: "HIGH",
        detail: "upload-progress enabled - the exact trigger used to demo CVE-2026-109618 pre-auth RCE; disable unless needed",
      });
    }
  }
  const ml = /^\s*memory_limit\s*=\s*(\S+)/gim;
  while ((m = ml.exec(text)) !== null) {
    out.push(memoryLimitFinding("ini", file, lineOf(text, m.index), m[1] ?? ""));
  }
  const oc = /^\s*opcache\.enable\s*=\s*(\S+)/gim;
  while ((m = oc.exec(text)) !== null) {
    if (isOn(m[1] ?? "")) {
      out.push({
        kind: "amplifier",
        file,
        line: lineOf(text, m.index),
        source: "ini",
        rule: "opcache.enable",
        severity: "INFO",
        detail: "OPcache enabled - involved in the CVE-2026-109619 exploit chain; patch PHP rather than disabling this",
      });
    }
  }
  return out;
}

function htaccess(file: string, text: string): Finding[] {
  const out: Finding[] = [];
  let m: RegExpExecArray | null;
  const up = /^\s*php_value\s+session\.upload_progress\.enabled\s+(\S+)/gim;
  while ((m = up.exec(text)) !== null) {
    if (isOn(m[1] ?? "")) {
      out.push({
        kind: "amplifier",
        file,
        line: lineOf(text, m.index),
        source: "htaccess",
        rule: "session.upload_progress.enabled",
        severity: "HIGH",
        detail: "upload-progress enabled via php_value - the exact trigger used to demo CVE-2026-109618 pre-auth RCE; disable unless needed",
      });
    }
  }
  const ml = /^\s*php_value\s+memory_limit\s+(\S+)/gim;
  while ((m = ml.exec(text)) !== null) {
    out.push(memoryLimitFinding("htaccess", file, lineOf(text, m.index), m[1] ?? ""));
  }
  return out;
}

function phpCode(file: string, text: string): Finding[] {
  const out: Finding[] = [];
  const filesIdx = text.indexOf("$_FILES");
  if (filesIdx !== -1) {
    const count = text.split("$_FILES").length - 1;
    out.push({
      kind: "amplifier",
      file,
      line: lineOf(text, filesIdx),
      source: "php-code",
      rule: "$_FILES",
      severity: "INFO",
      detail: `multipart upload endpoint (${count} use${count === 1 ? "" : "s"} of $_FILES) - attacker-controlled request body is the entry path for the CVE-2026-109618 OOM trigger`,
    });
  }
  const ini = /ini_set\s*\(\s*['"]session\.upload_progress\.enabled['"]\s*,\s*['"]?(\w*)/i.exec(text);
  if (ini !== null) {
    const val = ini[1] ?? "";
    if (val === "" || isOn(val)) {
      out.push({
        kind: "amplifier",
        file,
        line: lineOf(text, ini.index),
        source: "php-code",
        rule: "ini_set(session.upload_progress.enabled)",
        severity: "HIGH",
        detail: "upload-progress enabled in code - the exact trigger used to demo CVE-2026-109618 pre-auth RCE",
      });
    }
  }
  const sup = text.indexOf("session_upload_progress");
  if (sup !== -1) {
    out.push({
      kind: "amplifier",
      file,
      line: lineOf(text, sup),
      source: "php-code",
      rule: "session_upload_progress()",
      severity: "MEDIUM",
      detail: "upload-progress session key used in code - reachable upload-progress state, relevant to CVE-2026-109618",
    });
  }
  return out;
}

/**
 * Route one file by name to its detector. `file` is the scan-relative path
 * (POSIX separators); `size` is the file size in bytes.
 */
export function detect(file: string, text: string, size: number): Finding[] {
  const name = file.split("/").pop() ?? file;
  const lower = name.toLowerCase();
  const dot = lower.lastIndexOf(".");
  const ext = dot > 0 ? lower.slice(dot + 1) : "";

  if (name === "composer.json") return composerJson(file, text);
  if (name === "composer.lock") return composerLock(file, text);
  if (lower.startsWith("dockerfile")) return dockerfile(file, text);
  if (file.includes(".github/workflows/") && (ext === "yml" || ext === "yaml")) return githubActions(file, text);
  if (name === ".gitlab-ci.yml") return imageYml("gitlab-ci", file, text);
  if (/^(docker-)?compose[^/]*\.ya?ml$/.test(name)) return imageYml("compose-yml", file, text);
  if (name === ".php-version") return phpVersionFile(file, text);
  if (name === ".tool-versions") return toolVersions(file, text);
  if (name === ".htaccess") return htaccess(file, text);
  if ((ext === "php" || ext === "phtml") && size <= MAX_SCAN_BYTES) return phpCode(file, text);
  if ((ext === "ini" || name === ".user.ini") && size <= MAX_SCAN_BYTES) return ini(file, text);
  return [];
}
