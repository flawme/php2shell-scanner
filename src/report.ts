import type { ScanResult } from "./scan.js";
import { PHP2SHELL, type AmplifierFinding, type Finding, type Status, type VersionFinding } from "./types.js";

export interface RenderOptions {
  readonly color: boolean;
  readonly strict: boolean;
}

const RESET = "\x1b[0m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const MAGENTA = "\x1b[35m";
const GRAY = "\x1b[90m";
const BOLD = "\x1b[1m";

function paint(on: boolean, code: string, s: string): string {
  return on ? `${code}${s}${RESET}` : s;
}

const isVersion = (f: Finding): f is VersionFinding => f.kind === "version";
const isAmplifier = (f: Finding): f is AmplifierFinding => f.kind === "amplifier";

const STATUS_LABEL: Record<Status, string> = {
  VULNERABLE: "VULN",
  UNSUPPORTED: "EOL",
  FLOATING: "FLOATING",
  UNKNOWN: "UNKNOWN",
  SAFE: "SAFE",
};

const STATUS_COLOR: Record<Status, string> = {
  VULNERABLE: RED,
  UNSUPPORTED: MAGENTA,
  FLOATING: YELLOW,
  UNKNOWN: GRAY,
  SAFE: GREEN,
};

const SEVERITY_COLOR: Record<AmplifierFinding["severity"], string> = {
  HIGH: RED,
  MEDIUM: YELLOW,
  INFO: GRAY,
};

export function exitCode(findings: readonly Finding[], strict: boolean): number {
  const fail = strict
    ? new Set<Status>(["VULNERABLE", "UNSUPPORTED", "FLOATING", "UNKNOWN"])
    : new Set<Status>(["VULNERABLE", "UNSUPPORTED"]);
  return findings.some((f) => f.kind === "version" && fail.has(f.status)) ? 1 : 0;
}

const FIXES = PHP2SHELL.fixed.map((f) => f.join(".")).join(" / ");

export function renderText(res: ScanResult, opts: RenderOptions): { text: string; exit: number } {
  const on = opts.color;
  const versions = res.findings.filter(isVersion);
  const amps = res.findings.filter(isAmplifier);
  const counts: Record<Status, number> = {
    VULNERABLE: 0,
    UNSUPPORTED: 0,
    FLOATING: 0,
    UNKNOWN: 0,
    SAFE: 0,
  };
  for (const f of versions) counts[f.status]++;

  let verdict: string;
  let verdictColor = GREEN;
  if (counts.VULNERABLE > 0) {
    verdict = "EXPOSED - one or more declared PHP versions are unpatched; upgrade PHP on those deployments";
    verdictColor = RED;
  } else if (counts.UNSUPPORTED > 0) {
    verdict = "EXPOSED - EOL PHP branch in use; no patch exists, migration required";
    verdictColor = RED;
  } else if (counts.FLOATING + counts.UNKNOWN > 0) {
    verdict = "NO CONFIRMED EXPOSURE - but unpinned or unresolvable version references exist; resolve them";
    verdictColor = YELLOW;
  } else if (versions.length > 0) {
    verdict = "PATCHED - every declared PHP version is patched";
  } else {
    verdict = "NO PHP VERSION PINS FOUND - if this repo deploys PHP, pin the version explicitly so it can be verified";
    verdictColor = YELLOW;
  }

  const L: string[] = [];
  L.push(
    paint(
      on,
      BOLD,
      `PHP2Shell scanner - ${PHP2SHELL.cves.join(" / ")} (PHP engine RCE, disclosed ${PHP2SHELL.disclosed})`,
    ),
  );
  L.push(
    `Unpatched windows: 8.2.0-8.2.34, 8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11 - fixes: ${FIXES}`,
  );
  L.push(`The fix is a PHP engine upgrade; application code changes cannot patch this.`);
  L.push(`Advisory: ${PHP2SHELL.sources[0]}`);
  L.push("");

  if (versions.length > 0) {
    L.push("VERSION PINS");
    for (const f of versions) {
      const label = paint(on, STATUS_COLOR[f.status], `[${STATUS_LABEL[f.status]}]`.padEnd(10));
      L.push(`  ${label} ${f.file}:${f.line}  ${f.constraint}  - ${f.detail}`);
    }
    L.push("");
  }

  if (amps.length > 0) {
    L.push("ATTACK-SURFACE AMPLIFIERS");
    for (const f of amps) {
      const label = paint(on, SEVERITY_COLOR[f.severity], `[${f.severity}]`.padEnd(10));
      L.push(`  ${label} ${f.file}:${f.line}  ${f.rule}  - ${f.detail}`);
    }
    L.push("");
  }

  L.push("SUMMARY");
  L.push(
    `  scanned ${res.files} file(s) - ${versions.length} version pin(s): ${counts.VULNERABLE} vulnerable, ` +
      `${counts.UNSUPPORTED} EOL, ${counts.FLOATING} floating, ${counts.UNKNOWN} unknown, ${counts.SAFE} safe; ` +
      `${amps.length} amplifier(s)`,
  );
  if (res.unreadable > 0) L.push(`  warning: ${res.unreadable} file(s) could not be read`);
  if (res.detectorErrors > 0) L.push(`  warning: ${res.detectorErrors} file(s) failed detection`);
  L.push(`  verdict: ${paint(on, verdictColor, verdict)}`);
  L.push("  note: static scan of repo-declared versions - ground truth is `php -v` on the deployed server");
  L.push("");

  return { text: L.join("\n"), exit: exitCode(res.findings, opts.strict) };
}

export function renderJson(res: ScanResult, strict: boolean): string {
  return (
    JSON.stringify(
      {
        scanner: "php2shell-scanner",
        version: "1.0.0",
        advisory: {
          cves: PHP2SHELL.cves,
          disclosed: PHP2SHELL.disclosed,
          unpatched: {
            "8.2": ">=8.2.0 <8.2.35",
            "8.3": ">=8.3.0 <8.3.36",
            "8.4": ">=8.4.0 <8.4.27",
            "8.5": ">=8.5.0 <8.5.12",
          },
          fixes: PHP2SHELL.fixed,
          sources: PHP2SHELL.sources,
        },
        scannedFiles: res.files,
        unreadableFiles: res.unreadable,
        detectorErrors: res.detectorErrors,
        findings: res.findings,
        exitCode: exitCode(res.findings, strict),
      },
      null,
      2,
    ) + "\n"
  );
}
