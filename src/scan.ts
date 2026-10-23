import { readFileSync, statSync } from "node:fs";
import { relative } from "node:path";
import { detect } from "./detectors.js";
import type { Finding, Status } from "./types.js";
import { walk } from "./walk.js";

export interface ScanResult {
  readonly findings: readonly Finding[];
  readonly files: number;
  readonly unreadable: number;
  readonly detectorErrors: number;
}

const STATUS_RANK: Record<Status, number> = {
  VULNERABLE: 0,
  UNSUPPORTED: 1,
  FLOATING: 2,
  UNKNOWN: 3,
  SAFE: 4,
};

function severityRank(s: "HIGH" | "MEDIUM" | "INFO"): number {
  return s === "HIGH" ? 0 : s === "MEDIUM" ? 1 : 2;
}

export function scanPath(root: string): ScanResult {
  const findings: Finding[] = [];
  let files = 0;
  let unreadable = 0;
  let detectorErrors = 0;

  for (const abs of walk(root)) {
    files++;
    const rel = relative(root, abs) || ".";
    let size = 0;
    let text: string;
    try {
      size = statSync(abs).size;
      text = readFileSync(abs, "utf8");
    } catch {
      unreadable++;
      continue;
    }
    try {
      findings.push(...detect(rel, text, size));
    } catch {
      detectorErrors++; // one broken file must not kill the scan
    }
  }

  findings.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "version" ? -1 : 1;
    if (a.kind === "version" && b.kind === "version") {
      const byStatus = STATUS_RANK[a.status] - STATUS_RANK[b.status];
      if (byStatus !== 0) return byStatus;
    }
    if (a.kind === "amplifier" && b.kind === "amplifier") {
      const bySeverity = severityRank(a.severity) - severityRank(b.severity);
      if (bySeverity !== 0) return bySeverity;
    }
    return a.file === b.file ? a.line - b.line : a.file.localeCompare(b.file);
  });

  return { findings, files, unreadable, detectorErrors };
}
