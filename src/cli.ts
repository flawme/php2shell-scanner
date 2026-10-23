#!/usr/bin/env node
import { statSync } from "node:fs";
import { resolve } from "node:path";
import { exitCode, renderJson, renderText } from "./report.js";
import { scanPath } from "./scan.js";
import { PHP2SHELL } from "./types.js";

const USAGE = `php2shell-scan [options] [path]

Scans a codebase for PHP2Shell exposure (${PHP2SHELL.cves.join(" / ")}):
PHP version pins in composer / Dockerfile / CI files, plus attack-surface
amplifiers (upload-progress, low memory_limit, upload endpoints).
The bug is in the PHP engine itself - the fix is upgrading PHP, not app code.

Options:
  --json        machine-readable JSON report
  --no-color    disable ANSI colors
  --strict      also fail (exit 1) on FLOATING/UNKNOWN version references
  -h, --help    this help
  -V, --version print scanner version

Arguments:
  path          directory to scan (default: current directory)

Exit codes:
  0  no confirmed exposure
  1  VULNERABLE or UNSUPPORTED pin found (also FLOATING/UNKNOWN with --strict)
  2  usage or scan error
`;

function fail(msg: string): number {
  process.stderr.write(`error: ${msg}\n\n${USAGE}`);
  return 2;
}

function main(): number {
  const argv = process.argv.slice(2);
  let json = false;
  let noColor = false;
  let strict = false;
  let help = false;
  let showVersion = false;
  let pathArg: string | null = null;

  for (const a of argv) {
    if (a === "--json") json = true;
    else if (a === "--no-color") noColor = true;
    else if (a === "--strict") strict = true;
    else if (a === "-h" || a === "--help") help = true;
    else if (a === "-V" || a === "--version") showVersion = true;
    else if (a.startsWith("-")) return fail(`unknown option "${a}"`);
    else if (pathArg === null) pathArg = a;
    else return fail("only one scan path is allowed");
  }

  if (help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (showVersion) {
    process.stdout.write("php2shell-scanner 1.0.0\n");
    return 0;
  }

  const root = resolve(pathArg ?? ".");
  let isDir = false;
  try {
    isDir = statSync(root).isDirectory();
  } catch {
    return fail(`scan path not found: ${root}`);
  }
  if (!isDir) return fail(`scan path is not a directory: ${root}`);

  const res = scanPath(root);
  if (json) {
    process.stdout.write(renderJson(res, strict));
  } else {
    const color = !noColor && process.stdout.isTTY === true;
    process.stdout.write(renderText(res, { color, strict }).text);
  }
  return exitCode(res.findings, strict);
}

process.exitCode = main();
