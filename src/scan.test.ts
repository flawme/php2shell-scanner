import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { exitCode } from "./report.js";
import { scanPath } from "./scan.js";
import type { Finding, Status } from "./types.js";

const FIXTURES = fileURLToPath(new URL("../tests/fixtures/", import.meta.url));

function versionStatuses(findings: readonly Finding[]): Status[] {
  return findings.flatMap((f) => (f.kind === "version" ? [f.status] : []));
}

function ampRules(findings: readonly Finding[]): string[] {
  return findings.flatMap((f) => (f.kind === "amplifier" ? [f.rule] : []));
}

test("e2e: exposed-app reports vulnerable pins and amplifiers, exit 1", () => {
  const res = scanPath(join(FIXTURES, "exposed-app"));
  const st = versionStatuses(res.findings);

  // 7 vulnerable: composer require ^8.2, platform 8.2.20, lock 8.3.2,
  // Dockerfile ARG 8.4.2 + resolved FROM + 8.3.12-cli, CI matrix 8.3.12
  assert.equal(st.filter((s) => s === "VULNERABLE").length, 7);
  // 2 floating: CI php-versions 8.2 + CI php-version '8.2'
  assert.equal(st.filter((s) => s === "FLOATING").length, 2);
  // 1 EOL: .php-version 8.1.2
  assert.equal(st.filter((s) => s === "UNSUPPORTED").length, 1);
  assert.equal(st.length, 10);

  const rules = ampRules(res.findings);
  assert.equal(rules.filter((r) => r === "session.upload_progress.enabled").length, 2); // ini + htaccess
  assert.ok(rules.includes("memory_limit"));
  assert.ok(rules.includes("opcache.enable"));
  assert.ok(rules.includes("$_FILES"));

  // sorted: versions before amplifiers
  assert.equal(res.findings[0]?.kind, "version");
  assert.equal(res.findings[res.findings.length - 1]?.kind, "amplifier");

  assert.equal(exitCode(res.findings, false), 1);
  assert.equal(exitCode(res.findings, true), 1);
});

test("e2e: safe-app is all SAFE, exit 0 even with --strict", () => {
  const res = scanPath(join(FIXTURES, "safe-app"));
  const st = versionStatuses(res.findings);
  assert.equal(st.length, 5);
  assert.ok(st.every((s) => s === "SAFE"));
  assert.equal(ampRules(res.findings).length, 0);
  assert.equal(exitCode(res.findings, false), 0);
  assert.equal(exitCode(res.findings, true), 0);
});

test("e2e: edge-app is unknown/floating only - exit 0, strict exit 1", () => {
  const res = scanPath(join(FIXTURES, "edge-app"));
  const st = versionStatuses(res.findings);
  assert.equal(st.filter((s) => s === "VULNERABLE").length, 0);
  assert.equal(st.filter((s) => s === "UNSUPPORTED").length, 0);
  assert.ok(st.includes("UNKNOWN")); // malformed composer.json, unresolved ${PHP_VERSION}, matrix var
  assert.ok(st.includes("FLOATING"));
  assert.equal(exitCode(res.findings, false), 0);
  assert.equal(exitCode(res.findings, true), 1);
});

test("e2e: empty-app finds nothing, exit 0", () => {
  const res = scanPath(join(FIXTURES, "empty-app"));
  assert.equal(res.findings.length, 0);
  assert.equal(res.files, 1);
  assert.equal(exitCode(res.findings, false), 0);
});
