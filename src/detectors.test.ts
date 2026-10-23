import { test } from "node:test";
import assert from "node:assert/strict";
import { detect } from "./detectors.js";
import type { AmplifierFinding, Finding, Status } from "./types.js";

function versionStatuses(findings: Finding[]): Status[] {
  return findings.flatMap((f) => (f.kind === "version" ? [f.status] : []));
}

function ampRules(findings: Finding[]): string[] {
  return findings.flatMap((f) => (f.kind === "amplifier" ? [f.rule] : []));
}

test("composer.json: require, platform, malformed", () => {
  const req = detect("composer.json", '{"require":{"php":"^8.2"}}', 40);
  assert.equal(versionStatuses(req).length, 1);
  assert.equal(versionStatuses(req)[0], "VULNERABLE");

  const both = detect(
    "composer.json",
    '{"require":{"php":"^8.2"},"config":{"platform":{"php":"8.5.12"}}}',
    60,
  );
  assert.deepEqual(versionStatuses(both), ["VULNERABLE", "SAFE"]);

  const dev = detect("composer.json", '{"require-dev":{"php":"^8.4.27"}}', 40);
  assert.deepEqual(versionStatuses(dev), ["VULNERABLE"]);

  const bad = detect("composer.json", "{ not json", 12);
  assert.deepEqual(versionStatuses(bad), ["UNKNOWN"]);
});

test("composer.lock: platform override", () => {
  const out = detect("composer.lock", '{"platform":{"php":"8.3.2"},"packages":[]}', 40);
  assert.deepEqual(versionStatuses(out), ["VULNERABLE"]);
});

test("Dockerfile: FROM tags, ARG substitution, platform prefix", () => {
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM php:8.3.12-fpm-alpine\n", 30)), [
    "VULNERABLE",
  ]);
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM php:8.5.12-fpm\n", 25)), ["SAFE"]);
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM php:8.3-fpm\n", 20)), ["FLOATING"]);
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM php:8.1-fpm\n", 20)), ["UNSUPPORTED"]);
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "FROM --platform=linux/amd64 php:8.4.26-fpm\n", 45)),
    ["VULNERABLE"],
  );

  const arg = detect("Dockerfile", "ARG PHP_VERSION=8.4.2\nFROM php:${PHP_VERSION}-cli\n", 50);
  assert.deepEqual(versionStatuses(arg), ["VULNERABLE", "VULNERABLE"]);

  const unresolved = detect("Dockerfile", "FROM php:${PHP_VERSION}-cli\n", 30);
  assert.deepEqual(versionStatuses(unresolved), ["UNKNOWN"]);
});

test("Dockerfile: registry-qualified php images, frankenphp runtime, distro packages", () => {
  // registry-qualified base image (witness: digininja/DVWA)
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM docker.io/library/php:8-apache\n", 40)), [
    "FLOATING",
  ]);
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "FROM docker.io/library/php:8.3.12-apache\n", 45)),
    ["VULNERABLE"],
  );
  // namespaced registry image
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM ghcr.io/acme/php:8.3.12-fpm\n", 40)), [
    "VULNERABLE",
  ]);

  // frankenphp embeds the PHP runtime in its tag (witness: lycheeorg/Lychee)
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "FROM dunglas/frankenphp:1.13.2-php8-trixie AS runtime\n", 60)),
    ["FLOATING"],
  );
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "FROM dunglas/frankenphp:php-8.4-bookworm\n", 40)),
    ["FLOATING"],
  );
  // frankenphp tag without a php version: nothing to pin
  assert.deepEqual(versionStatuses(detect("Dockerfile", "FROM dunglas/frankenphp:v1.13.2\n", 40)), []);

  // alpine apk packages pin only the branch (witnesses: kanboard, Shaarli, FreshRSS)
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "RUN apk add --no-cache php85 php85-fpm php85-phar\n", 55)),
    ["FLOATING"],
  );
  // many php84-* packages dedupe to one finding per branch
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "RUN apk add php84 php84-ctype php84-curl php84-fpm\n", 58)),
    ["FLOATING"],
  );
  // debian-style apt packages
  assert.deepEqual(
    versionStatuses(detect("Dockerfile", "RUN apt-get install -y php8.4-fpm php8.4-cli\n", 52)),
    ["FLOATING"],
  );
  // EOL branch via packages (witness: FreshRSS Dockerfile-Oldest)
  assert.deepEqual(versionStatuses(detect("Dockerfile", "RUN apk add php81 php81-fpm\n", 50)), [
    "UNSUPPORTED",
  ]);
});

test("github actions: scalar, inline array, block list, matrix variable", () => {
  const scalar = detect(".github/workflows/ci.yml", "          php-version: '8.2'\n", 25);
  assert.deepEqual(versionStatuses(scalar), ["FLOATING"]);

  const exact = detect(".github/workflows/ci.yml", "          php-version: 8.5.12\n", 25);
  assert.deepEqual(versionStatuses(exact), ["SAFE"]);

  const inline = detect(
    ".github/workflows/ci.yml",
    "        php-versions: [8.3.12, 8.5.12]\n",
    35,
  );
  assert.deepEqual(versionStatuses(inline), ["VULNERABLE", "SAFE"]);

  const block = detect(
    ".github/workflows/ci.yml",
    ["jobs:", "  test:", "    strategy:", "      matrix:", "        php:", "          - 8.5.12", "          - 8.4.26", "    steps:", "      - uses: shivammathur/setup-php@v2"].join("\n"),
    200,
  );
  assert.deepEqual(versionStatuses(block), ["SAFE", "VULNERABLE"]);

  const matrixVar = detect(
    ".github/workflows/ci.yml",
    "          php-version: ${{ matrix.php }}\n",
    35,
  );
  assert.deepEqual(versionStatuses(matrixVar), ["UNKNOWN"]);
});

test("github actions: path filters and list openers are not version tokens", () => {
  // `php-version:` key with a block list below: the scalar scan must not read "-" as a token
  // (witness: lycheeorg/Lychee php_dist.yml)
  const blockList = detect(
    ".github/workflows/dist.yml",
    ["  matrix:", "    php-version:", "      - 8.4", "      - 8.5"].join("\n"),
    60,
  );
  assert.deepEqual(versionStatuses(blockList), ["FLOATING", "FLOATING"]);

  // inline bracket list right after the key: the versions, no "[" token
  // (witness: symfony/demo lint.yaml)
  const inlineBracket = detect(".github/workflows/lint.yaml", "        php-version: ['8.4']\n", 30);
  assert.deepEqual(versionStatuses(inlineBracket), ["FLOATING"]);

  // dorny/paths-filter: a `php:` key holding path globs is not a version matrix
  // (witness: lycheeorg/Lychee CICD.yml)
  const pathsFilter = detect(
    ".github/workflows/CICD.yml",
    [
      "    outputs:",
      "      php: ${{ steps.filter.outputs.php }}",
      "    steps:",
      "      - uses: dorny/paths-filter@v3",
      "        id: filter",
      "        with:",
      "          filters: |",
      "            php:",
      "              - 'app/**/*.php'",
      "              - 'config/**/*.php'",
      "              - 'composer.json'",
      "              - 'phpunit.xml'",
    ].join("\n"),
    220,
  );
  assert.deepEqual(versionStatuses(pathsFilter), []);
});

test("gitlab-ci and compose: image tags", () => {
  const gitlab = detect(".gitlab-ci.yml", "test:\n  image: php:8.2.34\n", 28);
  assert.deepEqual(versionStatuses(gitlab), ["VULNERABLE"]);

  const bare = detect(".gitlab-ci.yml", "test:\n  image: php\n", 20);
  assert.deepEqual(versionStatuses(bare), ["FLOATING"]);

  const compose = detect("docker-compose.yml", "services:\n  app:\n    image: php:8.1-fpm\n", 40);
  assert.deepEqual(versionStatuses(compose), ["UNSUPPORTED"]);
});

test("version files", () => {
  assert.deepEqual(versionStatuses(detect(".php-version", "8.5.12\n", 8)), ["SAFE"]);
  assert.deepEqual(versionStatuses(detect(".tool-versions", "php 8.4.26\nnodejs 22\n", 20)), [
    "VULNERABLE",
  ]);
});

test("ini and htaccess amplifiers", () => {
  const ini = detect(
    "php.ini",
    "session.upload_progress.enabled = 1\nmemory_limit = 64M\nopcache.enable = 1\n",
    70,
  );
  const rules = ampRules(ini);
  assert.ok(rules.includes("session.upload_progress.enabled"));
  assert.ok(rules.includes("memory_limit"));
  assert.ok(rules.includes("opcache.enable"));
  const upload = ini.find(
    (f): f is AmplifierFinding =>
      f.kind === "amplifier" && f.rule === "session.upload_progress.enabled",
  );
  assert.equal(upload?.severity, "HIGH");

  const off = detect("php.ini", "session.upload_progress.enabled = 0\n", 40);
  assert.equal(ampRules(off).length, 0);

  const ht = detect(".htaccess", "php_value session.upload_progress.enabled 1\n", 45);
  const htRule = ht.find(
    (f): f is AmplifierFinding =>
      f.kind === "amplifier" && f.rule === "session.upload_progress.enabled",
  );
  assert.equal(htRule?.severity, "HIGH");
});

test("php code amplifiers", () => {
  const withIni = detect(
    "upload.php",
    "<?php ini_set('session.upload_progress.enabled', '1');\n",
    60,
  );
  assert.ok(ampRules(withIni).includes("ini_set(session.upload_progress.enabled)"));

  const files = detect("upload.php", "<?php\n$x = $_FILES['a'];\n", 25);
  assert.ok(ampRules(files).includes("$_FILES"));

  const clean = detect("index.php", "<?php echo 'hello';\n", 25);
  assert.equal(ampRules(clean).length, 0);
});
