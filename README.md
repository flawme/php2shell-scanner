# php2shell-scanner

Static scanner for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — the PHP engine RCE disclosed 2026-10-21. Both bugs live in the PHP engine itself, so any application running an unpatched PHP build is exposed, even a hello world: the fix is upgrading PHP, not changing application code. This tool scans a codebase for every declared PHP version and reports which deployments can resolve to an unpatched build, plus which attack-surface amplifiers are present.

## Install

```bash
npm install -g php2shell-scanner
```

Or run it once without installing:

```bash
npx php2shell-scanner /path/to/project
```

## Scan a project

```bash
php2shell-scan [options] [path]
```

`path` defaults to the current directory.

| Option | Effect |
| --- | --- |
| `--json` | Emit a machine-readable JSON report instead of text |
| `--no-color` | Disable ANSI colors |
| `--strict` | Also fail (exit 1) on FLOATING and UNKNOWN version references |
| `-h`, `--help` | Print usage |
| `-V`, `--version` | Print scanner version |

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No confirmed exposure |
| 1 | A VULNERABLE or UNSUPPORTED pin exists (FLOATING/UNKNOWN also fail under `--strict`) |
| 2 | Usage or scan error |

The exit code makes the scanner usable as a CI gate:

```bash
php2shell-scan . || echo "blocked: unpatched PHP pin detected"
```

## What it detects

**Version pins** — every place a repo declares which PHP it runs:

| Source | Examples |
| --- | --- |
| composer.json | `require.php`, `require-dev.php`, `config.platform.php` |
| composer.lock | platform overrides (the authoritative pin for deploys) |
| Dockerfiles | `FROM php:*` tags (including registry-qualified names), `ARG`/`ENV PHP_VERSION`, distro packages (`php84`, `php8.4-fpm`), FrankenPHP runtime tags |
| CI files | GitHub Actions `php-version` scalars and matrices, GitLab CI and docker-compose `image: php:*` |
| Version files | `.php-version`, `.tool-versions` (asdf) |

**Verdicts** — one per pin:

- `VULNERABLE` — the constraint resolves into an unpatched window (8.2.0-8.2.34, 8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11)
- `UNSUPPORTED` — the pin includes an EOL branch (below 8.2.0); no PHP2Shell patch exists there, migration is required
- `FLOATING` — unpinned or branch-only; resolves to a patched build today but a rebuild can silently drift
- `UNKNOWN` — a CI matrix variable or unparsable token; resolve and pin it
- `SAFE` — every version matching the constraint is patched (fixes: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, released 2026-10-21)

**Attack-surface amplifiers** — config that makes exploitation easier while the engine stays unpatched:

- `session.upload_progress.enabled` anywhere (ini, `.htaccess`, `ini_set`) — HIGH; the exact trigger used to demo the CVE-2026-109618 pre-auth RCE
- low `memory_limit` — MEDIUM; one cheap request can force the OOM at the heart of CVE-2026-109618
- `opcache.enable` and `$_FILES` upload endpoints — INFO; involved in the exploit chains

## Sample output

From `tests/fixtures/exposed-app` in this repo:

```text
PHP2Shell scanner - CVE-2026-109618 / CVE-2026-109619 (PHP engine RCE, disclosed 2026-10-21)
Unpatched windows: 8.2.0-8.2.34, 8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11 - fixes: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
The fix is a PHP engine upgrade; application code changes cannot patch this.

VERSION PINS
  [VULN]     .github/workflows/ci.yml:8  8.3.12  - CI php-version - 8.3.12 is unpatched — first fix in the 8.3 branch is 8.3.36
  [VULN]     composer.json:4  ^8.2  - require.php (runtime) - can resolve to unpatched PHP: 8.2.x below 8.2.35; 8.3.x below 8.3.36; 8.4.x below 8.4.27; 8.5.x below 8.5.12
  [VULN]     Dockerfile:2  8.4.2-fpm-alpine  - base image - 8.4.2 is unpatched — first fix in the 8.4 branch is 8.4.27
  [EOL]      .php-version:1  8.1.2  - .php-version - PHP 8.1.2 is on an EOL branch — no PHP2Shell patch exists; upgrade required
  [FLOATING] .github/workflows/ci.yml:8  8.2  - CI php-version - unpinned — currently resolves to 8.2.35 (patched 2026-10-21); pin the exact version so a rebuild cannot drift

ATTACK-SURFACE AMPLIFIERS
  [HIGH]     php.ini:1  session.upload_progress.enabled  - upload-progress enabled - the exact trigger used to demo CVE-2026-109618 pre-auth RCE; disable unless needed
  [MEDIUM]   php.ini:2  memory_limit  - memory_limit = 64M - low enough that one cheap request can force the OOM at the heart of CVE-2026-109618

SUMMARY
  scanned 8 file(s) - 10 version pin(s): 7 vulnerable, 1 EOL, 2 floating, 0 unknown, 0 safe; 6 amplifier(s)
  verdict: EXPOSED - one or more declared PHP versions are unpatched; upgrade PHP on those deployments
  note: static scan of repo-declared versions - ground truth is `php -v` on the deployed server
```

(Rows omitted for brevity in the listing above; the real run reports every pin.)

## Limitations

This is a static scan of repo-declared versions. The authoritative answer for a deployment is `php -v` on the server that actually runs it. `UNKNOWN` and `FLOATING` findings name the file and line to resolve.

## Advisory

- [PHP Foundation security release announcement (2026-10-21)](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Wiz: PHP2Shell PHP RCE analysis](https://www.wiz.io/blog/php2shell-php-rce)
- [CISA alert (2026-10-21)](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)

## Development

```bash
npm test    # builds with tsc, runs the full test suite
npm run scan -- /path/to/project
```

## License

[MIT](LICENSE) — [ko-fi.com/flawme](https://ko-fi.com/flawme) if this saved you a bad weekend.
