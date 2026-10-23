/** PHP version as [major, minor, patch]. */
export type Ver = readonly [number, number, number];

export interface Advisory {
  readonly cves: readonly string[];
  readonly disclosed: string;
  /** First patched version of each supported branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). */
  readonly fixed: readonly Ver[];
  /** Lowest branch with a patch (8.2.0); anything below is EOL with no fix available. */
  readonly supportedFloor: Ver;
  readonly sources: readonly string[];
}

/**
 * Single source of truth for the PHP2Shell advisory.
 * CVE-2026-109618: RCE via OOM corruption (upload-progress unserializer UAF).
 * CVE-2026-109619: RCE via stale global state (fatal-error backtrace + OPcache UAF).
 * Both are PHP engine bugs: any app on an unpatched build is exposed, even hello world.
 */
export const PHP2SHELL: Advisory = {
  cves: ["CVE-2026-109618", "CVE-2026-109619"],
  disclosed: "2026-10-21",
  fixed: [
    [8, 2, 35],
    [8, 3, 36],
    [8, 4, 27],
    [8, 5, 12],
  ],
  supportedFloor: [8, 2, 0],
  sources: [
    "https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/",
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    "https://www.wiz.io/blog/php2shell-php-rce",
    "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching",
  ],
};

export type Status = "VULNERABLE" | "UNSUPPORTED" | "FLOATING" | "UNKNOWN" | "SAFE";

/** Which kind of repo metadata declared a version or amplifier. */
export type Source =
  | "composer.json"
  | "composer.lock"
  | "dockerfile"
  | "compose-yml"
  | "github-actions"
  | "gitlab-ci"
  | "php-version-file"
  | "ini"
  | "htaccess"
  | "php-code";

export interface VersionFinding {
  readonly kind: "version";
  /** Path relative to the scanned root. */
  readonly file: string;
  readonly line: number;
  readonly source: Source;
  /** The raw version token as written in the file. */
  readonly constraint: string;
  readonly status: Status;
  readonly detail: string;
}

export interface AmplifierFinding {
  readonly kind: "amplifier";
  readonly file: string;
  readonly line: number;
  readonly source: Source;
  /** The config key or code construct that widens the attack surface. */
  readonly rule: string;
  readonly severity: "HIGH" | "MEDIUM" | "INFO";
  readonly detail: string;
}

export type Finding = VersionFinding | AmplifierFinding;
