import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyTag, evaluate, parseConstraint } from "./version.js";

function constraintStatus(c: string): string {
  const pc = parseConstraint(c);
  return pc === null ? "UNKNOWN" : evaluate(pc).status;
}

test("composer-style constraints vs the PHP2Shell windows", () => {
  const cases: readonly (readonly [string, string])[] = [
    // the sneaky one: caret crosses into the next branch's unpatched range
    ["^8.2", "VULNERABLE"],
    ["^8.4.27", "VULNERABLE"],
    ["~8.4.27", "SAFE"],
    ["~8.5", "VULNERABLE"],
    ["^8.5.12", "SAFE"],
    // comparison operators
    [">=8.5", "VULNERABLE"],
    [">=8.5.12", "SAFE"],
    [">=8.4.27 <8.5.0", "SAFE"],
    [">=8.2.35 <8.3", "SAFE"],
    [">=8.2.35", "VULNERABLE"],
    ["> 8.3.12", "VULNERABLE"],
    ["> 8.3", "VULNERABLE"],
    ["<=8.3.35", "VULNERABLE"],
    ["<=8.2.34", "VULNERABLE"],
    ["8.3.12", "VULNERABLE"],
    ["8.5.12", "SAFE"],
    // wildcards
    ["8.3.*", "VULNERABLE"],
    ["8.*", "VULNERABLE"],
    ["*", "VULNERABLE"],
    ["!=8.3.5", "VULNERABLE"],
    // hyphen ranges — every one of these crosses an unpatched window
    ["8.2 - 8.5.12", "VULNERABLE"],
    ["8.3.36 - 8.4.27", "VULNERABLE"],
    ["8.4.27 - 8.5.12", "VULNERABLE"],
    // unions
    [">=8.3 <8.4 || >=8.5.12", "VULNERABLE"],
    ["8.2.35 || 8.3.36 || 8.4.27 || 8.5.12", "SAFE"],
    // EOL branches: no patch exists at all
    ["^7.4", "UNSUPPORTED"],
    [">=8.1 <8.2", "UNSUPPORTED"],
    ["7.4 || 8.5.12", "UNSUPPORTED"],
    [">=5.3", "VULNERABLE"], // spans EOL territory but also admits unpatched 8.2-8.5 — window hit wins
    ["<8.2", "UNSUPPORTED"],
    ["8.1.29", "UNSUPPORTED"],
    // unparseable / partial
    ["banana", "UNKNOWN"],
    ["", "UNKNOWN"],
    ["8.2 || banana", "VULNERABLE"], // the parsed branch alone proves exposure
  ];
  for (const [c, expected] of cases) {
    assert.equal(constraintStatus(c), expected, `constraint: ${c}`);
  }
});

test("docker / CI version tokens", () => {
  const cases: readonly (readonly [string, string])[] = [
    ["8.3.12-fpm", "VULNERABLE"],
    ["8.5.12-cli", "SAFE"],
    ["8.2.34", "VULNERABLE"],
    ["8.3", "FLOATING"],
    ["8.3-fpm", "FLOATING"],
    ["8", "FLOATING"],
    ["latest", "FLOATING"],
    ["fpm-alpine", "FLOATING"],
    ["8.1-fpm", "UNSUPPORTED"],
    ["8.0.30", "UNSUPPORTED"],
    ["7.4.33", "UNSUPPORTED"],
    ["8.6.0-fpm", "FLOATING"],
    ["${{ matrix.php }}", "UNKNOWN"],
    ["banana", "UNKNOWN"],
  ];
  for (const [tok, expected] of cases) {
    assert.equal(classifyTag(tok).status, expected, `token: ${tok}`);
  }
});
