import test from "node:test";
import assert from "node:assert/strict";
import { applyNoiseFilters } from "../server/noise.js";
import {
  buildDependencyFindings,
  compareVersions,
  cvss3BaseScore,
  fixedVersionFor,
  isSupportedLockfile,
  parseLockfile,
  severityOf
} from "../server/osv.js";
import { failsThreshold, relativePath, toCsv, toSarif } from "../server/report.js";

const base = { ruleId: "r", label: "x", severity: "critical", category: "cloud", stage: "token-pattern", masked: "abcd...wxyz" };

test("lockfile secrets are suppressed as lockfile noise", () => {
  const { kept, suppressed } = applyNoiseFilters([{ ...base, id: "1", file: "app/package-lock.json", context: '"integrity": "sha512-abc"' }]);
  assert.equal(kept.length, 0);
  assert.equal(suppressed[0].suppressedBy, "lockfile");
});

test("dependency CVEs inside lockfiles are kept", () => {
  const { kept } = applyNoiseFilters([{ ...base, id: "1", category: "dependency-cve", file: "package-lock.json", context: "lodash@4.17.15" }]);
  assert.equal(kept.length, 1);
});

test("regex rule definitions are not reported as credentials", () => {
  const { suppressed } = applyNoiseFilters([
    { ...base, id: "1", file: "server/rules/providerRules.js", context: "pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----/" }
  ]);
  assert.equal(suppressed[0].suppressedBy, "rule-definition");
});

test("inline allow comments suppress a finding", () => {
  const { suppressed } = applyNoiseFilters([{ ...base, id: "1", file: "src/a.js", context: 'const k = "abcd...wxyz"; // gitleaks:allow' }]);
  assert.equal(suppressed[0].suppressedBy, "inline-allow");
});

test("vendor and build directories are suppressed", () => {
  const { suppressed } = applyNoiseFilters([{ ...base, id: "1", file: "repo/node_modules/x/index.js", context: "k=abc" }]);
  assert.equal(suppressed[0].suppressedBy, "vendor-build");
});

test("findings in test files are kept but downgraded and tagged", () => {
  const { kept } = applyNoiseFilters([{ ...base, id: "1", file: "tests/scanner.test.js", context: "const token = 'abcd...wxyz'" }]);
  assert.equal(kept[0].severity, "high");
  assert.equal(kept[0].originalSeverity, "critical");
  assert.equal(kept[0].inTestFile, true);
});

test("real source findings pass through untouched", () => {
  const finding = { ...base, id: "1", file: "src/config.js", context: 'const key = "abcd...wxyz"' };
  const { kept, suppressed } = applyNoiseFilters([finding]);
  assert.deepEqual(kept, [finding]);
  assert.equal(suppressed.length, 0);
});

test("parses package-lock v3 including scoped and nested packages", () => {
  const lock = JSON.stringify(
    {
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/@babel/core": { version: "7.0.0", dev: true },
        "node_modules/a/node_modules/minimist": { version: "1.2.0" },
        "node_modules/local": { link: true }
      }
    },
    null,
    2
  );
  const pkgs = parseLockfile("package-lock.json", lock);
  assert.deepEqual(
    pkgs.map((p) => `${p.name}@${p.version}${p.dev ? ":dev" : ""}`),
    ["lodash@4.17.15", "@babel/core@7.0.0:dev", "minimist@1.2.0"]
  );
  assert.ok(pkgs[0].line > 1);
});

test("parses yarn.lock v1, requirements.txt and Cargo.lock", () => {
  const yarn = '# yarn lockfile v1\n\n"@scope/a@^1.0.0", "@scope/a@^1.1.0":\n  version "1.2.3"\n\nlodash@^4.0.0:\n  version "4.17.20"\n';
  assert.deepEqual(parseLockfile("yarn.lock", yarn).map((p) => `${p.name}@${p.version}`), ["@scope/a@1.2.3", "lodash@4.17.20"]);

  const req = "# comment\nrequests==2.19.0\nflask>=2.0\njinja2[i18n]==2.10 ; python_version > '3'\n-r other.txt\n";
  assert.deepEqual(parseLockfile("requirements.txt", req).map((p) => `${p.name}@${p.version}`), ["requests@2.19.0", "jinja2@2.10"]);

  const cargo = '[[package]]\nname = "serde"\nversion = "1.0.100"\n\n[[package]]\nname = "time"\nversion = "0.1.40"\n';
  assert.deepEqual(parseLockfile("Cargo.lock", cargo).map((p) => `${p.ecosystem}:${p.name}@${p.version}`), [
    "crates.io:serde@1.0.100",
    "crates.io:time@0.1.40"
  ]);
});

test("recognises supported lockfiles only", () => {
  assert.equal(isSupportedLockfile("a/b/package-lock.json"), true);
  assert.equal(isSupportedLockfile("requirements-dev.txt"), true);
  assert.equal(isSupportedLockfile("package.json"), false);
});

test("computes CVSS v3 base scores", () => {
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(severityOf({ database_specific: { severity: "MODERATE" } }).severity, "medium");
});

test("picks the lowest fixed version above the installed one", () => {
  const vuln = {
    affected: [
      { package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.12" }] }] },
      { package: { name: "lodash" }, ranges: [{ events: [{ introduced: "4.17.13" }, { fixed: "4.17.21" }] }] }
    ]
  };
  assert.equal(fixedVersionFor(vuln, { name: "lodash", version: "4.17.15" }), "4.17.21");
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
});

test("builds dependency findings with upgrade advice", () => {
  const pkg = { name: "lodash", version: "4.17.15", ecosystem: "npm", line: 12, dev: false };
  const osvResult = new Map([
    [
      "npm|lodash|4.17.15",
      [
        {
          id: "GHSA-p6mc-m468-83gw",
          aliases: ["CVE-2020-8203"],
          summary: "Prototype Pollution in lodash",
          database_specific: { severity: "HIGH", cwe_ids: ["CWE-1321"] },
          affected: [{ package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }] }]
        }
      ]
    ]
  ]);
  const [finding] = buildDependencyFindings({ file: "package-lock.json", packages: [pkg], osvResult, source: "current" });
  assert.equal(finding.category, "dependency-cve");
  assert.equal(finding.severity, "high");
  assert.equal(finding.package.fixedVersion, "4.17.19");
  assert.equal(finding.package.upgrade, "npm install lodash@4.17.19");
  assert.deepEqual(finding.possibleCves, ["CVE-2020-8203"]);
  assert.equal(finding.cwe, "CWE-1321");
});

test("exports SARIF with relative paths and masked messages only", () => {
  const result = {
    findings: [
      { ...base, id: "1", fingerprint: "fp1", repository: "o/r", file: "o/r/src/a.js", line: 3, advice: "rotate" }
    ]
  };
  const sarif = toSarif(result);
  assert.equal(sarif.version, "2.1.0");
  const r = sarif.runs[0].results[0];
  assert.equal(r.level, "error");
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, "src/a.js");
  assert.equal(r.partialFingerprints.primaryLocationLineHash, "fp1");
  assert.match(r.message.text, /abcd\.\.\.wxyz/);
  assert.equal(relativePath({ file: "x\\y.js" }), "x/y.js");
});

test("CSV export escapes fields and threshold check works", () => {
  const result = { findings: [{ ...base, id: "1", severity: "medium", file: "a.js", label: 'say "hi", ok' }] };
  assert.match(toCsv(result), /"say ""hi"", ok"/);
  assert.equal(failsThreshold(result, "high"), false);
  assert.equal(failsThreshold(result, "medium"), true);
});
