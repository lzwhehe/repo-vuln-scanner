import test from "node:test";
import assert from "node:assert/strict";
import { mergeScanIntoVault } from "../server/vault.js";

const baseFinding = {
  id: "github-token-demo",
  ruleId: "github-classic-token",
  label: "GitHub classic token",
  severity: "critical",
  stage: "token-pattern",
  repository: "example/ai-app",
  file: "example/ai-app/.env",
  fileUrl: "https://github.com/example/ai-app/blob/main/.env#L1",
  line: 1,
  source: "github",
  masked: "ghp_...GHIJ",
  context: "GITHUB_TOKEN=ghp_...GHIJ",
  exploitability: { confidence: "high" },
  verification: { status: "not_checked" }
};

const baseProject = {
  name: "example/ai-app",
  url: "https://github.com/example/ai-app",
  severity: "critical",
  findingCount: 1,
  files: ["example/ai-app/.env"],
  fileLocations: [
    {
      path: "example/ai-app/.env",
      displayPath: ".env",
      url: "https://github.com/example/ai-app/blob/main/.env#L1",
      severity: "critical",
      findingCount: 1,
      lines: [1]
    }
  ],
  rules: ["GitHub classic token"],
  stages: ["token-pattern"]
};

test("persists sanitized findings and projects into the vault", () => {
  const vault = mergeScanIntoVault(undefined, {
    target: "github:explore",
    mode: "github-ai-explore",
    scannedAt: "2026-05-29T00:00:00.000Z",
    durationMs: 1200,
    summary: { total: 1, critical: 1 },
    findings: [baseFinding],
    riskProjects: [baseProject],
    repositories: [{ name: "example/ai-app" }]
  });

  assert.equal(vault.vulnerabilityCount, 1);
  assert.equal(vault.projectCount, 1);
  assert.equal(vault.scanCount, 1);
  assert.equal(vault.findings[0].masked, "ghp_...GHIJ");
  assert.equal(vault.findings[0].secret, undefined);
  assert.equal(vault.projects[0].fileLocations[0].displayPath, ".env");
});

test("deduplicates repeated findings and increments occurrences", () => {
  const first = mergeScanIntoVault(undefined, {
    target: "github:explore",
    scannedAt: "2026-05-29T00:00:00.000Z",
    summary: { total: 1 },
    findings: [baseFinding],
    riskProjects: [baseProject]
  });
  const second = mergeScanIntoVault(first, {
    target: "github:explore",
    scannedAt: "2026-05-29T01:00:00.000Z",
    summary: { total: 1 },
    findings: [baseFinding],
    riskProjects: [baseProject]
  });

  assert.equal(second.vulnerabilityCount, 1);
  assert.equal(second.findings[0].occurrences, 2);
  assert.equal(second.projects[0].occurrences, 2);
});
