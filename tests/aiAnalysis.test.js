import test from "node:test";
import assert from "node:assert/strict";
import { groupHighRiskFindings } from "../server/aiAnalysis.js";

test("groups high-risk findings by repository and file", () => {
  const groups = groupHighRiskFindings([
    {
      key: "one",
      repository: "example/ai-app",
      file: "example/ai-app/.env",
      severity: "critical",
      stage: "token-pattern",
      label: "GitHub token"
    },
    {
      key: "two",
      repository: "example/ai-app",
      file: "example/ai-app/.env",
      severity: "high",
      stage: "entropy-context",
      label: "High entropy secret"
    },
    {
      key: "three",
      repository: "example/ai-app",
      file: "example/ai-app/README.md",
      severity: "low",
      stage: "token-pattern",
      label: "Ignored low risk"
    }
  ]);

  assert.equal(groups.length, 1);
  assert.equal(groups[0].file, "example/ai-app/.env");
  assert.equal(groups[0].severity, "critical");
  assert.equal(groups[0].findings.length, 2);
});

test("does not analyze risk-file-name findings without credential evidence", () => {
  const groups = groupHighRiskFindings([
    {
      key: "compose",
      repository: "example/router",
      file: "example/router/docker-compose.yml",
      severity: "low",
      stage: "risk-file-name",
      label: "Cloud configuration file",
      evidenceLevel: "candidate"
    }
  ]);

  assert.equal(groups.length, 0);
});
