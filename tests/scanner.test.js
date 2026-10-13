import test from "node:test";
import assert from "node:assert/strict";
import { aiRepositoryScore, classifyRiskFile, parseGitHubTarget, scanLine, scanVulnerabilityLine, secretRules } from "../server/scanner.js";

// Sample (non-real) secrets assembled at runtime so the literals never appear
// in source and GitHub push protection does not flag these test fixtures.
const SAMPLE_GH_TOKEN = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"].join("_");
const SAMPLE_DS_KEY = ["sk", "abcdef1234567890abcdef1234567890"].join("-");
const SAMPLE_HF_TOKEN = ["hf", "abcdefghijklmnopqrstuvwxyzABCDEFGH"].join("_");
const SAMPLE_GITLAB_PAT = ["glpat", "abcdefghijklmnopqrstuvwxyz"].join("-");
const SAMPLE_STRIPE_PK = ["pk", "live", "abcdefghijklmnopqrstuvwxyz123456"].join("_");

test("detects and redacts a GitHub token", () => {
  const findings = scanLine({
    line: `GITHUB_TOKEN=${SAMPLE_GH_TOKEN}`,
    file: ".env",
    lineNumber: 1,
    source: "current"
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "github-classic-token");
  assert.equal(findings[0].stage, "token-pattern");
  assert.equal(findings[0].masked, "ghp_...GHIJ");
  assert.equal(findings[0].context.includes("abcdefghijklmnopqrstuvwxyz"), false);
  assert.equal(findings[0].exploitability.confidence, "high");
  assert.equal(findings[0].exploitability.safeTests.some((test) => test.result === "not_run"), true);
});

test("detects generic high entropy assigned secrets", () => {
  const findings = scanLine({
    line: "CLIENT_SECRET='N9tM8sdP4xT6vK2qR7zY1nL5cH3bW0aE'",
    file: "config.js",
    lineNumber: 8,
    source: "current"
  });

  const genericFinding = findings.find((finding) => finding.ruleId === "generic-high-entropy-secret");
  assert.equal(Boolean(genericFinding), true);
  assert.equal(genericFinding.stage, "entropy-context");
});

test("detects AI provider and database-specific secret rules", () => {
  const findings = [
    ...scanLine({
      line: `HUGGINGFACE_TOKEN=${SAMPLE_HF_TOKEN}`,
      file: ".env",
      lineNumber: 1,
      source: "current"
    }),
    ...scanLine({
      line: "DATABASE_URL=postgres://app:superSecretPassword123@db.production.internal:5432/prod",
      file: ".env",
      lineNumber: 2,
      source: "current"
    }),
    ...scanLine({
      line: `DEEPSEEK_API_KEY=${SAMPLE_DS_KEY}`,
      file: ".env",
      lineNumber: 3,
      source: "current"
    })
  ];

  assert.equal(findings.some((finding) => finding.ruleId === "huggingface-token"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "database-url-with-password"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "deepseek-api-key"), true);
});

test("loads Coff0xc supplemental provider rules with metadata", () => {
  assert.equal(secretRules.length >= 120, true);
  const gitlabFinding = scanLine({
    line: `GITLAB_TOKEN=${SAMPLE_GITLAB_PAT}`,
    file: ".env",
    lineNumber: 5,
    source: "current"
  })[0];

  assert.equal(gitlabFinding.ruleId, "coff0xc-gitlab-pat");
  assert.equal(gitlabFinding.provider, "gitlab");
  assert.equal(gitlabFinding.category, "devops");
  assert.equal(gitlabFinding.evidenceLevel, "confirmed_pattern");
});

test("requires context for broad Coff0xc-style hash patterns", () => {
  const plainHashFindings = scanLine({
    line: "CHECKSUM=0123456789abcdef0123456789abcdef",
    file: "build.js",
    lineNumber: 6,
    source: "current"
  });
  const datadogFindings = scanLine({
    line: "DATADOG_API_KEY=0123456789abcdef0123456789abcdef",
    file: ".env",
    lineNumber: 7,
    source: "current"
  });

  assert.equal(plainHashFindings.some((finding) => finding.ruleId === "coff0xc-datadog-api"), false);
  assert.equal(datadogFindings.some((finding) => finding.provider === "datadog"), true);
});

test("marks public identifiers as non-actionable", () => {
  const findings = scanLine({
    line: `NEXT_PUBLIC_STRIPE_KEY=${SAMPLE_STRIPE_PK}`,
    file: ".env",
    lineNumber: 8,
    source: "current"
  });

  const publishable = findings.find((finding) => finding.ruleId === "coff0xc-stripe-publishable");
  assert.equal(Boolean(publishable), true);
  assert.equal(publishable.actionable, false);
});

test("keeps generic assigned-secret rule stricter than plain service URLs", () => {
  const findings = scanLine({
    line: "API_URL=https://api.openai.com/v1/chat/completions",
    file: "config.js",
    lineNumber: 4,
    source: "current"
  });

  assert.equal(findings.length, 0);
});

test("matches dependency CVE rules from file content", () => {
  const findings = scanVulnerabilityLine({
    line: '<artifactId>log4j-core</artifactId><version>2.14.1</version>',
    file: "pom.xml",
    lineNumber: 22,
    source: "current"
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "cve-log4shell-log4j-core");
  assert.equal(findings[0].stage, "vulnerability-pattern");
  assert.equal(findings[0].possibleCves.includes("CVE-2021-44228"), true);
  assert.equal(findings[0].cwe, "CWE-502");
  assert.equal(findings[0].exploitability.safeTests.some((test) => test.name === "CVE/CWE 映射" && test.result === "passed"), true);
});

test("matches dangerous code vulnerability patterns", () => {
  const findings = scanLine({
    line: "exec(`convert ${req.query.file}`)",
    file: "server.js",
    lineNumber: 11,
    source: "current"
  });

  const commandInjection = findings.find((finding) => finding.ruleId === "cwe-command-injection");
  assert.equal(Boolean(commandInjection), true);
  assert.equal(commandInjection.severity, "high");
  assert.equal(commandInjection.cwe, "CWE-78");
});

test("does not match safe parameterized SQL", () => {
  const findings = scanVulnerabilityLine({
    line: "db.query('select * from users where id = ?', [userId])",
    file: "db.js",
    lineNumber: 4,
    source: "current"
  });

  assert.equal(findings.length, 0);
});

test("preserves GitHub file location URLs on findings", () => {
  const fileUrl = "https://github.com/example/ai-app/blob/main/.env#L1";
  const findings = scanLine({
    line: `GITHUB_TOKEN=${SAMPLE_GH_TOKEN}`,
    file: "example/ai-app/.env",
    fileUrl,
    lineNumber: 1,
    source: "github",
    repository: "example/ai-app"
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].fileUrl, fileUrl);
  assert.equal(findings[0].exploitability.safeTests.some((test) => test.name === "公开定位证据" && test.result === "passed"), true);
});


test("ignores obvious placeholders", () => {
  const findings = scanLine({
    line: "token=your_token_here",
    file: "README.md",
    lineNumber: 4,
    source: "current"
  });

  assert.equal(findings.length, 0);
});

test("parses GitHub account and repository targets", () => {
  assert.deepEqual(parseGitHubTarget("https://github.com"), {
    type: "explore",
    display: "GitHub AI public repositories"
  });

  assert.deepEqual(parseGitHubTarget("github:explore"), {
    type: "explore",
    display: "GitHub AI public repositories"
  });

  assert.deepEqual(parseGitHubTarget("https://github.com/lzwhehe"), {
    type: "account",
    owner: "lzwhehe",
    display: "https://github.com/lzwhehe"
  });

  assert.deepEqual(parseGitHubTarget("https://github.com/lzwhehe/token-guardian.git"), {
    type: "repo",
    owner: "lzwhehe",
    repo: "token-guardian",
    display: "https://github.com/lzwhehe/token-guardian"
  });
});

test("prioritizes small AI repositories over high-star mature projects", () => {
  const smallRepoScore = aiRepositoryScore(
    {
      name: "openai-agent-demo",
      description: "small langchain rag starter",
      topics: ["llm", "ai-agent"],
      stargazers_count: 3,
      size: 1200,
      pushed_at: new Date().toISOString()
    },
    "topic:llm stars:0..50"
  );
  const matureRepoScore = aiRepositoryScore(
    {
      name: "enterprise-ml-platform",
      description: "large machine learning platform",
      topics: ["machine-learning"],
      stargazers_count: 50_000,
      size: 250_000,
      pushed_at: new Date().toISOString()
    },
    "topic:machine-learning"
  );

  assert.equal(smallRepoScore > matureRepoScore, true);
});

test("classifies risky GitHub file paths", () => {
  assert.equal(classifyRiskFile(".env")?.id, "committed-env-file");
  assert.equal(classifyRiskFile("keys/prod.pem")?.id, "private-key-file");
  assert.equal(classifyRiskFile(".npmrc")?.id, "platform-credential-file");
  assert.equal(classifyRiskFile("config/litellm_config.yaml")?.id, "ai-provider-config-file");
  assert.equal(classifyRiskFile(".venv/lib/python/site-packages/certifi/cacert.pem"), undefined);
  assert.equal(classifyRiskFile(".env.example"), undefined);
});
