import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import * as tar from "tar";
import { coff0xcSupplementalRules } from "./rules/providerRules.js";
import { coff0xcSearchQueries } from "./rules/searchKeywords.js";
import { vulnerabilityRules } from "./rules/vulnerabilityRules.js";
import { applyNoiseFilters } from "./noise.js";
import { isSupportedLockfile, scanDependencies } from "./osv.js";

const execFileAsync = promisify(execFile);

const SKIPPED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".vercel",
  "coverage",
  "vendor",
  ".scanner-tmp"
]);

const SKIPPED_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".icns",
  ".pdf",
  ".zip",
  ".gz",
  ".tgz",
  ".7z",
  ".mp4",
  ".mov",
  ".mp3",
  ".wav",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot"
]);

const DEFAULT_GITHUB_REPOSITORY_LIMIT = 60;
const MAX_GITHUB_REPOSITORY_LIMIT = 500;
const DEFAULT_GITHUB_FILES_PER_REPO = 80;
const MAX_GITHUB_FILES_PER_REPO = 300;
const GITHUB_EXPLORE_QUERY_PAGE_LIMIT = 3;

const builtinSecretRules = [
  {
    id: "github-classic-token",
    label: "GitHub classic token",
    severity: "critical",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g,
    advice: "Revoke the token in GitHub Developer settings, then create a scoped replacement."
  },
  {
    id: "github-fine-grained-token",
    label: "GitHub fine-grained token",
    severity: "critical",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
    advice: "Revoke the fine-grained PAT and check repository access scopes."
  },
  {
    id: "openai-api-key",
    label: "OpenAI API key",
    severity: "critical",
    pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,255}\b/g,
    excludeContextPattern: /deepseek/i,
    advice: "Rotate the API key in the provider dashboard and audit recent usage."
  },
  {
    id: "anthropic-api-key",
    label: "Anthropic API key",
    severity: "critical",
    pattern: /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{40,255}\b/g,
    advice: "Rotate the Anthropic API key and review recent API usage."
  },
  {
    id: "deepseek-api-key",
    label: "DeepSeek API key",
    severity: "critical",
    pattern: /\bsk-[a-f0-9]{32}\b/gi,
    contextPattern: /(deepseek|api[_-]?key|secret|token)/i,
    advice: "Rotate the DeepSeek key and audit provider usage."
  },
  {
    id: "huggingface-token",
    label: "Hugging Face token",
    severity: "critical",
    pattern: /\bhf_[A-Za-z0-9]{30,255}\b/g,
    advice: "Revoke the Hugging Face token and check model/dataset access."
  },
  {
    id: "replicate-api-token",
    label: "Replicate API token",
    severity: "critical",
    pattern: /\br8_[A-Za-z0-9]{30,255}\b/g,
    advice: "Rotate the Replicate token and review API usage."
  },
  {
    id: "groq-api-key",
    label: "Groq API key",
    severity: "critical",
    pattern: /\bgsk_[A-Za-z0-9]{30,255}\b/g,
    advice: "Rotate the Groq API key and review recent model calls."
  },
  {
    id: "pinecone-api-key",
    label: "Pinecone API key",
    severity: "critical",
    pattern: /\bpcsk_[A-Za-z0-9_-]{30,255}\b/g,
    advice: "Rotate the Pinecone API key and check index access permissions."
  },
  {
    id: "langsmith-api-key",
    label: "LangSmith API key",
    severity: "high",
    pattern: /\blsv2_pt_[A-Za-z0-9_-]{20,255}\b/g,
    advice: "Rotate the LangSmith key and review tracing/project access."
  },
  {
    id: "perplexity-api-key",
    label: "Perplexity API key",
    severity: "critical",
    pattern: /\bpplx-[A-Za-z0-9_-]{30,255}\b/g,
    advice: "Rotate the Perplexity API key and audit usage."
  },
  {
    id: "aws-access-key",
    label: "AWS access key id",
    severity: "high",
    pattern: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA)[A-Z0-9]{16}\b/g,
    advice: "Deactivate the IAM access key, rotate dependent credentials, and review CloudTrail."
  },
  {
    id: "aws-secret-access-key",
    label: "AWS secret access key",
    severity: "critical",
    pattern: /\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    secretGroup: 1,
    advice: "Rotate the AWS access key pair and review CloudTrail for the exposed principal."
  },
  {
    id: "google-api-key",
    label: "Google API key",
    severity: "high",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    advice: "Restrict or rotate the Google API key in Google Cloud Console."
  },
  {
    id: "google-service-account-key",
    label: "Google service account private key",
    severity: "critical",
    pattern: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g,
    advice: "Delete and recreate the service account key, then audit service account permissions."
  },
  {
    id: "azure-storage-key",
    label: "Azure storage account key",
    severity: "critical",
    pattern: /\b(?:account[_-]?key|azure[_-]?storage[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9+/]{80,}={0,2})["']?/gi,
    secretGroup: 1,
    advice: "Rotate the Azure storage account key and prefer managed identity where possible."
  },
  {
    id: "slack-token",
    label: "Slack token",
    severity: "critical",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,80}\b/g,
    advice: "Revoke the Slack token and reinstall or rotate the app credentials."
  },
  {
    id: "slack-webhook-url",
    label: "Slack webhook URL",
    severity: "high",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    advice: "Revoke the Slack incoming webhook and create a new scoped webhook."
  },
  {
    id: "stripe-secret-key",
    label: "Stripe secret key",
    severity: "critical",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{24,255}\b/g,
    advice: "Roll the Stripe secret key and check dashboard events for suspicious activity."
  },
  {
    id: "discord-bot-token",
    label: "Discord bot token",
    severity: "critical",
    pattern: /\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g,
    advice: "Reset the Discord bot token in the developer portal."
  },
  {
    id: "discord-webhook-url",
    label: "Discord webhook URL",
    severity: "high",
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g,
    advice: "Delete the Discord webhook and recreate it with minimum channel scope."
  },
  {
    id: "npm-token",
    label: "npm access token",
    severity: "critical",
    pattern: /\bnpm_[A-Za-z0-9]{36,255}\b/g,
    advice: "Revoke the npm token and review package publish activity."
  },
  {
    id: "pypi-token",
    label: "PyPI API token",
    severity: "critical",
    pattern: /\bpypi-[A-Za-z0-9_-]{50,255}\b/g,
    advice: "Revoke the PyPI token and review package release history."
  },
  {
    id: "dockerhub-token",
    label: "Docker Hub access token",
    severity: "high",
    pattern: /\bdckr_pat_[A-Za-z0-9_-]{20,255}\b/g,
    advice: "Revoke the Docker Hub token and review image push history."
  },
  {
    id: "sendgrid-api-key",
    label: "SendGrid API key",
    severity: "critical",
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
    advice: "Rotate the SendGrid key and inspect recent mail sending activity."
  },
  {
    id: "database-url-with-password",
    label: "Database URL with password",
    severity: "critical",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^:\s/@]+:[^@\s/]+@[^\s"'<>]+/gi,
    advice: "Rotate the database password and enforce network and role-level restrictions."
  },
  {
    id: "jwt",
    label: "JWT",
    severity: "medium",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    advice: "Treat committed JWTs as exposed and rotate the signing/session material if needed."
  },
  {
    id: "private-key",
    label: "Private key block",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    advice: "Remove the private key from the repository and replace it everywhere it was trusted."
  }
];

export const secretRules = dedupeRules([...builtinSecretRules, ...coff0xcSupplementalRules]);

const genericSecretPattern =
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|refresh[_-]?token|secret|client[_-]?secret|private[_-]?key|password|passwd|pwd|webhook[_-]?secret|signing[_-]?secret|jwt[_-]?secret|session[_-]?secret)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=:@-]{24,240})["']?/gi;

const riskFileRules = [
  {
    id: "committed-env-file",
    label: "Committed environment file",
    severity: "high",
    pattern: /(^|\/)\.env(?:\.[^/]*)?$/i,
    ignore: /\.(example|sample|template|dist)$/i,
    context: "Environment-style file is committed in a GitHub repository.",
    advice: "Move real values into GitHub Actions secrets or a secret manager, then rotate any value that was committed."
  },
  {
    id: "credential-file",
    label: "Credential-looking file",
    severity: "high",
    pattern: /(^|\/)(credentials?|secrets?|service-account|firebase-adminsdk|google-services|GoogleService-Info|auth|token|apikey|api-key|keyring)[^/]*\.(json|ya?ml|toml|ini|env|plist|cfg|conf)$/i,
    context: "Credential-looking file was found in the repository tree.",
    advice: "Review whether this file contains real credentials. If it does, remove it and rotate the exposed secret."
  },
  {
    id: "platform-credential-file",
    label: "Platform credential file",
    severity: "critical",
    pattern: /(^|\/)(\.npmrc|\.pypirc|\.netrc|\.dockercfg|\.docker\/config\.json|\.aws\/credentials|\.aws\/config|\.kube\/config|kubeconfig|terraform\.tfvars|[^/]+\.tfvars|[^/]+\.tfstate)$/i,
    ignore: /\.(example|sample|template|dist)$/i,
    context: "Platform credential/config file was committed in the repository tree.",
    advice: "Rotate any credentials referenced by this file and replace committed local credential files with secret-manager references."
  },
  {
    id: "private-key-file",
    label: "Private key file",
    severity: "critical",
    pattern: /(^|\/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|[^/]+\.(pem|key|p12|pfx|asc))$/i,
    ignore: /(^|\/)(cacert|cert|certificate|ca-bundle|bundle)\.pem$/i,
    context: "Private-key-looking file was found in the repository tree.",
    advice: "Treat committed private keys as compromised. Replace the key material everywhere it was trusted."
  },
  {
    id: "cloud-config-risk-file",
    label: "Cloud configuration file",
    severity: "medium",
    pattern: /(^|\/)(application|appsettings|docker-compose|compose|serverless|sam|terraform|provider|variables|pulumi\.[^/]+|cloudbuild|skaffold|helmfile)\.(json|ya?ml|toml|properties|tf)$/i,
    context: "Configuration file often carries credentials or deployment tokens.",
    advice: "Check the file for inline credentials and move sensitive values to managed secrets."
  },
  {
    id: "ai-provider-config-file",
    label: "AI provider configuration file",
    severity: "high",
    pattern: /(^|\/)(litellm|langchain|langsmith|openai|anthropic|deepseek|huggingface|replicate|pinecone|weaviate|qdrant|milvus|chroma)[^/]*\.(json|ya?ml|toml|ini|env|properties)$/i,
    ignore: /\.(example|sample|template|dist)$/i,
    context: "AI/LLM provider config file may carry API keys, vector DB credentials, or tracing tokens.",
    advice: "Move provider keys and vector database credentials to managed secrets and rotate exposed values."
  }
];

const SCANNABLE_SOURCE_EXTENSIONS = new Set([
  ".env",
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".cfg",
  ".conf",
  ".toml",
  ".ini",
  ".properties",
  ".py",
  ".rb",
  ".php",
  ".go",
  ".java",
  ".cs",
  ".rs",
  ".swift",
  ".kt",
  ".sh",
  ".bash",
  ".zsh",
  ".md",
  ".txt",
  ".ipynb",
  ".plist",
  ".gradle",
  ".kts",
  ".sql",
  ".http",
  ".xml",
  ".lock"
]);

const pipelineStages = [
  {
    id: "risk-file-name",
    label: "风险文件名",
    description: "先用文件名和路径找 .env、私钥、凭证、云配置等高风险位置。"
  },
  {
    id: "token-pattern",
    label: "Token pattern",
    description: "再用精确正则匹配 GitHub、OpenAI、AWS、Slack、Stripe 等常见 token。"
  },
  {
    id: "entropy-context",
    label: "Entropy/context",
    description: "再结合变量名、上下文和字符串熵判断疑似 secret。"
  },
  {
    id: "vulnerability-pattern",
    label: "漏洞/CVE 规则",
    description: "根据依赖版本、危险 API、配置和用户输入流匹配可能 CVE/CWE 漏洞。"
  },
  {
    id: "validity-check",
    label: "Validity check",
    description: "可插拔验证阶段，默认关闭，避免滥用第三方 API 验证他人 token。"
  }
];

export async function scanTarget(target, options = {}) {
  const startedAt = Date.now();

  if (options.githubApiMode) {
    return scanGitHubRiskTarget(target, {
      githubToken: options.githubToken || process.env.GITHUB_TOKEN,
      maxRepositories: options.maxRepositories,
      maxFilesPerRepo: options.maxFilesPerRepo,
      scanTheme: options.scanTheme,
      enableValidityCheck: options.enableValidityCheck
    });
  }

  const targetInfo = await prepareTarget(target, options);
  const findings = [];
  let dependency;

  try {
    const scanned = await scanDirectory(targetInfo.path);
    findings.push(...scanned.findings);
    dependency = scanned.dependency;

    if (options.scanHistory) {
      const historyFindings = await scanGitHistory(
        targetInfo.path,
        Number(options.maxHistoryCommits || 200)
      );
      findings.push(...historyFindings);
    }
  } finally {
    if (targetInfo.cleanupPath) {
      await fs.rm(targetInfo.cleanupPath, { recursive: true, force: true });
    }
  }

  return finalizeScanResult({
    target: targetInfo.display,
    mode: targetInfo.mode,
    durationMs: Date.now() - startedAt,
    findings,
    summaryExtras: { dependencyScan: dependencySummary([dependency]) }
  });
}

export async function scanCurrentFiles(rootDir) {
  return (await scanDirectory(rootDir)).findings;
}

async function scanDirectory(rootDir) {
  const files = await collectFiles(rootDir);
  const findings = [];
  const manifests = [];

  for (const absoluteFile of files) {
    const relativeFile = path.relative(rootDir, absoluteFile);
    const text = await readTextFile(absoluteFile);
    if (text === null) continue;
    if (isSupportedLockfile(relativeFile)) {
      manifests.push({ path: relativeFile, file: relativeFile, text, source: "current" });
    }

    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      findings.push(
        ...scanLine({
          line,
          file: relativeFile,
          lineNumber: index + 1,
          source: "current"
        })
      );
    });
  }

  const dependency = await scanDependencies(manifests);
  return { findings: mergeDependencyFindings(findings, dependency), dependency };
}

// OSV 查询成功时用它的结果替换内置的静态依赖规则；失败时保留静态规则结果作为兜底
function mergeDependencyFindings(findings, dependency) {
  if (!dependency?.ok || !dependency.files.length) return findings;
  return [
    ...findings.filter((finding) => !(finding.category === "dependency-cve" && finding.sourceRuleSet !== "osv")),
    ...dependency.findings
  ];
}

function dependencySummary(statuses) {
  const list = statuses.filter(Boolean);
  if (!list.length) return undefined;
  const errors = list.filter((s) => !s.ok).map((s) => s.error);
  return {
    source: errors.length && errors.length === list.length ? "静态规则（OSV 不可用）" : "OSV.dev",
    ok: errors.length === 0,
    lockfiles: list.reduce((n, s) => n + s.files.length, 0),
    packages: list.reduce((n, s) => n + s.packages, 0),
    vulnerablePackages: list.reduce((n, s) => n + s.vulnerable, 0),
    error: errors[0]
  };
}

export async function scanGitHistory(repoPath, maxCommits = 200) {
  if (!(await isGitRepo(repoPath))) return [];

  const { stdout } = await execFileAsync(
    "git",
    ["-C", repoPath, "rev-list", "--all", `--max-count=${maxCommits}`],
    { maxBuffer: 10 * 1024 * 1024 }
  );
  const commits = stdout.trim().split(/\s+/).filter(Boolean);
  const findings = [];

  for (const commit of commits) {
    const patch = await gitShowPatch(repoPath, commit);
    let file = "unknown";
    let newLine = 0;
    let oldLine = 0;

    for (const rawLine of patch.split(/\r?\n/)) {
      if (rawLine.startsWith("diff --git ")) {
        const match = rawLine.match(/^diff --git a\/(.+?) b\/(.+)$/);
        file = match?.[2] || file;
        continue;
      }

      if (rawLine.startsWith("@@")) {
        const match = rawLine.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
        oldLine = match ? Number(match[1]) : 0;
        newLine = match ? Number(match[2]) : 0;
        continue;
      }

      if (rawLine.startsWith("+++") || rawLine.startsWith("---")) continue;

      if (rawLine.startsWith("+") || rawLine.startsWith("-")) {
        const sign = rawLine[0];
        const content = rawLine.slice(1);
        const lineNumber = sign === "+" ? newLine : oldLine;
        findings.push(
          ...scanLine({
            line: content,
            file,
            lineNumber: lineNumber || undefined,
            source: "history",
            commit
          })
        );
        if (sign === "+") newLine += 1;
        if (sign === "-") oldLine += 1;
      } else if (rawLine.length > 0) {
        newLine += 1;
        oldLine += 1;
      }
    }
  }

  return findings;
}

export function scanLine({ line, file, lineNumber, source, commit, repository, fileUrl }) {
  const findings = [];
  const matchedSecretFingerprints = new Set();
  const matchedValueFingerprints = new Set();

  for (const rule of secretRules) {
    rule.pattern.lastIndex = 0;
    for (const match of line.matchAll(rule.pattern)) {
      if (rule.excludeContextPattern) {
        rule.excludeContextPattern.lastIndex = 0;
        if (rule.excludeContextPattern.test(line)) continue;
      }
      if (rule.contextPattern) {
        rule.contextPattern.lastIndex = 0;
        if (!rule.contextPattern.test(line)) continue;
      }
      const secret = match[rule.secretGroup || 0];
      if (!shouldReportSecret(secret)) continue;
      const secretKey = fingerprint(secret);
      if (matchedSecretFingerprints.has(secretKey)) continue;
      matchedSecretFingerprints.add(secretKey);
      matchedValueFingerprints.add(fingerprint(secret));
      findings.push(
        buildFinding({
          rule,
          secret,
          line,
          file,
          lineNumber,
          source,
          commit,
          repository,
          fileUrl,
          stage: "token-pattern"
        })
      );
    }
  }

  if (findings.length) return findings;

  genericSecretPattern.lastIndex = 0;
  for (const match of line.matchAll(genericSecretPattern)) {
    const secret = match[1];
    if (!shouldReportGeneric(secret)) continue;
    if (matchedValueFingerprints.has(fingerprint(secret))) continue;
    findings.push(
      buildFinding({
        rule: {
          id: "generic-high-entropy-secret",
          label: "High-entropy assigned secret",
          severity: "medium",
          provider: "generic",
          category: "generic",
          evidenceLevel: "generic_entropy",
          advice: "Move this value into a secret manager or environment variable, then rotate it if it was real."
        },
        secret,
        line,
        file,
        lineNumber,
        source,
        commit,
        repository,
        fileUrl,
        stage: "entropy-context"
      })
    );
  }

  findings.push(
    ...scanVulnerabilityLine({
      line,
      file,
      lineNumber,
      source,
      commit,
      repository,
      fileUrl
    })
  );

  return findings;
}

export function scanVulnerabilityLine({ line, file, lineNumber, source, commit, repository, fileUrl }) {
  const findings = [];
  const normalizedFile = String(file || "").replace(/\\/g, "/");

  for (const rule of vulnerabilityRules) {
    if (rule.filePattern && !rule.filePattern.test(normalizedFile)) continue;
    if (rule.excludeFilePattern && rule.excludeFilePattern.test(normalizedFile)) continue;
    rule.pattern.lastIndex = 0;
    if (!rule.pattern.test(line)) continue;
    findings.push(
      buildVulnerabilityFinding({
        rule,
        line,
        file,
        lineNumber,
        source,
        commit,
        repository,
        fileUrl
      })
    );
  }

  return findings;
}

export async function scanGitHubRiskTarget(target, options = {}) {
  const startedAt = Date.now();
  const parsed = parseGitHubTarget(target);
  if (!parsed) {
    throw new Error("Please provide a GitHub user, organization, or repository URL.");
  }

  const headers = makeGitHubHeaders(options.githubToken);
  const maxRepositories = clampNumber(
    options.maxRepositories,
    1,
    MAX_GITHUB_REPOSITORY_LIMIT,
    DEFAULT_GITHUB_REPOSITORY_LIMIT
  );
  const maxFilesPerRepo = clampNumber(
    options.maxFilesPerRepo,
    10,
    MAX_GITHUB_FILES_PER_REPO,
    DEFAULT_GITHUB_FILES_PER_REPO
  );
  const scanTheme = options.scanTheme || "ai";

  const repositories =
    parsed.type === "repo"
      ? [await fetchGitHubRepo(parsed.owner, parsed.repo, headers)]
      : parsed.type === "explore"
        ? await explorePublicGitHubRepositories(headers, maxRepositories, scanTheme)
        : await listGitHubRepositories(parsed.owner, headers, maxRepositories);

  const findings = [];
  const repoResults = [];
  const dependencyStatuses = [];

  for (const repository of repositories.slice(0, maxRepositories)) {
    if (repository.archived || repository.disabled || !repository.default_branch) {
      repoResults.push({
        name: repository.full_name,
        url: repository.html_url,
        description: repository.description,
        language: repository.language,
        stars: repository.stargazers_count || 0,
        topics: repository.topics || [],
        updatedAt: repository.updated_at,
        scannedFiles: 0,
        riskFiles: 0,
        skipped: true,
        reason: !repository.default_branch ? "No default branch" : "Archived or disabled"
      });
      continue;
    }

    try {
      const repoResult = await scanGitHubRepository(repository, headers, maxFilesPerRepo);
      findings.push(...repoResult.findings);
      dependencyStatuses.push(repoResult.dependency);
      repoResults.push({
        name: repository.full_name,
        url: repository.html_url,
        description: repository.description,
        language: repository.language,
        stars: repository.stargazers_count || 0,
        topics: repository.topics || [],
        updatedAt: repository.updated_at,
        private: Boolean(repository.private),
        scannedFiles: repoResult.scannedFiles,
        riskFiles: repoResult.riskFiles,
        defaultBranch: repository.default_branch
      });
    } catch (error) {
      repoResults.push({
        name: repository.full_name,
        url: repository.html_url,
        description: repository.description,
        language: repository.language,
        stars: repository.stargazers_count || 0,
        topics: repository.topics || [],
        updatedAt: repository.updated_at,
        private: Boolean(repository.private),
        scannedFiles: 0,
        riskFiles: 0,
        defaultBranch: repository.default_branch,
        skipped: true,
        reason: error instanceof Error ? error.message : "Repository scan failed"
      });
    }
  }

  const uniqueFindings = annotateValidity(dedupeFindings(findings), {
    enabled: Boolean(options.enableValidityCheck)
  });
  const summary = summarize(uniqueFindings);
  summary.repositories = repoResults.filter((repo) => !repo.skipped).length;
  summary.scannedFiles = repoResults.reduce((total, repo) => total + repo.scannedFiles, 0);
  summary.riskFiles = repoResults.reduce((total, repo) => total + repo.riskFiles, 0);
  summary.skippedRepositories = repoResults.filter((repo) => repo.skipped).length;

  return finalizeScanResult({
    target: parsed.display,
    mode:
      parsed.type === "repo"
      ? "github-repository"
      : parsed.type === "explore"
          ? "github-ai-explore"
          : "github-account",
    durationMs: Date.now() - startedAt,
    findings: uniqueFindings,
    repositories: repoResults,
    validityEnabled: Boolean(options.enableValidityCheck),
    summaryExtras: {
      repositories: summary.repositories,
      scannedFiles: summary.scannedFiles,
      riskFiles: summary.riskFiles,
      skippedRepositories: summary.skippedRepositories,
      scanTheme: parsed.type === "explore" ? scanTheme : undefined,
      dependencyScan: dependencySummary(dependencyStatuses)
    }
  });
}

async function prepareTarget(target, options) {
  const trimmed = String(target || "").trim();
  if (!trimmed) {
    throw new Error("Please provide a local repository path or GitHub URL.");
  }

  if (isGitHubUrl(trimmed)) {
    if (options.preferGitHubArchive && options.scanHistory) {
      throw new Error("Hosted scans can inspect the current repository tree only. Git history scans are available in local mode.");
    }

    if (options.preferGitHubArchive) {
      return downloadGitHubArchive(trimmed, options.githubToken || process.env.GITHUB_TOKEN);
    }

    const tmpParent = await fs.mkdtemp(path.join(os.tmpdir(), "vulnerability-scanner-"));
    const checkoutPath = path.join(tmpParent, "repo");
    const cloneArgs = ["clone", "--quiet"];
    if (!options.scanHistory) cloneArgs.push("--depth", "1");
    cloneArgs.push(normalizeGitHubUrl(trimmed), checkoutPath);
    await execFileAsync("git", cloneArgs, { maxBuffer: 20 * 1024 * 1024 });
    return {
      path: checkoutPath,
      cleanupPath: tmpParent,
      display: trimmed,
      mode: "github"
    };
  }

  const resolved = path.resolve(trimmed);
  const stat = await fs.stat(resolved);
  if (!stat.isDirectory()) throw new Error("The target path must be a directory.");
  return {
    path: resolved,
    display: resolved,
    mode: "local"
  };
}

function isGitHubUrl(value) {
  return /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(?:\.git)?\/?$/.test(value) ||
    /^git@github\.com:[\w.-]+\/[\w.-]+(?:\.git)?$/.test(value);
}

function normalizeGitHubUrl(value) {
  if (value.startsWith("git@github.com:")) return value;
  return value.endsWith(".git") ? value : `${value.replace(/\/$/, "")}.git`;
}

function parseGitHubUrl(value) {
  const httpsMatch = value.match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/);
  if (httpsMatch) return { owner: httpsMatch[1], repo: httpsMatch[2] };

  const sshMatch = value.match(/^git@github\.com:([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  if (sshMatch) return { owner: sshMatch[1], repo: sshMatch[2] };

  return null;
}

export function parseGitHubTarget(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return null;

  if (/^(github:)?explore$/i.test(trimmed) || /^global$/i.test(trimmed)) {
    return { type: "explore", display: "GitHub AI public repositories" };
  }

  if (/^[\w.-]+\/[\w.-]+$/.test(trimmed)) {
    const [owner, repo] = trimmed.split("/");
    return { type: "repo", owner, repo, display: `https://github.com/${owner}/${repo}` };
  }

  if (/^[\w.-]+$/.test(trimmed)) {
    return { type: "account", owner: trimmed, display: `https://github.com/${trimmed}` };
  }

  const url = safeUrl(trimmed);
  if (!url || url.hostname !== "github.com") return null;

  const parts = url.pathname
    .replace(/\/+$/, "")
    .split("/")
    .filter(Boolean)
    .map((part) => part.replace(/\.git$/, ""));

  if (parts.length === 0) {
    return { type: "explore", display: "GitHub AI public repositories" };
  }

  if (parts.length === 1) {
    return { type: "account", owner: parts[0], display: `https://github.com/${parts[0]}` };
  }

  if (parts.length === 2) {
    return {
      type: "repo",
      owner: parts[0],
      repo: parts[1],
      display: `https://github.com/${parts[0]}/${parts[1]}`
    };
  }

  return null;
}

export function classifyRiskFile(filePath) {
  const normalized = String(filePath || "").replace(/\\/g, "/");
  return riskFileRules.find((rule) => {
    if (!rule.pattern.test(normalized)) return false;
    return !rule.ignore || !rule.ignore.test(normalized);
  });
}

async function scanGitHubRepository(repository, headers, maxFilesPerRepo) {
  const owner = repository.owner?.login;
  const repo = repository.name;
  const repositoryName = repository.full_name || `${owner}/${repo}`;
  const branch = repository.default_branch || "main";
  const tree = await fetchGitHubTree(owner, repo, branch, headers);
  const candidates = tree
    .filter((item) => item.type === "blob")
    .filter((item) => shouldScanGitHubPath(item.path, item.size))
    .sort((left, right) => candidateScore(right.path) - candidateScore(left.path))
    .slice(0, maxFilesPerRepo);

  const findings = [];
  const manifests = [];
  let scannedFiles = 0;
  let riskFiles = 0;

  for (const candidate of candidates) {
    const riskRule = classifyRiskFile(candidate.path);
    if (riskRule) {
      riskFiles += 1;
      findings.push(
        buildRiskFileFinding({
          rule: riskRule,
          repository: repositoryName,
          file: candidate.path,
          fileUrl: githubFileUrl(owner, repo, branch, candidate.path)
        })
      );
    }

    const text = await fetchGitHubFileContent(
      owner,
      repo,
      candidate.path,
      branch,
      headers
    );
    if (text === null) continue;

    scannedFiles += 1;
    if (isSupportedLockfile(candidate.path)) {
      manifests.push({
        path: candidate.path,
        file: `${repositoryName}/${candidate.path}`,
        text,
        source: "github",
        repository: repositoryName,
        fileUrl: (line) => githubFileUrl(owner, repo, branch, candidate.path, line)
      });
    }
    text.split(/\r?\n/).forEach((line, index) => {
      findings.push(
        ...scanLine({
          line,
          file: `${repositoryName}/${candidate.path}`,
          lineNumber: index + 1,
          source: "github",
          repository: repositoryName,
          fileUrl: githubFileUrl(owner, repo, branch, candidate.path, index + 1)
        })
      );
    });
  }

  const dependency = await scanDependencies(manifests);
  return { findings: mergeDependencyFindings(findings, dependency), scannedFiles, riskFiles, dependency };
}

async function fetchGitHubRepo(owner, repo, headers) {
  return githubJson(`https://api.github.com/repos/${owner}/${repo}`, headers, {
    notFoundMessage:
      "GitHub repository not found or not accessible. Public repositories work by default; private repositories require a GITHUB_TOKEN environment variable."
  });
}

async function listGitHubRepositories(owner, headers, maxRepositories) {
  const account = await githubJson(`https://api.github.com/users/${owner}`, headers, {
    notFoundMessage: "GitHub user or organization not found."
  });

  let endpoint;
  if (account.type === "Organization") {
    endpoint = `https://api.github.com/orgs/${owner}/repos?type=all&sort=updated&per_page=100`;
  } else {
    const viewer = await fetchGitHubViewer(headers);
    endpoint =
      viewer?.login?.toLowerCase() === owner.toLowerCase()
        ? "https://api.github.com/user/repos?visibility=all&affiliation=owner&sort=updated&per_page=100"
        : `https://api.github.com/users/${owner}/repos?type=owner&sort=updated&per_page=100`;
  }

  const repos = await githubPaginatedJson(endpoint, headers, maxRepositories);
  return repos
    .filter((repo) => repo && repo.owner?.login && repo.name)
    .sort((left, right) => new Date(right.updated_at || 0) - new Date(left.updated_at || 0));
}

async function explorePublicGitHubRepositories(headers, maxRepositories, scanTheme = "ai") {
  const perPage = Math.min(100, Math.max(Math.ceil(maxRepositories / 2), 30));
  const pushedSince = daysAgoDate(90);
  const queries =
    scanTheme === "ai"
      ? [
          `topic:artificial-intelligence is:public archived:false pushed:>${pushedSince}`,
          `topic:machine-learning is:public archived:false pushed:>${pushedSince}`,
          `topic:llm is:public archived:false pushed:>${pushedSince}`,
          `topic:large-language-models is:public archived:false pushed:>${pushedSince}`,
          `topic:generative-ai is:public archived:false pushed:>${pushedSince}`,
          `topic:rag is:public archived:false pushed:>${pushedSince}`,
          `topic:ai-agent is:public archived:false pushed:>${pushedSince}`,
          `topic:agents is:public archived:false pushed:>${pushedSince}`,
          `topic:langchain is:public archived:false pushed:>${pushedSince}`,
          `topic:openai is:public archived:false pushed:>${pushedSince}`,
          `topic:deepseek is:public archived:false pushed:>${pushedSince}`,
          `topic:huggingface is:public archived:false pushed:>${pushedSince}`,
          `topic:vector-database is:public archived:false pushed:>${pushedSince}`,
          `topic:chatbot is:public archived:false pushed:>${pushedSince}`,
          `topic:llm is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `topic:rag is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `topic:ai-agent is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `topic:openai is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `topic:deepseek is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `topic:huggingface is:public archived:false stars:0..50 pushed:>${pushedSince}`,
          `llm OR openai OR langchain OR rag in:name,description is:public archived:false pushed:>${pushedSince}`,
          `agent OR chatbot OR copilot in:name,description is:public archived:false pushed:>${pushedSince}`,
          `deepseek OR anthropic OR huggingface in:name,description is:public archived:false pushed:>${pushedSince}`,
          `llm OR openai OR langchain OR rag in:name,description is:public archived:false stars:0..25 pushed:>${pushedSince}`,
          `agent OR chatbot OR copilot in:name,description is:public archived:false stars:0..25 pushed:>${pushedSince}`,
          `embedding OR vector OR database OR rag in:name,description is:public archived:false pushed:>${pushedSince}`,
          ...repositorySearchQueriesFromCoff0xc(pushedSince)
        ]
      : [
          `is:public archived:false pushed:>${pushedSince}`,
          "is:public archived:false stars:>0"
        ];

  const discovered = new Map();

  for (const query of queries) {
    for (let page = 1; page <= GITHUB_EXPLORE_QUERY_PAGE_LIMIT; page += 1) {
      const url =
        `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}` +
        `&sort=updated&order=desc&per_page=${perPage}&page=${page}`;
      try {
        const payload = await githubJson(url, headers);
        const repositories = Array.isArray(payload.items) ? payload.items : [];
        for (const repo of repositories) {
          if (!repo?.owner?.login || !repo.name || discovered.has(repo.full_name)) continue;
          discovered.set(repo.full_name, {
            ...repo,
            matchedQuery: query,
            discoveryScore: aiRepositoryScore(repo, query)
          });
        }
        if (repositories.length < perPage) break;
      } catch (error) {
        if (query === queries.at(-1) && discovered.size === 0) throw error;
        break;
      }
    }
    if (discovered.size >= maxRepositories * 3) break;
  }

  return [...discovered.values()]
    .sort(
      (left, right) =>
        (right.discoveryScore || 0) - (left.discoveryScore || 0) ||
        new Date(right.updated_at || 0) - new Date(left.updated_at || 0)
    )
    .slice(0, maxRepositories);
}

function repositorySearchQueriesFromCoff0xc(pushedSince) {
  return coff0xcSearchQueries.map((query) => {
    const normalized = query
      .replace(/\bfilename:[^\s]+/g, "")
      .replace(/\bin:file\b/g, "")
      .replace(/\s+/g, " ")
      .trim();
    return `${normalized} in:readme,description is:public archived:false stars:0..100 pushed:>${pushedSince}`;
  });
}

export function aiRepositoryScore(repo, query = "") {
  const topics = Array.isArray(repo.topics) ? repo.topics.join(" ") : "";
  const text = `${repo.name || ""} ${repo.description || ""} ${topics} ${query}`.toLowerCase();
  const stars = Number(repo.stargazers_count || 0);
  const repoSize = Number(repo.size || 0);
  let score = 0;

  if (stars <= 5) score += 9;
  else if (stars <= 25) score += 8;
  else if (stars <= 100) score += 6;
  else if (stars <= 500) score += 3;
  else score -= Math.min(6, Math.log10(stars));

  if (repoSize > 0 && repoSize <= 5_000) score += 2;
  else if (repoSize > 50_000) score -= 2;

  if (/(llm|large-language-model|openai|anthropic|deepseek|huggingface|langchain|rag|agent|chatbot|copilot|embedding|vector|pinecone|qdrant|weaviate|milvus)/i.test(text)) {
    score += 10;
  }
  if (/(demo|starter|template|example|sample|tutorial|quickstart)/i.test(text)) score += 3;
  if (new Date(repo.pushed_at || repo.updated_at || 0) > new Date(Date.now() - 14 * 24 * 60 * 60 * 1000)) {
    score += 2;
  }
  return score;
}

async function fetchGitHubViewer(headers) {
  if (!headers.Authorization) return null;
  try {
    return await githubJson("https://api.github.com/user", headers);
  } catch {
    return null;
  }
}

async function fetchGitHubTree(owner, repo, branch, headers) {
  const branchInfo = await githubJson(
    `https://api.github.com/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}`,
    headers
  );
  const treeSha = branchInfo.commit?.commit?.tree?.sha || branchInfo.commit?.sha || branch;
  const tree = await githubJson(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${treeSha}?recursive=1`,
    headers
  );
  return Array.isArray(tree.tree) ? tree.tree : [];
}

async function fetchGitHubFileContent(owner, repo, filePath, ref, headers) {
  const response = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodePath(filePath)}?ref=${encodeURIComponent(ref)}`,
    { headers }
  );
  if (!response.ok) return null;

  const payload = await response.json();
  if (payload.type !== "file" || payload.encoding !== "base64" || !payload.content) return null;
  const buffer = Buffer.from(payload.content.replace(/\s/g, ""), "base64");
  if (buffer.includes(0)) return null;
  return buffer.toString("utf8");
}

async function githubJson(url, headers, messages = {}) {
  const response = await fetch(url, { headers });
  if (!response.ok) {
    if (response.status === 404 && messages.notFoundMessage) {
      throw new Error(messages.notFoundMessage);
    }
    if (response.status === 403) {
      const remaining = response.headers.get("x-ratelimit-remaining");
      if (remaining === "0") {
        throw new Error("GitHub API rate limit reached. Add a GITHUB_TOKEN environment variable in Vercel to raise the limit.");
      }
    }
    throw new Error(`GitHub API returned ${response.status}.`);
  }
  return response.json();
}

async function githubPaginatedJson(firstUrl, headers, maxItems) {
  const items = [];
  let nextUrl = firstUrl;

  while (nextUrl && items.length < maxItems) {
    const response = await fetch(nextUrl, { headers });
    if (!response.ok) throw new Error(`GitHub API returned ${response.status}.`);
    const payload = await response.json();
    items.push(...payload);
    nextUrl = parseNextLink(response.headers.get("link"));
  }

  return items.slice(0, maxItems);
}

function makeGitHubHeaders(githubToken) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "vulnerability-scanner"
  };
  if (githubToken) headers.Authorization = `Bearer ${githubToken}`;
  return headers;
}

function shouldScanGitHubPath(filePath, size = 0) {
  const normalized = String(filePath || "").replace(/\\/g, "/");
  if (!normalized || size > 2 * 1024 * 1024) return false;
  if (normalized.split("/").some((part) => SKIPPED_DIRS.has(part))) return false;
  if (SKIPPED_EXTENSIONS.has(path.extname(normalized).toLowerCase())) return false;
  return (
    Boolean(classifyRiskFile(normalized)) ||
    isVulnerabilityRelevantPath(normalized) ||
    SCANNABLE_SOURCE_EXTENSIONS.has(extensionOrEnv(normalized))
  );
}

function candidateScore(filePath) {
  const normalized = String(filePath || "").replace(/\\/g, "/");
  const riskRule = classifyRiskFile(normalized);
  if (riskRule?.severity === "critical") return 100;
  if (riskRule?.severity === "high") return 80;
  if (riskRule?.severity === "medium") return 60;
  if (isDependencyManifest(normalized)) return 55;
  if (/(^|\/)\.github\/workflows\//i.test(normalized)) return 40;
  if (/(^|\/)(config|configs|settings|deploy|infra|terraform|helm|charts|k8s|kubernetes|ops|scripts|examples?|demos?|notebooks?)\//i.test(normalized)) return 30;
  if (/(openai|anthropic|deepseek|langchain|langsmith|huggingface|replicate|pinecone|qdrant|weaviate|milvus|chroma|secret|token|credential|apikey|api-key|auth)/i.test(normalized)) return 25;
  return 10;
}

function isVulnerabilityRelevantPath(filePath) {
  return (
    isDependencyManifest(filePath) ||
    vulnerabilityRules.some((rule) => rule.filePattern && rule.filePattern.test(filePath))
  );
}

function isDependencyManifest(filePath) {
  return /(^|\/)(package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|build\.gradle|gradle\.kts|requirements\.txt|pyproject\.toml|poetry\.lock|Gemfile\.lock|go\.mod|Cargo\.toml|composer\.json)$/i.test(
    filePath
  );
}

function extensionOrEnv(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  if (basename === ".env" || basename.startsWith(".env.")) return ".env";
  return path.extname(basename);
}

function dedupeRules(rules) {
  const seen = new Set();
  return rules.filter((rule) => {
    if (seen.has(rule.id)) return false;
    seen.add(rule.id);
    return true;
  });
}

function providerFromRuleId(ruleId = "") {
  const id = String(ruleId).replace(/^coff0xc-/, "");
  if (id.includes("github")) return "github";
  if (id.includes("openai")) return "openai";
  if (id.includes("anthropic")) return "anthropic";
  if (id.includes("deepseek")) return "deepseek";
  if (id.includes("huggingface")) return "huggingface";
  if (id.includes("replicate")) return "replicate";
  if (id.includes("groq")) return "groq";
  if (id.includes("pinecone")) return "pinecone";
  if (id.includes("langsmith")) return "langsmith";
  if (id.includes("perplexity")) return "perplexity";
  if (id.includes("aws")) return "aws";
  if (id.includes("google") || id.includes("gcp") || id.includes("gemini")) return "google";
  if (id.includes("azure")) return "azure";
  if (id.includes("slack")) return "slack";
  if (id.includes("stripe")) return "stripe";
  if (id.includes("discord")) return "discord";
  if (id.includes("npm")) return "npm";
  if (id.includes("pypi")) return "pypi";
  if (id.includes("docker")) return "dockerhub";
  if (id.includes("sendgrid")) return "sendgrid";
  if (id.includes("database") || id.includes("mongodb") || id.includes("redis")) return "database";
  if (id.includes("jwt")) return "jwt";
  if (id.includes("private-key")) return "private-key";
  return "generic";
}

function categoryFromRuleId(ruleId = "") {
  const provider = providerFromRuleId(ruleId);
  if (["openai", "anthropic", "deepseek", "huggingface", "replicate", "groq", "pinecone", "langsmith", "perplexity", "gemini", "cohere", "mistral", "together", "fireworks", "anyscale"].includes(provider)) return "ai";
  if (["github", "gitlab", "npm", "pypi", "dockerhub"].includes(provider)) return "devops";
  if (["aws", "google", "azure", "gcp"].includes(provider)) return "cloud";
  if (["slack", "discord", "sendgrid", "telegram", "twilio"].includes(provider)) return "messaging";
  if (provider === "stripe") return "payment";
  if (provider === "database") return "database";
  if (provider === "private-key") return "private-key";
  if (provider === "jwt") return "auth";
  return "generic";
}

function buildRiskFileFinding({ rule, repository, file, fileUrl }) {
  const fullFile = `${repository}/${file}`;
  const finding = {
    id: `${rule.id}-${repository}-${file}-${fingerprint(`${repository}/${file}`)}`,
    ruleId: rule.id,
    label: rule.label,
    severity: "low",
    stage: "risk-file-name",
    repository,
    file: fullFile,
    fileUrl,
    source: "github",
    provider: "candidate",
    category: "candidate",
    masked: "[risk-file]",
    context: rule.context,
    entropy: 0,
    evidenceLevel: "candidate",
    actionable: false,
    advice: rule.advice
  };
  return {
    ...finding,
    exploitability: buildExploitabilityAssessment(finding)
  };
}

function parseNextLink(linkHeader) {
  if (!linkHeader) return null;
  const next = linkHeader
    .split(",")
    .map((part) => part.trim())
    .find((part) => part.endsWith('rel="next"'));
  return next?.match(/<([^>]+)>/)?.[1] || null;
}

function encodePath(filePath) {
  return filePath.split("/").map(encodeURIComponent).join("/");
}

function githubFileUrl(owner, repo, branch, filePath, lineNumber) {
  const branchPath = encodeURIComponent(branch || "main").replace(/%2F/g, "/");
  const url = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/blob/${branchPath}/${encodePath(filePath)}`;
  return lineNumber ? `${url}#L${lineNumber}` : url;
}

function safeUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function clampNumber(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.round(number)));
}

function daysAgoDate(days) {
  const date = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return date.toISOString().slice(0, 10);
}

async function downloadGitHubArchive(githubUrl, githubToken) {
  const parsed = parseGitHubUrl(githubUrl);
  if (!parsed) throw new Error("Please provide a valid GitHub repository URL.");

  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "vulnerability-scanner"
  };
  if (githubToken) headers.Authorization = `Bearer ${githubToken}`;

  const repoResponse = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, {
    headers
  });

  if (!repoResponse.ok) {
    if (repoResponse.status === 404) {
      throw new Error("GitHub repository not found or not accessible. Public repositories work by default; private repositories require a GITHUB_TOKEN environment variable.");
    }
    throw new Error(`GitHub API returned ${repoResponse.status}.`);
  }

  const repo = await repoResponse.json();
  const branch = repo.default_branch || "main";
  const archiveResponse = await fetch(
    `https://codeload.github.com/${parsed.owner}/${parsed.repo}/tar.gz/${encodeURIComponent(branch)}`,
    { headers: githubToken ? { Authorization: `Bearer ${githubToken}` } : {} }
  );

  if (!archiveResponse.ok) {
    throw new Error(`GitHub archive download returned ${archiveResponse.status}.`);
  }

  const tmpParent = await fs.mkdtemp(path.join(os.tmpdir(), "vulnerability-scanner-"));
  const checkoutPath = path.join(tmpParent, "repo");
  const archivePath = path.join(tmpParent, "repo.tar.gz");
  await fs.mkdir(checkoutPath, { recursive: true });
  await fs.writeFile(archivePath, Buffer.from(await archiveResponse.arrayBuffer()));
  await tar.x({
    file: archivePath,
    cwd: checkoutPath,
    strip: 1
  });

  return {
    path: checkoutPath,
    cleanupPath: tmpParent,
    display: githubUrl,
    mode: "github"
  };
}

async function collectFiles(rootDir) {
  const files = [];

  async function walk(currentDir) {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) await walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (SKIPPED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;

      const stat = await fs.stat(fullPath);
      if (stat.size > 1024 * 1024) continue;
      files.push(fullPath);
    }
  }

  await walk(rootDir);
  return files;
}

async function readTextFile(file) {
  const buffer = await fs.readFile(file);
  if (buffer.includes(0)) return null;
  return buffer.toString("utf8");
}

async function isGitRepo(repoPath) {
  try {
    await execFileAsync("git", ["-C", repoPath, "rev-parse", "--is-inside-work-tree"]);
    return true;
  } catch {
    return false;
  }
}

async function gitShowPatch(repoPath, commit) {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["-C", repoPath, "show", "--format=medium", "--no-ext-diff", "--no-color", "--unified=0", commit],
      { maxBuffer: 30 * 1024 * 1024 }
    );
    return stdout;
  } catch {
    return "";
  }
}

function buildFinding({ rule, secret, line, file, lineNumber, source, commit, repository, fileUrl, stage }) {
  const evidenceLevel = rule.evidenceLevel || (stage === "entropy-context" ? "generic_entropy" : rule.contextPattern ? "contextual_pattern" : "confirmed_pattern");
  const finding = {
    id: `${rule.id}-${file}-${lineNumber || "unknown"}-${fingerprint(secret)}`,
    ruleId: rule.id,
    label: rule.label,
    severity: rule.severity,
    stage: stage || "token-pattern",
    repository,
    file,
    fileUrl,
    line: lineNumber,
    source,
    commit,
    provider: rule.provider || providerFromRuleId(rule.id),
    category: rule.category || categoryFromRuleId(rule.id),
    evidenceLevel,
    sourceRuleSet: rule.sourceRuleSet || "builtin",
    actionable: rule.actionable !== false,
    masked: maskSecret(secret),
    context: redactLine(line, secret),
    fingerprint: fingerprint(`${rule.id}|${file}|${secret}`),
    entropy: Number(shannonEntropy(secret).toFixed(2)),
    advice: rule.advice
  };
  return {
    ...finding,
    exploitability: buildExploitabilityAssessment(finding, { secret, line })
  };
}

function buildVulnerabilityFinding({ rule, line, file, lineNumber, source, commit, repository, fileUrl }) {
  const finding = {
    id: `${rule.id}-${file}-${lineNumber || "unknown"}-${fingerprint(line)}`,
    ruleId: rule.id,
    label: rule.label,
    severity: rule.severity,
    stage: "vulnerability-pattern",
    repository,
    file,
    fileUrl,
    line: lineNumber,
    source,
    commit,
    provider: rule.provider || "static-analysis",
    category: rule.category || "application-security",
    evidenceLevel: rule.evidenceLevel || "static_vulnerability_pattern",
    sourceRuleSet: rule.sourceRuleSet || "builtin-vulnerability",
    actionable: rule.actionable !== false,
    masked: "[static-risk]",
    context: String(line || "").trim().slice(0, 260),
    fingerprint: fingerprint(`${rule.id}|${file}|${String(line || "").trim()}`),
    entropy: 0,
    cwe: rule.cwe,
    possibleCves: rule.possibleCves || [],
    advice: rule.advice
  };
  return {
    ...finding,
    exploitability: buildExploitabilityAssessment(finding, { line }, rule.exploitability)
  };
}

function buildExploitabilityAssessment(finding, evidence = {}, overrideDefinition) {
  const definition = overrideDefinition || exploitabilityDefinitions[finding.ruleId] || exploitabilityDefinitions.default;
  const safeTests = buildSafeEvidenceTests(finding, evidence);
  const passed = safeTests.filter((test) => test.result === "passed").length;
  const confidence =
    finding.stage === "risk-file-name"
      ? passed >= 3
        ? "medium"
        : "low"
      : passed >= 4
        ? "high"
        : passed >= 3
          ? "medium"
          : "low";

  return {
    summary: definition.summary,
    confidence,
    modes: definition.modes,
    safeTests,
    limitation:
      "非侵入式安全测试只证明公开暴露、格式和上下文风险，不会调用第三方 API 或使用泄露凭证验证权限。"
  };
}

const exploitabilityDefinitions = {
  "github-classic-token": {
    summary: "GitHub PAT 一旦有效，可能被用于访问代码、读取组织资源或触发仓库写操作，具体取决于 token scope。",
    modes: [
      {
        title: "代码与仓库资源访问",
        impact: "读取私有仓库、issue、PR 或 Actions 相关资源。",
        prerequisites: "token 仍有效，并且被授予对应 GitHub scope。"
      },
      {
        title: "供应链投毒",
        impact: "向有权限的仓库推送代码、修改工作流或发布恶意版本。",
        prerequisites: "token 具备写权限或包发布权限。"
      }
    ]
  },
  "github-fine-grained-token": {
    summary: "Fine-grained PAT 的影响面由资源所有者、仓库范围和权限粒度决定，但公开暴露后仍应立即撤销。",
    modes: [
      {
        title: "限定仓库操作",
        impact: "在被授权的仓库范围内读取代码、创建 PR 或写入内容。",
        prerequisites: "token 未撤销且对应仓库权限包含相关操作。"
      },
      {
        title: "工作流滥用",
        impact: "在具备 Actions 或 contents 权限时触发 CI/CD 链路。",
        prerequisites: "token 权限覆盖 Actions、contents 或 workflows。"
      }
    ]
  },
  "openai-api-key": {
    summary: "OpenAI API key 若有效，可能导致额度消耗、账单损失或模型调用数据暴露。",
    modes: [
      {
        title: "额度与账单滥用",
        impact: "攻击者批量调用模型消耗配额或产生费用。",
        prerequisites: "key 未轮换且账户仍允许 API 调用。"
      },
      {
        title: "服务冒用",
        impact: "冒充应用后端调用模型，污染日志或绕过业务侧访问控制。",
        prerequisites: "应用没有额外的服务端鉴权或用量限制。"
      }
    ]
  },
  "anthropic-api-key": {
    summary: "AI provider API key 若有效，通常可被用于消耗模型调用额度、访问项目资源或冒用应用后端调用链路。",
    modes: [
      {
        title: "模型额度滥用",
        impact: "批量调用模型造成费用、配额或风控风险。",
        prerequisites: "key 未轮换且账户允许 API 调用。"
      },
      {
        title: "应用服务冒用",
        impact: "冒充业务后端调用模型或污染审计日志。",
        prerequisites: "应用缺少服务端限流、来源绑定或二次鉴权。"
      }
    ]
  },
  "deepseek-api-key": {
    summary: "DeepSeek API key 若有效，可能被用于模型调用额度消耗或冒用应用侧 AI 功能。",
    modes: [
      {
        title: "模型调用滥用",
        impact: "消耗账户额度、产生费用或触发异常调用风控。",
        prerequisites: "key 未轮换且 API 权限仍可用。"
      }
    ]
  },
  "huggingface-token": {
    summary: "Hugging Face token 可能授予模型、dataset、space 或组织资源访问能力。",
    modes: [
      {
        title: "模型与数据资源访问",
        impact: "读取私有模型/dataset，或在权限允许时推送模型产物。",
        prerequisites: "token 有效并具备 read/write scope。"
      }
    ]
  },
  "replicate-api-token": {
    summary: "Replicate API token 若有效，可能被用于运行模型并消耗账户额度。",
    modes: [
      {
        title: "模型运行额度滥用",
        impact: "批量运行模型造成费用或资源占用。",
        prerequisites: "token 未轮换且账户有可用额度。"
      }
    ]
  },
  "groq-api-key": {
    summary: "Groq API key 若有效，可能被用于模型调用额度消耗或服务冒用。",
    modes: [
      {
        title: "模型接口滥用",
        impact: "消耗 API 配额并污染业务调用日志。",
        prerequisites: "key 有效且没有服务端限流/来源约束。"
      }
    ]
  },
  "pinecone-api-key": {
    summary: "Pinecone API key 可能允许访问向量索引，导致 RAG 数据泄露或索引被篡改。",
    modes: [
      {
        title: "向量数据库访问",
        impact: "读取、写入或删除索引中的 embedding 与关联元数据。",
        prerequisites: "key 有效且权限覆盖目标 index/project。"
      }
    ]
  },
  "langsmith-api-key": {
    summary: "LangSmith API key 可能暴露 trace、prompt、评测数据或项目级调试信息。",
    modes: [
      {
        title: "AI 调试数据暴露",
        impact: "访问链路 trace、输入输出样本、prompt 或评测结果。",
        prerequisites: "key 有效且关联项目保存了敏感调用数据。"
      }
    ]
  },
  "perplexity-api-key": {
    summary: "Perplexity API key 若有效，可能被用于消耗模型调用额度或冒用应用搜索能力。",
    modes: [
      {
        title: "搜索/模型调用滥用",
        impact: "产生异常调用、费用或配额消耗。",
        prerequisites: "key 未轮换且账户允许 API 调用。"
      }
    ]
  },
  "aws-access-key": {
    summary: "AWS access key id 单独不足以登录，但如果同仓库还存在 secret access key，可能导致云资源被接管。",
    modes: [
      {
        title: "云资源访问",
        impact: "读取对象存储、启动计算资源或访问数据库等。",
        prerequisites: "同时存在匹配的 secret access key，且 IAM 权限允许。"
      },
      {
        title: "横向移动",
        impact: "利用过宽 IAM 权限发现更多云凭证或部署资源。",
        prerequisites: "密钥有效且 IAM policy 过宽。"
      }
    ]
  },
  "aws-secret-access-key": {
    summary: "AWS secret access key 与 access key id 成对泄露时，可能导致云资源被直接访问。",
    modes: [
      {
        title: "云账号资源访问",
        impact: "访问 S3、EC2、IAM、数据库或其他被授权资源。",
        prerequisites: "同一仓库或历史中存在匹配 access key id，且 IAM 权限仍有效。"
      }
    ]
  },
  "google-api-key": {
    summary: "Google API key 若没有来源、API 或配额限制，可能被用于消耗配额或访问开放 API。",
    modes: [
      {
        title: "API 配额滥用",
        impact: "调用启用的 Google API 造成配额耗尽或账单异常。",
        prerequisites: "key 有效，并且缺少 HTTP referrer、IP 或 API 限制。"
      }
    ]
  },
  "google-service-account-key": {
    summary: "Google service account key 暴露通常意味着机器身份凭证泄露，可直接访问被授予的 GCP/Firebase 资源。",
    modes: [
      {
        title: "服务账号冒用",
        impact: "读取或操作云资源、Firebase 项目、存储桶或后台 API。",
        prerequisites: "私钥仍有效且服务账号权限未收敛。"
      }
    ]
  },
  "azure-storage-key": {
    summary: "Azure storage account key 暴露可能允许读取或改写对应存储账户数据。",
    modes: [
      {
        title: "对象存储访问",
        impact: "读取、写入、删除 blob/table/queue 数据。",
        prerequisites: "account key 未轮换且存储账户接受该密钥。"
      }
    ]
  },
  "slack-token": {
    summary: "Slack token 可能允许读取工作区数据、发送消息或操作 bot，影响取决于 token 类型和 scope。",
    modes: [
      {
        title: "工作区数据访问",
        impact: "读取频道、用户或消息元数据。",
        prerequisites: "token 有效且具备对应 Slack scope。"
      },
      {
        title: "消息与自动化冒用",
        impact: "冒充应用发送消息、触发工作流或引导钓鱼。",
        prerequisites: "bot/app 权限允许发信或交互。"
      }
    ]
  },
  "slack-webhook-url": {
    summary: "Slack webhook URL 可被用于向绑定频道发送消息，常被滥用于钓鱼或告警污染。",
    modes: [
      {
        title: "消息发送冒用",
        impact: "向 Slack 频道发送伪造消息、钓鱼链接或污染告警流。",
        prerequisites: "webhook 未撤销且频道仍存在。"
      }
    ]
  },
  "stripe-secret-key": {
    summary: "Stripe secret key 若有效，可能暴露支付、客户或订阅操作能力；live key 风险最高。",
    modes: [
      {
        title: "支付数据访问",
        impact: "读取客户、付款、发票或订阅信息。",
        prerequisites: "key 有效并具备相关 Stripe 权限。"
      },
      {
        title: "资金相关操作",
        impact: "在权限允许时创建退款、调整订阅或发起测试/真实交易。",
        prerequisites: "live secret key 未轮换且账户未加额外限制。"
      }
    ]
  },
  "discord-bot-token": {
    summary: "Discord bot token 若有效，可能让攻击者完全控制对应 bot。",
    modes: [
      {
        title: "Bot 接管",
        impact: "读取可见频道、发送消息、执行 bot 已授权命令。",
        prerequisites: "token 有效且 bot 仍在服务器中。"
      }
    ]
  },
  "discord-webhook-url": {
    summary: "Discord webhook URL 暴露后可被用于向绑定频道发送消息。",
    modes: [
      {
        title: "频道消息冒用",
        impact: "发送伪造公告、钓鱼链接或垃圾消息。",
        prerequisites: "webhook 未删除且目标频道仍有效。"
      }
    ]
  },
  "npm-token": {
    summary: "包发布 token 暴露可能导致供应链发布链路被接管。",
    modes: [
      {
        title: "包发布与供应链投毒",
        impact: "发布恶意版本、篡改包元数据或读取私有包。",
        prerequisites: "token 有效且具备 publish 或 package read 权限。"
      }
    ]
  },
  "pypi-token": {
    summary: "PyPI API token 暴露可能导致 Python 包发布链路被冒用。",
    modes: [
      {
        title: "Python 包供应链投毒",
        impact: "发布恶意包版本或读取私有项目包。",
        prerequisites: "token 有效且绑定项目或账户权限允许发布。"
      }
    ]
  },
  "dockerhub-token": {
    summary: "Docker Hub access token 暴露可能导致镜像仓库被读取或写入。",
    modes: [
      {
        title: "镜像发布链路冒用",
        impact: "推送恶意镜像、覆盖 tag 或读取私有镜像。",
        prerequisites: "token 有效且具备 repository read/write 权限。"
      }
    ]
  },
  "sendgrid-api-key": {
    summary: "SendGrid API key 若有效，可能被用于批量发信、钓鱼或读取邮件相关配置。",
    modes: [
      {
        title: "邮件发送滥用",
        impact: "批量发送钓鱼/垃圾邮件，损害域名信誉或产生费用。",
        prerequisites: "key 未轮换且具备 mail.send 或管理权限。"
      }
    ]
  },
  "database-url-with-password": {
    summary: "带用户名和密码的数据库连接串暴露通常可以直接指向可尝试登录的数据资产。",
    modes: [
      {
        title: "数据库访问",
        impact: "读取、写入或删除业务数据。",
        prerequisites: "数据库网络可达、密码仍有效且账号权限允许。"
      }
    ]
  },
  jwt: {
    summary: "JWT 泄露可能导致会话重放或身份冒用，但是否可用取决于过期时间、签名密钥和服务端校验。",
    modes: [
      {
        title: "会话重放",
        impact: "以令牌持有者身份访问业务接口。",
        prerequisites: "JWT 未过期、未被吊销，且服务端接受该 token。"
      }
    ]
  },
  "private-key": {
    summary: "私钥内容暴露通常可用于 SSH 登录、TLS 伪装或签名冒用，具体取决于该密钥被哪里信任。",
    modes: [
      {
        title: "身份冒用",
        impact: "冒充服务器、开发者或部署身份进行连接或签名。",
        prerequisites: "公钥仍被目标系统信任，私钥未设置强口令或口令也泄露。"
      }
    ]
  },
  "generic-high-entropy-secret": {
    summary: "高熵 secret 结合敏感变量名通常表示真实密钥、密码或令牌，应按已泄露处理。",
    modes: [
      {
        title: "业务接口冒用",
        impact: "使用该值访问应用、数据库、第三方 API 或内部服务。",
        prerequisites: "secret 有效，且目标服务没有额外绑定或轮换。"
      }
    ]
  },
  "committed-env-file": {
    summary: ".env 文件常保存数据库 URL、API key、JWT secret 或部署凭证，公开提交会显著扩大泄露面。",
    modes: [
      {
        title: "配置集中泄露",
        impact: "一次获得多个服务的连接串、API key 或签名密钥。",
        prerequisites: "文件内包含真实生产或共享环境值。"
      },
      {
        title: "应用伪造与会话签名",
        impact: "利用 JWT/session secret 伪造会话或调用内部服务。",
        prerequisites: "服务端仍使用文件中的 secret。"
      }
    ]
  },
  "credential-file": {
    summary: "凭证文件通常是服务账号、部署 token 或应用认证配置，可能直接授予机器身份。",
    modes: [
      {
        title: "服务账号冒用",
        impact: "访问云资源、数据库、存储桶或后台 API。",
        prerequisites: "凭证仍有效且权限未被最小化。"
      }
    ]
  },
  "platform-credential-file": {
    summary: "平台级凭证文件通常保存包仓库、云 CLI、容器仓库或 Kubernetes 访问凭据。",
    modes: [
      {
        title: "平台身份冒用",
        impact: "访问包发布、云资源、集群或镜像仓库。",
        prerequisites: "文件中包含真实凭证且对应平台仍接受该凭证。"
      }
    ]
  },
  "private-key-file": {
    summary: "私钥类文件名表示仓库中可能包含可导入的认证材料，需结合内容确认。",
    modes: [
      {
        title: "密钥导入与认证",
        impact: "用于 SSH、TLS、包签名或云服务认证。",
        prerequisites: "文件内容确为私钥/证书包，并被外部系统信任。"
      }
    ]
  },
  "cloud-config-risk-file": {
    summary: "云配置和部署文件经常内联 token、数据库 URL 或 provider 密钥。",
    modes: [
      {
        title: "部署链路滥用",
        impact: "读取或改写云资源、部署配置和基础设施状态。",
        prerequisites: "配置中包含真实凭证或过宽 provider 权限。"
      }
    ]
  },
  "ai-provider-config-file": {
    summary: "AI provider 配置文件经常包含 LLM API key、向量数据库连接信息或 tracing token。",
    modes: [
      {
        title: "AI 应用调用链路暴露",
        impact: "模型额度被滥用、RAG 数据被访问或调试 trace 泄露。",
        prerequisites: "配置中包含真实 provider key 或 vector database 凭证。"
      }
    ]
  },
  default: {
    summary: "该命中具备凭证泄露或敏感配置暴露特征，需要结合上下文复核。",
    modes: [
      {
        title: "未授权访问",
        impact: "可能访问相关应用、服务或数据。",
        prerequisites: "凭证有效且目标服务接受该凭证。"
      }
    ]
  }
};

function buildSafeEvidenceTests(finding, evidence) {
  const tests = [
    {
      name: "公开定位证据",
      result: finding.fileUrl ? "passed" : "not_applicable",
      evidence: finding.fileUrl ? "命中项可定位到 GitHub 公开文件或具体行号。" : "本地/历史扫描没有公开 URL。"
    },
    {
      name: "敏感规则匹配",
      result: finding.ruleId ? "passed" : "failed",
      evidence: `${finding.label || finding.ruleId} matched by ${finding.stage}.`
    },
    {
      name: "占位符排除",
      result: /example|sample|placeholder|changeme|your[_-]?token/i.test(`${finding.context} ${finding.file}`)
        ? "failed"
        : "passed",
      evidence: "上下文未命中常见 example/sample/placeholder/changeme 标记。"
    }
  ];

  if (finding.stage === "risk-file-name") {
    tests.push(
      {
        name: "风险文件类型",
        result: "passed",
        evidence: `文件路径 ${finding.file} 符合 ${finding.label} 风险类型。`
      },
      {
        name: "内容验证状态",
        result: "not_run",
        evidence: "未使用文件内容中的凭证访问任何外部服务；仅进行文件名与路径证据测试。"
      }
    );
    return tests;
  }

  if (finding.stage === "vulnerability-pattern") {
    tests.push(
      {
        name: "CVE/CWE 映射",
        result: finding.possibleCves?.length || finding.cwe ? "passed" : "not_applicable",
        evidence: [...(finding.possibleCves || []), finding.cwe].filter(Boolean).join(", ") || "该规则只映射到通用漏洞类型。"
      },
      {
        name: "危险代码模式",
        result: "passed",
        evidence: `静态规则 ${finding.ruleId} 命中当前文件内容。`
      },
      {
        name: "利用验证状态",
        result: "not_run",
        evidence: "未对目标项目发起漏洞利用、探测 payload 或第三方服务验证。"
      }
    );
    return tests;
  }

  tests.push(
    {
      name: "高熵/格式证据",
      result: finding.entropy >= 3.5 || finding.stage === "token-pattern" ? "passed" : "failed",
      evidence: `脱敏值熵=${finding.entropy}; stage=${finding.stage}.`
    },
    {
      name: "敏感上下文",
      result: hasSensitiveContext(evidence.line || finding.context || "") ? "passed" : "not_applicable",
      evidence: "变量名或上下文包含 token/key/secret/password 等敏感语义。"
    },
    {
      name: "权限验证状态",
      result: "not_run",
      evidence: "未调用 GitHub/OpenAI/AWS/Slack/Stripe 等第三方 API 验证凭证有效性。"
    }
  );

  return tests;
}

function hasSensitiveContext(value) {
  return /(api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|private[_-]?key|password|passwd|pwd|credential)/i.test(
    value
  );
}

function shouldReportSecret(secret) {
  if (!secret || secret.length < 12) return false;
  if (/example|sample|placeholder|changeme|your[_-]?(token|key|secret)|insert|replace|sandbox|dummy|fake/i.test(secret)) return false;
  if (/^(x+|0+|1+|a+|test|demo|dummy)$/i.test(secret)) return false;
  if (/^(abcdef|123456|xxxxxx)+$/i.test(secret)) return false;
  // 模板变量 / 占位符：${VAR}、{{ var }}、%VAR%、<your-key>
  if (/^\$\{[^}]+\}$|^\{\{[^}]+\}\}$|^%[A-Za-z0-9_]+%$|^<[^>]+>$/.test(secret)) return false;
  // 间接引用：值来自环境变量或函数调用，而不是写死的凭证
  if (/^(process\.env|os\.environ|getenv|env\(|import\.meta\.env)/i.test(secret)) return false;
  // 同一字符重复
  if (/^(.)\1{7,}$/.test(secret)) return false;
  return true;
}

function shouldReportGeneric(secret) {
  if (!shouldReportSecret(secret)) return false;
  if (secret.length < 24) return false;
  if (/^(true|false|null|undefined)$/i.test(secret)) return false;
  if (/^(development|production|staging|localhost)$/i.test(secret)) return false;
  if (/^https?:\/\//i.test(secret)) return false;
  if (/^[a-z0-9.-]+\.(com|org|net|local)$/i.test(secret)) return false;
  if (/^#[0-9a-f]{6}$/i.test(secret)) return false;
  if (/^\d+(\.\d+){1,3}$/.test(secret)) return false;
  // UUID 通常是资源 ID 而不是凭证
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(secret)) return false;
  return shannonEntropy(secret) >= 3.8;
}

function maskSecret(secret) {
  if (secret.length <= 10) return "[redacted]";
  return `${secret.slice(0, 4)}...${secret.slice(-4)}`;
}

function redactLine(line, secret) {
  return line.replace(secret, maskSecret(secret)).trim().slice(0, 260);
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function fingerprint(secret) {
  let hash = 2166136261;
  for (let index = 0; index < secret.length; index += 1) {
    hash ^= secret.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}:${finding.file}:${finding.line}:${finding.source}:${finding.masked}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function finalizeScanResult({
  target,
  mode,
  durationMs,
  findings,
  repositories,
  summaryExtras = {},
  validityEnabled = false
}) {
  const { kept, suppressed, stats } = applyNoiseFilters(dedupeFindings(findings));
  const uniqueFindings = annotateValidity(kept, { enabled: validityEnabled });
  const summary = {
    ...summarize(uniqueFindings),
    ...summaryExtras,
    suppressed: suppressed.length,
    inTestFiles: uniqueFindings.filter((finding) => finding.inTestFile).length
  };
  const aggregations = aggregateFindings(uniqueFindings);
  const riskProjects = collectRiskProjects(uniqueFindings, repositories);

  return {
    target,
    mode,
    scannedAt: new Date().toISOString(),
    durationMs,
    summary,
    pipeline: buildPipelineSummary(uniqueFindings, validityEnabled),
    aggregations,
    riskProjects,
    repositories,
    findings: uniqueFindings,
    suppressed,
    suppressionStats: stats
  };
}

function annotateValidity(findings, { enabled = false } = {}) {
  return findings.map((finding) => ({
    ...finding,
    verification: enabled
      ? {
          status: "unsupported",
          reason: "Validity checks need provider-owned verification integrations."
        }
      : {
          status: "not_checked",
          reason: "Disabled by default to avoid validating third-party tokens."
        }
  }));
}

function buildPipelineSummary(findings, validityEnabled) {
  const counts = findings.reduce((accumulator, finding) => {
    accumulator[finding.stage] = (accumulator[finding.stage] || 0) + 1;
    return accumulator;
  }, {});

  return pipelineStages.map((stage) => ({
    ...stage,
    count: counts[stage.id] || 0,
    status: stage.id === "validity-check" ? (validityEnabled ? "unsupported" : "disabled") : "completed"
  }));
}

function aggregateFindings(findings) {
  return {
    byRepository: aggregateBy(findings, (finding) => finding.repository || repositoryFromFile(finding.file)),
    byFile: aggregateBy(findings, (finding) => finding.file),
    byRule: aggregateBy(findings, (finding) => finding.ruleId, (finding) => finding.label),
    byCve: aggregateBy(
      findings.filter((finding) => finding.possibleCves?.length || finding.cwe),
      (finding) => finding.possibleCves?.[0] || finding.cwe,
      (finding) => [finding.possibleCves?.[0], finding.cwe].filter(Boolean).join(" / ")
    ),
    byProvider: aggregateBy(findings, (finding) => finding.provider || "unknown"),
    byCategory: aggregateBy(findings, (finding) => finding.category || "unknown"),
    byEvidenceLevel: aggregateBy(findings, (finding) => finding.evidenceLevel || "unknown"),
    bySeverity: aggregateBy(findings, (finding) => finding.severity),
    byStage: aggregateBy(findings, (finding) => finding.stage)
  };
}

function collectRiskProjects(findings, repositories = []) {
  const repoMeta = new Map((repositories || []).map((repo) => [repo.name, repo]));
  const projects = new Map();

  for (const finding of findings) {
    if (!isActionableCredentialFinding(finding)) continue;

    const repository = finding.repository || repositoryFromFile(finding.file);
    if (!repository || repository === "local") continue;

    const current = projects.get(repository) || {
      name: repository,
      url: repoMeta.get(repository)?.url || `https://github.com/${repository}`,
      description: repoMeta.get(repository)?.description || "",
      language: repoMeta.get(repository)?.language || null,
      stars: repoMeta.get(repository)?.stars || 0,
      topics: repoMeta.get(repository)?.topics || [],
      severity: finding.severity,
      findingCount: 0,
      files: new Set(),
      fileLocations: new Map(),
      rules: new Set(),
      stages: new Set(),
      providers: new Set(),
      categories: new Set(),
      firstDetectedAt: new Date().toISOString(),
      lastDetectedAt: new Date().toISOString()
    };

    current.findingCount += 1;
    current.severity = higherSeverity(current.severity, finding.severity);
    current.files.add(finding.file);
    const location = current.fileLocations.get(finding.file) || {
      path: finding.file,
      displayPath: displayFilePath(repository, finding.file),
      url: finding.fileUrl || null,
      severity: finding.severity,
      findingCount: 0,
      lines: []
    };
    location.findingCount += 1;
    location.severity = higherSeverity(location.severity, finding.severity);
    if (!location.url && finding.fileUrl) location.url = finding.fileUrl;
    if (finding.line && !location.lines.includes(finding.line)) location.lines.push(finding.line);
    current.fileLocations.set(finding.file, location);
    current.rules.add(finding.label || finding.ruleId);
    current.stages.add(finding.stage);
    if (finding.provider) current.providers.add(finding.provider);
    if (finding.category) current.categories.add(finding.category);
    current.lastDetectedAt = new Date().toISOString();
    projects.set(repository, current);
  }

  return [...projects.values()]
    .map((project) => ({
      ...project,
      files: [...project.files],
      fileLocations: [...project.fileLocations.values()].sort(
        (left, right) =>
          severityRank(right.severity) - severityRank(left.severity) || right.findingCount - left.findingCount
      ),
      rules: [...project.rules],
      stages: [...project.stages],
      providers: [...project.providers],
      categories: [...project.categories]
    }))
    .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || right.findingCount - left.findingCount);
}

function isActionableCredentialFinding(finding) {
  if (finding.actionable === false) return false;
  return (
    finding.stage === "token-pattern" ||
    finding.stage === "entropy-context" ||
    finding.stage === "vulnerability-pattern" ||
    finding.actionable === true ||
    finding.evidenceLevel === "credential" ||
    finding.evidenceLevel === "static_vulnerability_pattern"
  );
}

function displayFilePath(repository, file) {
  const prefix = `${repository}/`;
  return String(file || "").startsWith(prefix) ? file.slice(prefix.length) : file;
}

function aggregateBy(findings, keyFn, labelFn = keyFn) {
  const map = new Map();
  for (const finding of findings) {
    const key = keyFn(finding) || "unknown";
    const current = map.get(key) || {
      key,
      label: labelFn(finding) || key,
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    current.total += 1;
    current[finding.severity] = (current[finding.severity] || 0) + 1;
    map.set(key, current);
  }

  return [...map.values()].sort((left, right) => {
    if (right.critical !== left.critical) return right.critical - left.critical;
    if (right.high !== left.high) return right.high - left.high;
    return right.total - left.total;
  });
}

function repositoryFromFile(file) {
  const parts = String(file || "").split("/");
  if (parts.length >= 2 && !parts[0].startsWith(".")) return `${parts[0]}/${parts[1]}`;
  return "local";
}

function higherSeverity(left, right) {
  return severityRank(right) > severityRank(left) ? right : left;
}

function severityRank(severity) {
  return {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }[severity] || 0;
}

function summarize(findings) {
  const summary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    current: 0,
    history: 0,
    github: 0,
    stages: {},
    rules: {}
  };

  for (const finding of findings) {
    summary[finding.severity] = (summary[finding.severity] || 0) + 1;
    summary[finding.source] = (summary[finding.source] || 0) + 1;
    summary.stages[finding.stage] = (summary.stages[finding.stage] || 0) + 1;
    summary.rules[finding.ruleId] = (summary.rules[finding.ruleId] || 0) + 1;
  }

  return summary;
}

export function createExampleFinding() {
  // Sample (non-real) token assembled at runtime so the literal never appears
  // in source and GitHub push protection does not flag the test fixture.
  const sampleToken = ["ghp", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"].join("_");
  return buildFinding({
    rule: secretRules[0],
    secret: sampleToken,
    line: `GITHUB_TOKEN=${sampleToken}`,
    file: ".env",
    lineNumber: 1,
    source: "current"
  });
}
