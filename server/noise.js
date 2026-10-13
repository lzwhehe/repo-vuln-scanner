// 可解释的降噪层：参考 gitleaks 默认 allowlist 与 detect-secrets 的命名过滤器。
// 被排除的结果不会丢掉，而是带上 suppressedBy 放进 suppressed 列表，界面上可以看到为什么被排除。

const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|poetry\.lock|Cargo\.lock|composer\.lock|Gemfile\.lock)$/i;
const VENDOR_OR_BUILD = /(^|\/)(node_modules|vendor|bower_components|third_party|dist|build|out|\.next|coverage)\//i;
const MINIFIED = /\.(min\.js|min\.css|map)$/i;
const TEST_PATH =
  /(^|\/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|mocks?|__mocks__|testdata|examples?|samples?)\/|\.(test|spec)\.[a-z0-9]+$/i;
const INLINE_ALLOW = /(rvs:allow|gitleaks:allow|pragma:\s*allowlist\s+secret|\bnosec\b)/i;
// 检测规则 / 正则定义本身：出现正则元字符或规则字段时，判定为「规则定义」而非真实凭证
const RULE_DEFINITION =
  /(new RegExp\(|\/-----BEGIN|\(\?:|\\s[*+]|\\d\{|\[A-Za-z0-9|\[a-zA-Z0-9|\[0-9a-fA-F|\[0-9a-f\]|\b(regex|pattern|contextPattern)\s*[:=])/;

export const SUPPRESSION_REASONS = {
  "inline-allow": "行内声明忽略（rvs:allow / gitleaks:allow / pragma: allowlist secret）",
  lockfile: "依赖锁文件中的包哈希或元数据",
  "vendor-build": "第三方依赖或构建产物目录",
  "rule-definition": "检测规则或正则定义本身，不是真实凭证"
};

const DOWNGRADE = { critical: "high", high: "medium", medium: "low", low: "low" };

function normalize(file) {
  return String(file || "").replace(/\\/g, "/");
}

function suppressionReason(finding) {
  const file = normalize(finding.file);
  const context = String(finding.context || "");
  const isDependency = finding.category === "dependency-cve";

  if (INLINE_ALLOW.test(context)) return "inline-allow";
  if (VENDOR_OR_BUILD.test(file) || MINIFIED.test(file)) return "vendor-build";
  if (isDependency || finding.category === "code-vulnerability") return null;
  if (LOCKFILE.test(file)) return "lockfile";
  if (finding.stage !== "risk-file-name" && RULE_DEFINITION.test(context)) return "rule-definition";
  return null;
}

/**
 * 返回 { kept, suppressed, stats }：
 * - kept：保留的结果；测试 / 夹具文件里的结果降一级并标记 inTestFile
 * - suppressed：被排除的结果（精简字段 + suppressedBy）
 */
export function applyNoiseFilters(findings) {
  const kept = [];
  const suppressed = [];
  const stats = {};
  for (const finding of findings) {
    const reason = suppressionReason(finding);
    if (reason) {
      stats[reason] = (stats[reason] || 0) + 1;
      suppressed.push({
        id: finding.id,
        ruleId: finding.ruleId,
        label: finding.label,
        severity: finding.severity,
        category: finding.category,
        repository: finding.repository,
        file: finding.file,
        fileUrl: finding.fileUrl,
        line: finding.line,
        masked: finding.masked,
        suppressedBy: reason,
        reason: SUPPRESSION_REASONS[reason]
      });
      continue;
    }
    if (TEST_PATH.test(normalize(finding.file)) && finding.category !== "dependency-cve") {
      kept.push({
        ...finding,
        severity: DOWNGRADE[finding.severity] || finding.severity,
        originalSeverity: finding.severity,
        inTestFile: true
      });
      continue;
    }
    kept.push(finding);
  }
  return { kept, suppressed, stats };
}
