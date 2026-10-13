// 扫描结果导出：SARIF 2.1.0（可上传到 GitHub 代码扫描）、CSV、阈值判断。
// 纯函数、无 Node 依赖，命令行和前端共用。导出内容只含脱敏值，不含凭证原文。

const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note" };
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };
const RANK = { low: 1, medium: 2, high: 3, critical: 4 };

export const TOOL_NAME = "repo-vuln-scanner";
export const TOOL_VERSION = "1.1.0";

/** SARIF 要求路径相对仓库根目录；GitHub 模式下 file 带 "owner/repo/" 前缀，需要去掉 */
export function relativePath(finding) {
  let file = String(finding.file || "").replace(/\\/g, "/");
  if (finding.repository && file.startsWith(`${finding.repository}/`)) file = file.slice(finding.repository.length + 1);
  return file || "unknown";
}

function messageOf(finding) {
  const masked = finding.masked && !String(finding.masked).startsWith("[") ? `（${finding.masked}）` : "";
  const fix = finding.package?.fixedVersion ? ` 建议升级到 ${finding.package.fixedVersion}。` : "";
  return `${finding.label}${masked}${fix}`;
}

export function toSarif(result) {
  const rules = new Map();
  const results = [];
  for (const finding of result.findings || []) {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.label },
        fullDescription: { text: finding.advisory?.summary || finding.label },
        help: { text: finding.advice || finding.label },
        properties: {
          "security-severity": finding.advisory?.cvss ? String(finding.advisory.cvss) : SECURITY_SEVERITY[finding.severity] || "5.0",
          tags: ["security", finding.category, finding.cwe].filter(Boolean)
        }
      });
    }
    results.push({
      ruleId: finding.ruleId,
      level: LEVEL[finding.severity] || "warning",
      message: { text: messageOf(finding) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: relativePath(finding) },
            region: { startLine: Math.max(1, Number(finding.line) || 1) }
          }
        }
      ],
      partialFingerprints: { primaryLocationLineHash: finding.fingerprint || finding.id },
      properties: { category: finding.category, repository: finding.repository, inTestFile: Boolean(finding.inTestFile) }
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: "https://github.com/lzwhehe/repo-vuln-scanner",
            version: TOOL_VERSION,
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}

export function toCsv(result) {
  const head = ["严重度", "类别", "说明", "仓库", "文件", "行号", "脱敏值/依赖", "修复版本", "CVE", "CWE", "测试文件", "指纹", "建议"];
  const esc = (v) => {
    const s = v === undefined || v === null ? "" : String(v);
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = (result.findings || []).map((f) =>
    [
      f.severity,
      f.category,
      f.label,
      f.repository || "",
      relativePath(f),
      f.line || "",
      f.package ? `${f.package.name}@${f.package.version}` : f.masked,
      f.package?.fixedVersion || "",
      (f.possibleCves || []).join(" "),
      f.cwe || "",
      f.inTestFile ? "是" : "",
      f.fingerprint || f.id,
      f.advice || ""
    ]
      .map(esc)
      .join(",")
  );
  return "﻿" + [head.join(","), ...rows].join("\n");
}

/** 是否存在不低于阈值的结果（用于 CI 判失败） */
export function failsThreshold(result, failOn = "low") {
  const threshold = RANK[failOn] || 1;
  return (result.findings || []).some((f) => (RANK[f.severity] || 0) >= threshold);
}
