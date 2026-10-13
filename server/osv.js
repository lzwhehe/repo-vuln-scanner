// 依赖漏洞检测：解析锁文件得到精确版本 → OSV.dev 批量查询（免 key，覆盖全量 GHSA / PyPA / RustSec 等）
// OSV 不可用时由调用方回退到内置的静态依赖规则。

const OSV_API = (process.env.OSV_API || "https://api.osv.dev").replace(/\/$/, "");
const BATCH_SIZE = 500;
const DETAIL_CONCURRENCY = 8;
const DETAIL_TTL_MS = 12 * 3600 * 1000;
const detailCache = new Map();

const LOCKFILE_PATTERN = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|requirements[^/]*\.txt|poetry\.lock|Cargo\.lock)$/i;

export function isSupportedLockfile(filePath) {
  return LOCKFILE_PATTERN.test(String(filePath || "").replace(/\\/g, "/"));
}

/** 解析锁文件，返回 [{ name, version, ecosystem, line, dev }] */
export function parseLockfile(filePath, text) {
  const name = String(filePath || "").replace(/\\/g, "/").split("/").pop().toLowerCase();
  try {
    if (name === "package-lock.json" || name === "npm-shrinkwrap.json") return parseNpmLock(text);
    if (name === "yarn.lock") return parseYarnLock(text);
    if (name.startsWith("requirements") && name.endsWith(".txt")) return parseRequirements(text);
    if (name === "poetry.lock") return parseTomlPackages(text, "PyPI");
    if (name === "cargo.lock") return parseTomlPackages(text, "crates.io");
  } catch {
    return [];
  }
  return [];
}

function lineIndex(text) {
  const lines = String(text).split(/\r?\n/);
  return { lines, find: (re) => lines.findIndex((l) => re.test(l)) + 1 || 1 };
}

function parseNpmLock(text) {
  const lock = JSON.parse(text);
  const { lines } = lineIndex(text);
  const out = [];
  if (lock.packages && typeof lock.packages === "object") {
    // v2 / v3：key 是 node_modules 路径，包名取最后一个 node_modules/ 之后的部分（兼容 @scope/name）
    const keyLine = new Map();
    lines.forEach((l, i) => {
      const m = l.match(/^\s*"((?:[^"]*\/)?node_modules\/[^"]+)":\s*\{/);
      if (m && !keyLine.has(m[1])) keyLine.set(m[1], i + 1);
    });
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key || entry.link) continue;
      const pkgName = entry.name || key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      if (!pkgName || !isExactVersion(entry.version)) continue;
      out.push({ name: pkgName, version: entry.version, ecosystem: "npm", dev: Boolean(entry.dev), line: keyLine.get(key) || 1 });
    }
  } else if (lock.dependencies) {
    // v1：递归 dependencies
    const walk = (deps) => {
      for (const [pkgName, entry] of Object.entries(deps || {})) {
        if (isExactVersion(entry.version)) {
          out.push({ name: pkgName, version: entry.version, ecosystem: "npm", dev: Boolean(entry.dev), line: 1 });
        }
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return out;
}

function parseYarnLock(text) {
  // yarn v1：块头形如 "@scope/a@^1.0.0", a@~1.2:   块内 version "1.2.3"
  const lines = String(text).split(/\r?\n/);
  const out = [];
  let header = null;
  lines.forEach((l, i) => {
    if (l && !l.startsWith(" ") && !l.startsWith("#") && l.trimEnd().endsWith(":")) {
      const first = l.trimEnd().slice(0, -1).split(",")[0].trim().replace(/^"|"$/g, "");
      const at = first.lastIndexOf("@");
      header = { name: at > 0 ? first.slice(0, at) : first, line: i + 1 };
      return;
    }
    const m = l.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (header && m && isExactVersion(m[1])) {
      out.push({ name: header.name, version: m[1], ecosystem: "npm", dev: false, line: header.line });
      header = null;
    }
  });
  return out;
}

function parseRequirements(text) {
  const out = [];
  String(text)
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const l = raw.replace(/#.*/, "").trim();
      if (!l || l.startsWith("-")) return;
      // 只认 == 精确版本；其它写法版本不确定，不查询
      const m = l.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)/);
      if (m) out.push({ name: m[1], version: m[2], ecosystem: "PyPI", dev: false, line: i + 1 });
    });
  return out;
}

function parseTomlPackages(text, ecosystem) {
  // poetry.lock / Cargo.lock：[[package]] 块内的 name = "…" 与 version = "…"
  const out = [];
  let current = null;
  String(text)
    .split(/\r?\n/)
    .forEach((l, i) => {
      if (/^\[\[package\]\]/.test(l.trim())) {
        if (current?.name && current.version) out.push(current);
        current = { ecosystem, dev: false, line: i + 1 };
        return;
      }
      if (!current) return;
      const m = l.match(/^(name|version|category)\s*=\s*"([^"]+)"/);
      if (m) {
        if (m[1] === "category") current.dev = m[2] === "dev";
        else current[m[1]] = m[2];
      }
    });
  if (current?.name && current.version) out.push(current);
  return out;
}

function isExactVersion(v) {
  return typeof v === "string" && /^\d+(\.\d+)*([-+.][0-9A-Za-z.-]+)?$/.test(v);
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "repo-vuln-scanner" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000)
  });
  if (!response.ok) throw new Error(`OSV HTTP ${response.status}`);
  return response.json();
}

async function getVuln(id) {
  const cached = detailCache.get(id);
  if (cached && Date.now() - cached.at < DETAIL_TTL_MS) return cached.data;
  const response = await fetch(`${OSV_API}/v1/vulns/${encodeURIComponent(id)}`, {
    headers: { "User-Agent": "repo-vuln-scanner" },
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error(`OSV vuln HTTP ${response.status}`);
  const data = await response.json();
  detailCache.set(id, { at: Date.now(), data });
  return data;
}

/**
 * 批量查询：返回 Map<"ecosystem|name|version", vulnDetail[]>。
 * querybatch 只返回 id，详情再并发拉取 /v1/vulns/{id} 并缓存。
 */
export async function queryOsv(packages) {
  const unique = new Map();
  for (const p of packages) unique.set(`${p.ecosystem}|${p.name}|${p.version}`, p);
  const keys = [...unique.keys()];
  const idsByKey = new Map();

  for (let i = 0; i < keys.length; i += BATCH_SIZE) {
    const chunk = keys.slice(i, i + BATCH_SIZE);
    const body = {
      queries: chunk.map((k) => {
        const p = unique.get(k);
        return { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version };
      })
    };
    const data = await postJson(`${OSV_API}/v1/querybatch`, body);
    (data.results || []).forEach((r, idx) => {
      const ids = (r.vulns || []).map((v) => v.id);
      if (ids.length) idsByKey.set(chunk[idx], ids);
    });
  }

  const allIds = [...new Set([...idsByKey.values()].flat())];
  const details = new Map();
  const queue = [...allIds];
  async function worker() {
    for (let id = queue.shift(); id; id = queue.shift()) {
      try {
        details.set(id, await getVuln(id));
      } catch {
        details.set(id, { id, summary: "", aliases: [] });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, queue.length) }, worker));

  const result = new Map();
  for (const [key, ids] of idsByKey) result.set(key, ids.map((id) => details.get(id)).filter(Boolean));
  return result;
}

const SEVERITY_FROM_DB = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

/** 严重度：优先用公告给出的等级（GHSA），否则按 CVSS v3 向量计算 */
export function severityOf(vuln) {
  const db = String(vuln.database_specific?.severity || "").toUpperCase();
  if (SEVERITY_FROM_DB[db]) return { severity: SEVERITY_FROM_DB[db], score: cvssFromVuln(vuln) };
  const score = cvssFromVuln(vuln);
  if (score === undefined) return { severity: "medium", score };
  return { severity: score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low", score };
}

function cvssFromVuln(vuln) {
  const vector = (vuln.severity || []).find((s) => /^CVSS_V3/.test(s.type))?.score;
  return vector ? cvss3BaseScore(vector) : undefined;
}

/** CVSS v3.x 基础分（按 FIRST 规范计算） */
export function cvss3BaseScore(vector) {
  const m = Object.fromEntries(
    String(vector)
      .split("/")
      .slice(1)
      .map((part) => part.split(":"))
  );
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 }
  };
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return undefined;
  const changed = m.S === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  if (impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(raw * 10) / 10;
}

/** 选出比当前版本高的最低修复版本 */
export function fixedVersionFor(vuln, pkg) {
  const fixes = [];
  for (const affected of vuln.affected || []) {
    const sameName = String(affected.package?.name || "").toLowerCase() === pkg.name.toLowerCase();
    if (!sameName) continue;
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) if (event.fixed) fixes.push(event.fixed);
    }
  }
  const higher = fixes.filter((v) => compareVersions(v, pkg.version) > 0).sort(compareVersions);
  return higher[0] || fixes.sort(compareVersions)[0];
}

export function compareVersions(a, b) {
  const pa = String(a).split(/[.+-]/);
  const pb = String(b).split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

function upgradeCommand(pkg, fixed) {
  if (!fixed) return undefined;
  if (pkg.ecosystem === "npm") return `npm install ${pkg.name}@${fixed}`;
  if (pkg.ecosystem === "PyPI") return `pip install "${pkg.name}>=${fixed}"`;
  if (pkg.ecosystem === "crates.io") return `cargo update -p ${pkg.name} --precise ${fixed}`;
  return undefined;
}

function fnv(value) {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

/** 把 OSV 结果转成与其它规则一致的 finding 结构 */
export function buildDependencyFindings({ file, packages, osvResult, source, repository, fileUrl }) {
  const findings = [];
  for (const pkg of packages) {
    const vulns = osvResult.get(`${pkg.ecosystem}|${pkg.name}|${pkg.version}`) || [];
    for (const vuln of vulns) {
      const { severity, score } = severityOf(vuln);
      const fixed = fixedVersionFor(vuln, pkg);
      const cves = (vuln.aliases || []).filter((a) => /^CVE-/.test(a));
      const cwes = vuln.database_specific?.cwe_ids || [];
      const upgrade = upgradeCommand(pkg, fixed);
      findings.push({
        id: `osv-${vuln.id}-${file}-${pkg.name}@${pkg.version}`,
        ruleId: `osv:${vuln.id}`,
        label: `${pkg.name}@${pkg.version} 存在已知漏洞 ${cves[0] || vuln.id}`,
        severity: pkg.dev && severity === "critical" ? "high" : severity,
        stage: "dependency-osv",
        repository,
        file,
        fileUrl: fileUrl ? fileUrl(pkg.line) : undefined,
        line: pkg.line,
        source,
        provider: "OSV.dev",
        category: "dependency-cve",
        evidenceLevel: "osv_advisory",
        sourceRuleSet: "osv",
        actionable: true,
        masked: "[dependency]",
        context: `${pkg.name}@${pkg.version}${pkg.dev ? "（开发依赖）" : ""} · ${vuln.summary || vuln.id}`.slice(0, 260),
        entropy: 0,
        cwe: cwes[0],
        possibleCves: cves,
        fingerprint: fnv(`osv|${vuln.id}|${pkg.ecosystem}|${pkg.name}|${file}`),
        advisory: {
          id: vuln.id,
          aliases: vuln.aliases || [],
          summary: vuln.summary || "",
          url: `https://osv.dev/vulnerability/${vuln.id}`,
          cvss: score,
          published: vuln.published
        },
        package: {
          name: pkg.name,
          version: pkg.version,
          ecosystem: pkg.ecosystem,
          dev: Boolean(pkg.dev),
          fixedVersion: fixed,
          upgrade
        },
        advice: fixed
          ? `升级 ${pkg.name} 到 ${fixed} 或更高版本${upgrade ? `：${upgrade}` : ""}。`
          : `${pkg.name} 暂无官方修复版本，评估替换组件或按公告中的缓解措施处理。`,
        exploitability: {
          summary: "依赖组件存在已公开披露的漏洞；能否被利用取决于项目是否调用了受影响的功能。",
          confidence: "high",
          modes: [
            {
              title: "已知漏洞利用",
              impact: vuln.summary || "参见公告详情。",
              prerequisites: "受影响版本被打包进生产环境，且存在可达的调用路径。"
            }
          ],
          safeTests: [],
          limitation: "结论来自 OSV.dev 公告与锁文件中的精确版本，未做调用可达性分析。"
        }
      });
    }
  }
  return findings;
}

/** 对一组锁文件执行依赖检测；失败时返回 ok:false，由调用方保留静态规则结果 */
export async function scanDependencies(manifests) {
  const started = Date.now();
  const parsed = manifests
    .map((m) => ({ ...m, packages: parseLockfile(m.path, m.text) }))
    .filter((m) => m.packages.length);
  const totalPackages = parsed.reduce((n, m) => n + m.packages.length, 0);
  if (!parsed.length) return { ok: true, findings: [], files: [], packages: 0, vulnerable: 0, ms: 0 };
  try {
    const osvResult = await queryOsv(parsed.flatMap((m) => m.packages));
    const findings = parsed.flatMap((m) =>
      buildDependencyFindings({
        file: m.file,
        packages: m.packages,
        osvResult,
        source: m.source,
        repository: m.repository,
        fileUrl: m.fileUrl
      })
    );
    return {
      ok: true,
      findings,
      files: parsed.map((m) => m.file),
      packages: totalPackages,
      vulnerable: new Set(findings.map((f) => `${f.package.ecosystem}|${f.package.name}|${f.package.version}`)).size,
      ms: Date.now() - started
    };
  } catch (error) {
    return {
      ok: false,
      findings: [],
      files: [],
      packages: totalPackages,
      vulnerable: 0,
      ms: Date.now() - started,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}
