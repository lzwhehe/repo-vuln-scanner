import { promises as fs } from "node:fs";
import path from "node:path";
import { del, get, put } from "@vercel/blob";

const VAULT_VERSION = 1;
const VAULT_BLOB_PATH = "token-guardian/vulnerability-vault.json";
const LOCAL_VAULT_PATH = path.join(process.cwd(), ".scanner-data", "vault.json");
const MAX_FINDINGS = 500;
const MAX_PROJECTS = 200;
const MAX_SCANS = 50;
const MAX_ANALYSES = 300;

export async function getVault() {
  const backend = resolveStorageBackend();
  const vault = await readVaultFromBackend(backend);
  return {
    storage: publicStorageStatus(backend),
    vault: publicVault(vault)
  };
}

export async function persistScanResult(result) {
  const backend = resolveStorageBackend();
  if (backend.type === "disabled") {
    return {
      storage: publicStorageStatus(backend),
      vault: publicVault(createEmptyVault())
    };
  }

  const current = await readVaultFromBackend(backend);
  const next = mergeScanIntoVault(current, result);
  await writeVaultToBackend(backend, next);

  return {
    storage: publicStorageStatus(backend),
    vault: publicVault(next)
  };
}

export async function clearVault() {
  const backend = resolveStorageBackend();
  if (backend.type === "disabled") {
    return {
      storage: publicStorageStatus(backend),
      vault: publicVault(createEmptyVault())
    };
  }

  const emptyVault = createEmptyVault();
  if (backend.type === "blob") {
    try {
      await del(VAULT_BLOB_PATH);
    } catch (error) {
      if (!isBlobNotFound(error)) throw error;
    }
  } else {
    await fs.rm(LOCAL_VAULT_PATH, { force: true });
  }

  return {
    storage: publicStorageStatus(backend),
    vault: publicVault(emptyVault)
  };
}

export async function persistAnalysisResult(analysisRecord) {
  const backend = resolveStorageBackend();
  if (backend.type === "disabled") {
    return {
      storage: publicStorageStatus(backend),
      vault: publicVault(createEmptyVault())
    };
  }

  const current = await readVaultFromBackend(backend);
  const next = mergeAnalysisIntoVault(current, analysisRecord);
  await writeVaultToBackend(backend, next);

  return {
    storage: publicStorageStatus(backend),
    vault: publicVault(next)
  };
}

export function mergeAnalysisIntoVault(vault, analysisRecord) {
  const base = normalizeVault(vault);
  const now = new Date().toISOString();
  const safeRecord = sanitizeAnalysisRecord(analysisRecord, now);
  const analyses = new Map(base.analyses.map((analysis) => [analysis.id, analysis]));
  analyses.set(safeRecord.id, safeRecord);

  const findings = base.findings.map((finding) =>
    safeRecord.findingKeys.includes(finding.key)
      ? {
          ...finding,
          aiAnalysis: {
            id: safeRecord.id,
            status: safeRecord.status,
            riskRating: safeRecord.result?.riskRating,
            exploitability: safeRecord.result?.exploitability,
            analyzedAt: safeRecord.analyzedAt
          }
        }
      : finding
  );

  const next = {
    ...base,
    updatedAt: now,
    analyses: [...analyses.values()]
      .sort((left, right) => new Date(right.analyzedAt) - new Date(left.analyzedAt))
      .slice(0, MAX_ANALYSES),
    findings
  };
  next.analysisCount = next.analyses.length;
  return next;
}

export function mergeScanIntoVault(vault, result) {
  const now = new Date().toISOString();
  const scannedAt = result.scannedAt || now;
  const base = normalizeVault(vault);
  const scanRecord = sanitizeScanRecord(result, scannedAt);

  const projects = new Map(base.projects.map((project) => [project.name, project]));
  for (const project of result.riskProjects || []) {
    const safeProject = sanitizeProjectRecord(project, scannedAt);
    const current = projects.get(safeProject.name);
    projects.set(safeProject.name, mergeProjectRecord(current, safeProject));
  }

  const findings = new Map(base.findings.map((finding) => [finding.key, finding]));
  for (const finding of result.findings || []) {
    const safeFinding = sanitizeFindingRecord(finding, scannedAt);
    const current = findings.get(safeFinding.key);
    findings.set(safeFinding.key, mergeFindingRecord(current, safeFinding));
  }

  const next = {
    ...base,
    updatedAt: now,
    scans: [scanRecord, ...base.scans].slice(0, MAX_SCANS),
    projects: [...projects.values()]
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || new Date(right.lastSeenAt) - new Date(left.lastSeenAt))
      .slice(0, MAX_PROJECTS),
    findings: [...findings.values()]
      .sort((left, right) => severityRank(right.severity) - severityRank(left.severity) || new Date(right.lastSeenAt) - new Date(left.lastSeenAt))
      .slice(0, MAX_FINDINGS)
  };

  next.scanCount = next.scans.length;
  next.projectCount = next.projects.length;
  next.vulnerabilityCount = next.findings.length;
  return next;
}

function resolveStorageBackend() {
  if (process.env.BLOB_READ_WRITE_TOKEN || (process.env.VERCEL_OIDC_TOKEN && process.env.BLOB_STORE_ID)) {
    return {
      type: "blob",
      configured: true,
      label: "Vercel Blob",
      path: VAULT_BLOB_PATH
    };
  }

  if (process.env.VERCEL) {
    return {
      type: "disabled",
      configured: false,
      label: "Not configured",
      reason: "Vercel Blob is not configured. Add a Blob store so findings can survive deployments."
    };
  }

  return {
    type: "local-file",
    configured: true,
    label: "Local JSON file",
    path: LOCAL_VAULT_PATH
  };
}

function publicStorageStatus(backend) {
  return {
    type: backend.type,
    configured: backend.configured,
    label: backend.label,
    path: backend.path,
    reason: backend.reason
  };
}

async function readVaultFromBackend(backend) {
  if (backend.type === "disabled") return createEmptyVault();
  if (backend.type === "blob") return readBlobVault();
  return readLocalVault();
}

async function writeVaultToBackend(backend, vault) {
  const serialized = JSON.stringify(vault, null, 2);
  if (backend.type === "blob") {
    await put(VAULT_BLOB_PATH, serialized, {
      access: "private",
      allowOverwrite: true,
      contentType: "application/json",
      cacheControlMaxAge: 60
    });
    return;
  }

  await fs.mkdir(path.dirname(LOCAL_VAULT_PATH), { recursive: true });
  await fs.writeFile(LOCAL_VAULT_PATH, serialized);
}

async function readBlobVault() {
  try {
    const response = await get(VAULT_BLOB_PATH, { access: "private", useCache: false });
    if (!response?.stream) return createEmptyVault();
    return parseVault(await streamToString(response.stream));
  } catch (error) {
    if (isBlobNotFound(error)) return createEmptyVault();
    throw error;
  }
}

async function readLocalVault() {
  try {
    return parseVault(await fs.readFile(LOCAL_VAULT_PATH, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return createEmptyVault();
    throw error;
  }
}

async function streamToString(stream) {
  const reader = stream.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseVault(text) {
  try {
    return normalizeVault(JSON.parse(text));
  } catch {
    return createEmptyVault();
  }
}

function normalizeVault(vault) {
  return {
    version: VAULT_VERSION,
    createdAt: vault?.createdAt || new Date().toISOString(),
    updatedAt: vault?.updatedAt || null,
    scanCount: Number(vault?.scanCount || vault?.scans?.length || 0),
    projectCount: Number(vault?.projectCount || vault?.projects?.length || 0),
    vulnerabilityCount: Number(vault?.vulnerabilityCount || vault?.findings?.length || 0),
    analysisCount: Number(vault?.analysisCount || vault?.analyses?.length || 0),
    scans: Array.isArray(vault?.scans) ? vault.scans : [],
    projects: Array.isArray(vault?.projects) ? vault.projects : [],
    findings: Array.isArray(vault?.findings) ? vault.findings : [],
    analyses: Array.isArray(vault?.analyses) ? vault.analyses : []
  };
}

function createEmptyVault() {
  return {
    version: VAULT_VERSION,
    createdAt: new Date().toISOString(),
    updatedAt: null,
    scanCount: 0,
    projectCount: 0,
    vulnerabilityCount: 0,
    analysisCount: 0,
    scans: [],
    projects: [],
    findings: [],
    analyses: []
  };
}

function publicVault(vault) {
  return {
    ...vault,
    findings: vault.findings.map((finding) => ({
      key: finding.key,
      ruleId: finding.ruleId,
      label: finding.label,
      severity: finding.severity,
      stage: finding.stage,
      repository: finding.repository,
      file: finding.file,
      fileUrl: finding.fileUrl,
      line: finding.line,
      source: finding.source,
      provider: finding.provider,
      category: finding.category,
      cwe: finding.cwe,
      possibleCves: finding.possibleCves,
      evidenceLevel: finding.evidenceLevel,
      sourceRuleSet: finding.sourceRuleSet,
      actionable: finding.actionable,
      masked: finding.masked,
      context: finding.context,
      exploitability: finding.exploitability,
      verification: finding.verification,
      aiAnalysis: finding.aiAnalysis,
      firstSeenAt: finding.firstSeenAt,
      lastSeenAt: finding.lastSeenAt,
      occurrences: finding.occurrences
    })),
    analyses: vault.analyses.map((analysis) => ({
      id: analysis.id,
      findingKeys: analysis.findingKeys,
      file: analysis.file,
      repository: analysis.repository,
      status: analysis.status,
      model: analysis.model,
      provider: analysis.provider,
      analyzedAt: analysis.analyzedAt,
      result: analysis.result,
      codeEvidence: analysis.codeEvidence
    }))
  };
}

function sanitizeScanRecord(result, scannedAt) {
  return {
    id: `scan-${Date.parse(scannedAt) || Date.now()}-${fingerprint(`${result.target}:${scannedAt}`)}`,
    target: result.target,
    mode: result.mode,
    scannedAt,
    durationMs: result.durationMs,
    summary: result.summary,
    repositoryCount: result.repositories?.length || 0,
    findingCount: result.findings?.length || 0,
    riskProjectCount: result.riskProjects?.length || 0
  };
}

function sanitizeProjectRecord(project, scannedAt) {
  return {
    name: project.name,
    url: project.url,
    description: project.description || "",
    language: project.language || null,
    stars: project.stars || 0,
    topics: project.topics || [],
    severity: project.severity,
    findingCount: project.findingCount || 0,
    files: project.files || [],
    fileLocations: project.fileLocations || [],
    rules: project.rules || [],
    stages: project.stages || [],
    providers: project.providers || [],
    categories: project.categories || [],
    firstSeenAt: project.firstDetectedAt || scannedAt,
    lastSeenAt: project.lastDetectedAt || scannedAt,
    occurrences: 1
  };
}

function sanitizeFindingRecord(finding, scannedAt) {
  const key =
    finding.id ||
    `${finding.ruleId}:${finding.repository || ""}:${finding.file}:${finding.line || "file"}:${fingerprint(finding.masked || finding.context || "")}`;
  return {
    key,
    ruleId: finding.ruleId,
    label: finding.label,
    severity: finding.severity,
    stage: finding.stage,
    repository: finding.repository,
    file: finding.file,
    fileUrl: finding.fileUrl,
    line: finding.line,
    source: finding.source,
    provider: finding.provider,
    category: finding.category,
    cwe: finding.cwe,
    possibleCves: finding.possibleCves || [],
    evidenceLevel: finding.evidenceLevel,
    sourceRuleSet: finding.sourceRuleSet,
    actionable: finding.actionable,
    masked: finding.masked,
    context: finding.context,
    entropy: finding.entropy,
    exploitability: finding.exploitability,
    verification: finding.verification,
    aiAnalysis: finding.aiAnalysis,
    firstSeenAt: scannedAt,
    lastSeenAt: scannedAt,
    occurrences: 1
  };
}

function sanitizeAnalysisRecord(record, analyzedAt) {
  const findingKeys = Array.isArray(record.findingKeys) ? record.findingKeys.filter(Boolean) : [];
  const id = record.id || `analysis-${fingerprint(`${findingKeys.join(":")}:${analyzedAt}`)}`;
  return {
    id,
    findingKeys,
    file: record.file,
    repository: record.repository,
    status: record.status || "completed",
    model: record.model,
    provider: record.provider,
    analyzedAt: record.analyzedAt || analyzedAt,
    result: record.result,
    codeEvidence: record.codeEvidence
  };
}

function mergeProjectRecord(current, next) {
  if (!current) return next;
  return {
    ...current,
    ...next,
    severity: higherSeverity(current.severity, next.severity),
    findingCount: Math.max(current.findingCount || 0, next.findingCount || 0),
    files: uniqueStrings([...(current.files || []), ...(next.files || [])]),
    fileLocations: mergeFileLocations(current.fileLocations, next.fileLocations),
    rules: uniqueStrings([...(current.rules || []), ...(next.rules || [])]),
    stages: uniqueStrings([...(current.stages || []), ...(next.stages || [])]),
    providers: uniqueStrings([...(current.providers || []), ...(next.providers || [])]),
    categories: uniqueStrings([...(current.categories || []), ...(next.categories || [])]),
    firstSeenAt: current.firstSeenAt || next.firstSeenAt,
    lastSeenAt: next.lastSeenAt || new Date().toISOString(),
    occurrences: (current.occurrences || 1) + 1
  };
}

function mergeFindingRecord(current, next) {
  if (!current) return next;
  return {
    ...current,
    ...next,
    severity: higherSeverity(current.severity, next.severity),
    firstSeenAt: current.firstSeenAt || next.firstSeenAt,
    lastSeenAt: next.lastSeenAt || new Date().toISOString(),
    occurrences: (current.occurrences || 1) + 1
  };
}

function mergeFileLocations(currentLocations = [], newLocations = []) {
  const locations = new Map();
  for (const location of [...currentLocations, ...newLocations]) {
    if (!location?.path && !location?.url) continue;
    const key = location.path || location.url;
    const current = locations.get(key);
    locations.set(key, {
      ...current,
      ...location,
      url: location.url || current?.url || null,
      findingCount: Math.max(current?.findingCount || 0, location.findingCount || 0),
      lines: uniqueStrings([...(current?.lines || []), ...(location.lines || [])])
    });
  }
  return [...locations.values()];
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ""))];
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

function fingerprint(value) {
  let hash = 2166136261;
  for (let index = 0; index < String(value).length; index += 1) {
    hash ^= String(value).charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}

function isBlobNotFound(error) {
  return error?.name === "BlobNotFoundError" || /not found/i.test(error?.message || "");
}
