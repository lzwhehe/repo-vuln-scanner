import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  Brain,
  CheckCircle2,
  Clock3,
  Code2,
  Copy,
  FileSearch,
  FolderSearch,
  Github,
  History,
  KeyRound,
  Loader2,
  LocateFixed,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
  Terminal
} from "lucide-react";
import "./styles.css";

const isLocalBrowser =
  typeof window === "undefined" ||
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";
const HOSTED_MODE = !isLocalBrowser && !import.meta.env.VITE_API_BASE;
const API_BASE = import.meta.env.VITE_API_BASE || (HOSTED_MODE ? "" : "http://localhost:8787");
const RISK_VAULT_KEY = "vulnerability-scanner-risk-projects";
const LEGACY_RISK_VAULT_KEY = "token-guardian-risk-projects";
const DEFAULT_ANALYSIS_MODEL = "gpt-5.4-mini";
const analysisProviders = {
  openai: {
    label: "OpenAI",
    defaultModel: "gpt-5.4-mini",
    placeholder: "OpenAI API Key，不会保存"
  },
  deepseek: {
    label: "DeepSeek",
    defaultModel: "deepseek-v4-pro",
    placeholder: "DeepSeek API Key，不会保存"
  }
};

const severityLabels = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危"
};

const severityOrder = ["critical", "high", "medium", "low"];
const confidenceLabels = {
  high: "高置信",
  medium: "中置信",
  low: "低置信"
};

function App() {
  const [activePage, setActivePage] = useState("scan");
  const [targetType, setTargetType] = useState(HOSTED_MODE ? "explore" : "local");
  const [target, setTarget] = useState(
    HOSTED_MODE ? "github:explore" : "/Users/a0000/vibe_coding"
  );
  const [scanHistory, setScanHistory] = useState(false);
  const [maxHistoryCommits, setMaxHistoryCommits] = useState(200);
  const [maxRepositories, setMaxRepositories] = useState(60);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [riskVault, setRiskVault] = useState(() => actionableRiskProjects(loadRiskVault()));
  const [vaultData, setVaultData] = useState(() => createEmptyClientVault(actionableRiskProjects(loadRiskVault())));
  const [vaultStatus, setVaultStatus] = useState({
    loading: true,
    storage: null,
    error: ""
  });
  const [aiKey, setAiKey] = useState("");
  const [aiProvider, setAiProvider] = useState("openai");
  const [analysisModel, setAnalysisModel] = useState(DEFAULT_ANALYSIS_MODEL);
  const [analysisLoading, setAnalysisLoading] = useState("");
  const [analysisError, setAnalysisError] = useState("");
  const [apiTestLoading, setApiTestLoading] = useState(false);
  const [apiTestResult, setApiTestResult] = useState(null);
  const [apiTestError, setApiTestError] = useState("");

  const findings = result?.findings || [];
  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      const text = `${finding.repository || ""} ${finding.file} ${finding.label} ${finding.context} ${finding.cwe || ""} ${(finding.possibleCves || []).join(" ")}`.toLowerCase();
      const matchesQuery = !query || text.includes(query.toLowerCase());
      const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter;
      const matchesSource = sourceFilter === "all" || finding.source === sourceFilter;
      return matchesQuery && matchesSeverity && matchesSource;
    });
  }, [findings, query, severityFilter, sourceFilter]);
  const highRiskFiles = useMemo(() => buildHighRiskFiles(vaultData), [vaultData]);

  useEffect(() => {
    let active = true;
    async function loadPersistentVault() {
      try {
        const response = await fetch(`${API_BASE}/api/vault`);
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "漏洞仓库读取失败");
        if (!active) return;

        const serverProjects = actionableRiskProjects(payload.vault?.projects || []);
        setVaultData(payload.vault || createEmptyClientVault(serverProjects));
        setRiskVault((currentVault) => persistRiskVault(mergeRiskProjects(currentVault, serverProjects)));
        setVaultStatus({ loading: false, storage: payload.storage, error: "" });
      } catch (vaultError) {
        if (!active) return;
        setVaultStatus({
          loading: false,
          storage: null,
          error: vaultError instanceof Error ? vaultError.message : "漏洞仓库读取失败"
        });
      }
    }

    loadPersistentVault();
    return () => {
      active = false;
    };
  }, []);

  async function runScan(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          githubApiMode: targetType === "github" || targetType === "explore",
          scanHistory: HOSTED_MODE ? false : scanHistory,
          maxHistoryCommits,
          maxRepositories,
          maxFilesPerRepo: 80,
          scanTheme: targetType === "explore" ? "ai" : undefined
        })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "扫描失败");
      setResult(payload);
      if (payload.riskProjects?.length) {
        const persistedProjects = actionableRiskProjects(payload.persistence?.vault?.projects || payload.riskProjects);
        setRiskVault((currentVault) => persistRiskVault(mergeRiskProjects(currentVault, persistedProjects)));
      }
      if (payload.persistence?.vault) {
        setVaultData(payload.persistence.vault);
      }
      if (payload.persistence?.storage) {
        setVaultStatus({ loading: false, storage: payload.persistence.storage, error: "" });
      }
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "扫描失败");
    } finally {
      setLoading(false);
    }
  }

  function applyTargetType(nextType) {
    if (HOSTED_MODE && nextType === "local") return;
    setTargetType(nextType);
    if (nextType === "local") setTarget("/Users/a0000/vibe_coding");
    if (nextType === "github") setTarget("https://github.com/lzwhehe");
    if (nextType === "explore") setTarget("github:explore");
  }

  async function clearRiskVault() {
    setRiskVault(persistRiskVault([]));
    setVaultData(createEmptyClientVault());
    try {
      const response = await fetch(`${API_BASE}/api/vault`, { method: "DELETE" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "漏洞仓库清空失败");
      setVaultData(payload.vault || createEmptyClientVault());
      setVaultStatus({ loading: false, storage: payload.storage, error: "" });
    } catch (vaultError) {
      setVaultStatus((current) => ({
        ...current,
        loading: false,
        error: vaultError instanceof Error ? vaultError.message : "漏洞仓库清空失败"
      }));
    }
  }

  async function runAiAnalysis(findingKeys = []) {
    const loadingKey = findingKeys.length ? findingKeys.join(":") : "all";
    setAnalysisLoading(loadingKey);
    setAnalysisError("");

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          apiKey: aiKey.trim() || undefined,
          findingKeys,
          provider: aiProvider,
          model: analysisModel.trim() || analysisProviders[aiProvider]?.defaultModel || DEFAULT_ANALYSIS_MODEL
        })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "AI 深度分析失败");
      if (payload.vault) {
        setVaultData(payload.vault);
        setRiskVault(persistRiskVault(payload.vault.projects || []));
      }
    } catch (analysisErrorValue) {
      setAnalysisError(analysisErrorValue instanceof Error ? analysisErrorValue.message : "AI 深度分析失败");
    } finally {
      setAnalysisLoading("");
    }
  }

  async function runApiAvailabilityTest() {
    setApiTestLoading(true);
    setApiTestResult(null);
    setApiTestError("");
    setAnalysisError("");

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          testOnly: true,
          apiKey: aiKey.trim() || undefined,
          provider: aiProvider,
          model: analysisModel.trim() || analysisProviders[aiProvider]?.defaultModel || DEFAULT_ANALYSIS_MODEL
        })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "API 可用性测试失败");
      setApiTestResult(payload);
    } catch (apiTestErrorValue) {
      setApiTestError(apiTestErrorValue instanceof Error ? apiTestErrorValue.message : "API 可用性测试失败");
    } finally {
      setApiTestLoading(false);
    }
  }

  function changeAiProvider(provider) {
    setAiProvider(provider);
    setAnalysisModel(analysisProviders[provider]?.defaultModel || DEFAULT_ANALYSIS_MODEL);
    setAiKey("");
    setApiTestResult(null);
    setApiTestError("");
    setAnalysisError("");
  }

  return (
    <main className="app-shell">
      <section className="workspace">
        <aside className="control-panel">
          <div className="brand-row">
            <div className="brand-mark" aria-hidden="true">
              <ShieldCheck size={24} />
            </div>
            <div>
              <h1>漏洞扫描器</h1>
              <p>CVE / 安全漏洞匹配</p>
            </div>
          </div>

          <nav className="page-nav" aria-label="功能页面">
            <button
              type="button"
              className={activePage === "scan" ? "active" : ""}
              onClick={() => setActivePage("scan")}
            >
              <FileSearch size={16} />
              扫描面板
            </button>
            <button
              type="button"
              className={activePage === "risk-files" ? "active" : ""}
              onClick={() => setActivePage("risk-files")}
            >
              <AlertTriangle size={16} />
              高风险文件
            </button>
          </nav>

          {activePage === "scan" && (
          <form className="scan-form" onSubmit={runScan}>
            <div className="field-group">
              <label>目标类型</label>
              <div className="segmented three" role="group" aria-label="目标类型">
                <button
                  type="button"
                  className={targetType === "local" ? "active" : ""}
                  onClick={() => applyTargetType("local")}
                  disabled={HOSTED_MODE}
                  title="本地仓库路径"
                >
                  <FolderSearch size={16} />
                  本地
                </button>
                <button
                  type="button"
                  className={targetType === "github" ? "active" : ""}
                  onClick={() => applyTargetType("github")}
                  title="GitHub 仓库地址"
                >
                  <Github size={16} />
                  GitHub
                </button>
                <button
                  type="button"
                  className={targetType === "explore" ? "active" : ""}
                  onClick={() => applyTargetType("explore")}
                  title="持续探索 AI 相关 GitHub 公开项目"
                >
                  <FileSearch size={16} />
                  AI探索
                </button>
              </div>
            </div>

            <div className="field-group">
              <label htmlFor="target">
                {targetType === "explore"
                  ? "探索范围"
                  : targetType === "github"
                    ? "GitHub 目标"
                    : "仓库目标"}
              </label>
              <div className="input-shell">
                {targetType === "local" ? <Terminal size={16} /> : <Github size={16} />}
                <input
                  id="target"
                  value={target}
                  onChange={(event) => setTarget(event.target.value)}
                  readOnly={targetType === "explore"}
                  placeholder={
                    targetType === "local"
                      ? "/path/to/repo"
                      : targetType === "explore"
                        ? "github:explore"
                        : "https://github.com/lzwhehe 或 https://github.com/owner/repo"
                  }
                />
              </div>
            </div>

            {targetType === "github" || targetType === "explore" ? (
              <div className="option-row">
                <div className="option-copy">
                  <Github size={18} />
                  <span>{targetType === "explore" ? "AI 公开项目持续探索" : "账号级风险搜索"}</span>
                </div>
                <span className="mode-badge">当前代码树</span>
              </div>
            ) : (
              <div className="option-row">
                <div className="option-copy">
                  <History size={18} />
                  <span>扫描 Git 历史</span>
                </div>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={!HOSTED_MODE && scanHistory}
                    disabled={HOSTED_MODE}
                    onChange={(event) => setScanHistory(event.target.checked)}
                  />
                  <span />
                </label>
              </div>
            )}

            <div className="field-group">
              <label htmlFor="scan-limit">
                {targetType === "github" || targetType === "explore" ? "仓库扫描上限" : "历史提交上限"}
              </label>
              <div className="range-row">
                <input
                  id="scan-limit"
                  type="range"
                  min={targetType === "github" || targetType === "explore" ? "1" : "25"}
                  max={targetType === "github" || targetType === "explore" ? "500" : "1000"}
                  step={targetType === "github" || targetType === "explore" ? "5" : "25"}
                  value={targetType === "github" || targetType === "explore" ? maxRepositories : maxHistoryCommits}
                  disabled={targetType === "github" || targetType === "explore" ? false : HOSTED_MODE || !scanHistory}
                  onChange={(event) => {
                    const nextValue = Number(event.target.value);
                    if (targetType === "github" || targetType === "explore") setMaxRepositories(nextValue);
                    else setMaxHistoryCommits(nextValue);
                  }}
                />
                <output>{targetType === "github" || targetType === "explore" ? maxRepositories : maxHistoryCommits}</output>
              </div>
            </div>

            <button className="primary-action" disabled={loading || !target.trim()}>
              {loading ? <Loader2 className="spin" size={18} /> : <FileSearch size={18} />}
              {loading ? "扫描中" : "开始扫描"}
            </button>
          </form>
          )}

          {activePage === "scan" && (
          <div className="safe-box">
            <Code2 size={18} />
            <p>
              {HOSTED_MODE
                ? "AI 探索模式会持续发现 AI/LLM/RAG/Agent 相关公开项目；当前实时版按批次扫描并显示已扫描仓库。"
                : "结果会脱敏显示；发现真实泄露后应立即撤销并轮换对应凭证。"}
            </p>
          </div>
          )}
        </aside>

        <section className="result-panel">
          <header className="topbar">
            <div>
              <p className="eyebrow">{activePage === "risk-files" ? "High Risk Files" : "Vulnerability Audit"}</p>
              <h2>{activePage === "risk-files" ? "高风险文件分析" : "CVE 与漏洞扫描"}</h2>
            </div>
            <div className="api-status">
              <span className={loading || analysisLoading || apiTestLoading ? "status-dot busy" : "status-dot"} />
              {loading ? "Scanning" : analysisLoading ? "Analyzing" : apiTestLoading ? "Testing API" : "Ready"}
            </div>
          </header>

          {error && (
            <div className="notice error">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}

          {activePage === "risk-files" ? (
            <HighRiskFilesPage
              files={highRiskFiles}
              aiKey={aiKey}
              provider={aiProvider}
              model={analysisModel}
              loadingKey={analysisLoading}
              error={analysisError}
              apiTestLoading={apiTestLoading}
              apiTestResult={apiTestResult}
              apiTestError={apiTestError}
              onAiKeyChange={(nextKey) => {
                setAiKey(nextKey);
                setApiTestResult(null);
                setApiTestError("");
              }}
              onProviderChange={changeAiProvider}
              onModelChange={(nextModel) => {
                setAnalysisModel(nextModel);
                setApiTestResult(null);
                setApiTestError("");
              }}
              onAnalyze={runAiAnalysis}
              onApiTest={runApiAvailabilityTest}
            />
          ) : !result && !loading && !error && (
            <>
              <RiskProjectVault projects={riskVault} status={vaultStatus} onClear={clearRiskVault} />
              <EmptyState />
            </>
          )}
          {activePage === "scan" && loading && <LoadingState />}
          {activePage === "scan" && result && (
            <>
              <SummaryGrid result={result} />
              <PipelineStrip pipeline={result.pipeline || []} />
              <AggregationPanel aggregations={result.aggregations} />
              <RiskProjectVault projects={riskVault} status={vaultStatus} onClear={clearRiskVault} />
              <ScannedRepositories repositories={result.repositories || []} />
              <div className="filters">
                <div className="search-box">
                  <SlidersHorizontal size={16} />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="筛选文件、规则或上下文"
                  />
                </div>
                <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                  <option value="all">全部等级</option>
                  {severityOrder.map((severity) => (
                    <option value={severity} key={severity}>
                      {severityLabels[severity]}
                    </option>
                  ))}
                </select>
                <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                  <option value="all">全部来源</option>
                  <option value="github">GitHub 搜索</option>
                  <option value="current">当前文件</option>
                  <option value="history">Git 历史</option>
                </select>
              </div>
              <FindingsTable findings={filteredFindings} />
            </>
          )}
        </section>
      </section>
    </main>
  );
}

function RiskProjectVault({ projects, status, onClear }) {
  const statusLabel = vaultStatusLabel(status);
  if (!projects.length) {
    return (
      <section className="risk-vault empty">
        <header>
          <strong>风险项目收纳</strong>
          <span>{statusLabel}</span>
        </header>
        <p>
          检测到真实凭证、密码型连接串、高熵 secret、私钥内容或可定位的高危漏洞模式后，对应项目会自动收纳到这里。
          {status?.error ? ` ${status.error}` : ""}
        </p>
      </section>
    );
  }

  return (
    <section className="risk-vault">
      <header>
        <strong>风险项目收纳</strong>
        <div className="vault-header-actions">
          <span>{statusLabel}</span>
          <button type="button" onClick={onClear}>清空</button>
        </div>
      </header>
      {status?.error && <p className="vault-warning">{status.error}</p>}
      <div className="vault-list">
        {projects.map((project) => (
          <article className="vault-row" key={project.name}>
            <div>
              <a href={project.url || `https://github.com/${project.name}`} target="_blank" rel="noreferrer">
                {project.name}
              </a>
              <span>{project.description || "No description"}</span>
              <VaultFileLinks project={project} />
            </div>
            <div className="vault-meta">
              <span className={`pill ${project.severity}`}>{severityLabels[project.severity]}</span>
              <span>{project.findingCount} findings</span>
              <span>{normalizeFileLocations(project).length || project.files?.length || 0} files</span>
              <span>{project.rules?.slice(0, 2).join(", ")}</span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function vaultStatusLabel(status) {
  if (status?.loading) return "读取持久化仓库";
  if (status?.error) return "持久化异常";
  if (!status?.storage) return "本地收纳";
  if (!status.storage.configured) return "未配置持久化";
  if (status.storage.type === "blob") return "Vercel Blob 持久化";
  if (status.storage.type === "local-file") return "本地 JSON 持久化";
  return status.storage.label || "已持久化";
}

function VaultFileLinks({ project }) {
  const locations = normalizeFileLocations(project).slice(0, 3);
  if (!locations.length) return null;

  return (
    <div className="vault-files" aria-label={`${project.name} 风险文件定位`}>
      {locations.map((location) =>
        location.url ? (
          <a
            className="vault-file-link"
            href={location.url}
            target="_blank"
            rel="noreferrer"
            key={location.path}
            title={location.path}
          >
            <LocateFixed size={13} />
            <span>{location.displayPath || location.path}</span>
          </a>
        ) : (
          <span className="vault-file-fallback" key={location.path} title={location.path}>
            {location.displayPath || location.path}
          </span>
        )
      )}
    </div>
  );
}

function HighRiskFilesPage({
  files,
  aiKey,
  provider,
  model,
  loadingKey,
  error,
  apiTestLoading,
  apiTestResult,
  apiTestError,
  onAiKeyChange,
  onProviderChange,
  onModelChange,
  onAnalyze,
  onApiTest
}) {
  const totalFindings = files.reduce((sum, file) => sum + file.findings.length, 0);
  const providerConfig = analysisProviders[provider] || analysisProviders.openai;

  return (
    <section className="risk-files-page">
      <div className="risk-file-toolbar">
        <div className="risk-file-stats">
          <article>
            <strong>{files.length}</strong>
            <span>风险文件</span>
          </article>
          <article>
            <strong>{totalFindings}</strong>
            <span>命中记录</span>
          </article>
        </div>
        <div className="ai-control-panel">
          <label>
            <Brain size={15} />
            <select value={provider} onChange={(event) => onProviderChange(event.target.value)}>
              {Object.entries(analysisProviders).map(([id, config]) => (
                <option value={id} key={id}>
                  {config.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            <KeyRound size={15} />
            <input
              type="password"
              value={aiKey}
              onChange={(event) => onAiKeyChange(event.target.value)}
              placeholder={providerConfig.placeholder}
              autoComplete="off"
            />
          </label>
          <label>
            <Brain size={15} />
            <input
              value={model}
              onChange={(event) => onModelChange(event.target.value)}
              placeholder={providerConfig.defaultModel}
            />
          </label>
          <button
            type="button"
            disabled={apiTestLoading}
            onClick={onApiTest}
          >
            {apiTestLoading ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
            API可用性测试
          </button>
        </div>
      </div>

      <div className="notice subtle">
        <ShieldCheck size={18} />
        <span>AI 分析支持 OpenAI / DeepSeek，只读取已保存的公开文件定位和脱敏代码上下文，不保存你的 API Key，也不会验证或使用泄露凭证。</span>
      </div>

      {error && (
        <div className="notice error">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}

      {apiTestError && (
        <div className="notice error">
          <AlertTriangle size={18} />
          <span>{apiTestError}</span>
        </div>
      )}

      {apiTestResult?.ok && (
        <div className="notice success">
          <CheckCircle2 size={18} />
          <span>
            {apiTestResult.providerLabel || providerConfig.label} / {apiTestResult.model} 可用。
            {apiTestResult.checkedAt ? ` 测试时间：${new Date(apiTestResult.checkedAt).toLocaleString()}` : ""}
          </span>
        </div>
      )}

      {files.length === 0 ? (
        <div className="clean-state">
          <CheckCircle2 size={22} />
          <span>漏洞仓库里还没有具备内容证据的高风险文件。先运行一次 GitHub 扫描即可收集。</span>
        </div>
      ) : (
        <div className="risk-file-list">
          {files.map((file) => {
            const loading = loadingKey === file.findings.map((finding) => finding.key).join(":");
            return (
              <article className="risk-file-row" key={`${file.repository}:${file.file}`}>
                <div className="risk-file-main">
                  <div className="risk-file-title">
                    <span className={`pill ${file.severity}`}>{severityLabels[file.severity]}</span>
                    <div>
                      <strong>{file.displayPath}</strong>
                      <span>{file.repository || "Unknown repository"}</span>
                    </div>
                  </div>
                  <div className="risk-file-tags">
                    {file.findings.slice(0, 4).map((finding) => (
                      <span key={finding.key}>{finding.label || finding.ruleId}</span>
                    ))}
                  </div>
                  {file.analysis?.result && <AiAnalysisResult analysis={file.analysis} />}
                </div>
                <div className="risk-file-actions">
                  {file.fileUrl && (
                    <a href={file.fileUrl} target="_blank" rel="noreferrer" className="locate-button">
                      <LocateFixed size={15} />
                      <span>定位</span>
                    </a>
                  )}
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => onAnalyze(file.findings.map((finding) => finding.key))}
                  >
                    {loading ? <Loader2 className="spin" size={16} /> : <Brain size={16} />}
                    深度分析
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function AiAnalysisResult({ analysis }) {
  const result = analysis.result;
  return (
    <details className="ai-analysis-result" open>
      <summary>
        <span>AI 深度分析</span>
        <b className={`confidence ${result.riskRating || "low"}`}>{severityLabels[result.riskRating] || result.riskRating}</b>
      </summary>
      <p>{result.summary}</p>
      <div className="analysis-columns">
        <AnalysisList title="证据" rows={result.evidence} />
        <AnalysisList title="利用前提" rows={result.exploitPrerequisites} />
        <AnalysisList title="修复建议" rows={result.recommendedActions} />
      </div>
      <small>
        {analysis.provider || "openai"} / {analysis.model} · {new Date(analysis.analyzedAt).toLocaleString()}
      </small>
    </details>
  );
}

function AnalysisList({ title, rows = [] }) {
  if (!rows.length) return null;
  return (
    <div className="analysis-list">
      <strong>{title}</strong>
      {rows.slice(0, 4).map((row) => (
        <span key={row}>{row}</span>
      ))}
    </div>
  );
}

function PipelineStrip({ pipeline }) {
  if (!pipeline.length) return null;

  return (
    <section className="pipeline-strip">
      {pipeline.map((stage, index) => (
        <article className={`pipeline-step ${stage.status}`} key={stage.id}>
          <div className="step-index">{index + 1}</div>
          <div>
            <strong>{stage.label}</strong>
            <span>{stage.description}</span>
          </div>
          <output>{stage.status === "disabled" ? "关闭" : stage.count}</output>
        </article>
      ))}
    </section>
  );
}

function AggregationPanel({ aggregations }) {
  if (!aggregations) return null;

  return (
    <section className="aggregation-grid">
      <AggregationList title="仓库聚合" rows={aggregations.byRepository} emptyLabel="暂无仓库命中" />
      <AggregationList title="CVE/CWE 聚合" rows={aggregations.byCve} emptyLabel="暂无 CVE/CWE 命中" />
      <AggregationList title="风险类型" rows={aggregations.byCategory} emptyLabel="暂无风险类型命中" />
      <AggregationList title="规则聚合" rows={aggregations.byRule} emptyLabel="暂无规则命中" />
    </section>
  );
}

function AggregationList({ title, rows = [], emptyLabel }) {
  const visibleRows = rows.slice(0, 4);

  return (
    <article className="aggregation-panel">
      <header>
        <strong>{title}</strong>
      </header>
      {visibleRows.length === 0 ? (
        <p>{emptyLabel}</p>
      ) : (
        <div className="aggregation-rows">
          {visibleRows.map((row) => (
            <div className="aggregation-row" key={row.key}>
              <span>{formatAggregationLabel(row.label)}</span>
              <strong>{row.total}</strong>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

function ScannedRepositories({ repositories }) {
  if (!repositories.length) return null;

  return (
    <section className="repo-panel">
      <header>
        <strong>已扫描仓库</strong>
        <span>{repositories.length} 个候选项目</span>
      </header>
      <div className="repo-list">
        {repositories.map((repo) => (
          <article className={`repo-row ${repo.skipped ? "skipped" : ""}`} key={repo.name}>
            <div>
              <a href={repo.url || `https://github.com/${repo.name}`} target="_blank" rel="noreferrer">
                {repo.name}
              </a>
              <span>{repo.description || "No description"}</span>
            </div>
            <div className="repo-meta">
              <span>{repo.language || "Mixed"}</span>
              <span>{repo.stars || 0} stars</span>
              <span>{repo.scannedFiles || 0} files</span>
              {repo.skipped && <span>Skipped</span>}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <div className="empty-visual" aria-hidden="true">
        <ShieldCheck size={42} />
      </div>
      <h3>等待扫描</h3>
      <p>选择 AI 探索模式可自主发现 GitHub 上 AI 相关公开项目，也可以输入用户、组织、仓库或本地路径，按文件内容匹配凭证泄露、CVE 依赖和常见代码漏洞。</p>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="empty-state">
      <div className="empty-visual scanning" aria-hidden="true">
        <RefreshCw size={40} />
      </div>
      <h3>正在分析仓库</h3>
      <p>大型仓库或历史扫描会需要更久一点。</p>
    </div>
  );
}

function SummaryGrid({ result }) {
  const summary = result.summary;
  const healthy = summary.total === 0;
  const githubSummary = typeof summary.repositories === "number";

  return (
    <section className="summary-grid">
      <div className={`summary-tile ${healthy ? "good" : "danger"}`}>
        {healthy ? <CheckCircle2 size={24} /> : <AlertTriangle size={24} />}
        <div>
          <span>{summary.total}</span>
          <p>总命中</p>
        </div>
      </div>
      {severityOrder.slice(0, githubSummary ? 2 : 3).map((severity) => (
        <div className="summary-tile" key={severity}>
          <span className={`severity-dot ${severity}`} />
          <div>
            <span>{summary[severity] || 0}</span>
            <p>{severityLabels[severity]}</p>
          </div>
        </div>
      ))}
      {githubSummary ? (
        <>
          <div className="summary-tile">
            <Github size={22} />
            <div>
              <span>{summary.repositories || 0}</span>
              <p>仓库</p>
            </div>
          </div>
          <div className="summary-tile">
            <FileSearch size={22} />
            <div>
              <span>{summary.scannedFiles || 0}</span>
              <p>文件</p>
            </div>
          </div>
        </>
      ) : (
        <div className="summary-tile">
          <Clock3 size={22} />
          <div>
            <span>{Math.max(1, Math.round(result.durationMs / 1000))}s</span>
            <p>耗时</p>
          </div>
        </div>
      )}
    </section>
  );
}

function FindingsTable({ findings }) {
  if (findings.length === 0) {
    return (
      <div className="clean-state">
        <CheckCircle2 size={22} />
        <span>当前筛选下没有命中。</span>
      </div>
    );
  }

  return (
    <div className="findings-table">
      <div className="table-head">
        <span>等级</span>
        <span>位置</span>
        <span>规则</span>
        <span>片段</span>
      </div>
      {findings.map((finding) => (
        <article className="finding-row" key={finding.id}>
          <div>
            <span className={`pill ${finding.severity}`}>{severityLabels[finding.severity]}</span>
          </div>
          <div className="location-cell">
            <strong>{finding.file}</strong>
            <span>
              {finding.line ? `Line ${finding.line}` : "Risk file"} ·{" "}
              {sourceLabel(finding.source)}
            </span>
            {finding.commit && <small>{finding.commit.slice(0, 12)}</small>}
          </div>
          <div className="rule-cell">
            <strong>{finding.label}</strong>
            <div className="risk-file-tags">
              {finding.provider && <span>{finding.provider}</span>}
              {finding.category && <span>{finding.category}</span>}
              {finding.cwe && <span>{finding.cwe}</span>}
              {(finding.possibleCves || []).slice(0, 2).map((cve) => (
                <span key={cve}>{cve}</span>
              ))}
              {finding.evidenceLevel && <span>{formatEvidenceLevel(finding.evidenceLevel)}</span>}
            </div>
            <span>{finding.advice}</span>
            <ExploitabilityPanel assessment={finding.exploitability} />
          </div>
          <div className="snippet-cell">
            <code>{finding.context}</code>
            <div className="snippet-actions">
              {finding.fileUrl && (
                <a
                  className="locate-button"
                  href={finding.fileUrl}
                  target="_blank"
                  rel="noreferrer"
                  title="定位到 GitHub 文件位置"
                  aria-label={`定位到 ${finding.file}`}
                >
                  <LocateFixed size={15} />
                  <span>定位</span>
                </a>
              )}
              <button
                type="button"
                title="复制脱敏片段"
                onClick={() => navigator.clipboard?.writeText(finding.context)}
              >
                <Copy size={15} />
              </button>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function ExploitabilityPanel({ assessment }) {
  if (!assessment) return null;
  const visibleModes = (assessment.modes || []).slice(0, 2);
  const visibleTests = (assessment.safeTests || []).slice(0, 5);

  return (
    <details className="exploit-panel">
      <summary>
        <span>可能利用</span>
        <b className={`confidence ${assessment.confidence || "low"}`}>
          {confidenceLabels[assessment.confidence] || "待复核"}
        </b>
      </summary>
      <p>{assessment.summary}</p>
      <div className="exploit-modes">
        {visibleModes.map((mode) => (
          <article key={mode.title}>
            <strong>{mode.title}</strong>
            <span>{mode.impact}</span>
            <small>{mode.prerequisites}</small>
          </article>
        ))}
      </div>
      <div className="safe-tests">
        {visibleTests.map((test) => (
          <span className={`test-chip ${test.result}`} title={test.evidence} key={test.name}>
            {test.name}
          </span>
        ))}
      </div>
      <small>{assessment.limitation}</small>
    </details>
  );
}

function sourceLabel(source) {
  if (source === "history") return "History";
  if (source === "github") return "GitHub";
  return "Current";
}

function formatAggregationLabel(label) {
  return severityLabels[label] || label;
}

function formatEvidenceLevel(level) {
  return {
    confirmed_pattern: "精确格式",
    contextual_pattern: "上下文格式",
    generic_entropy: "高熵上下文",
    static_vulnerability_pattern: "静态漏洞模式",
    candidate: "候选"
  }[level] || level;
}

function loadRiskVault() {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RISK_VAULT_KEY) || window.localStorage.getItem(LEGACY_RISK_VAULT_KEY) || "[]";
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function createEmptyClientVault(projects = []) {
  return {
    projects,
    findings: [],
    analyses: [],
    scanCount: 0,
    projectCount: projects.length,
    vulnerabilityCount: 0,
    analysisCount: 0
  };
}

function persistRiskVault(projects) {
  const sorted = [...projects].sort(
    (left, right) => severityRank(right.severity) - severityRank(left.severity) || right.findingCount - left.findingCount
  );
  if (typeof window !== "undefined") {
    window.localStorage.setItem(RISK_VAULT_KEY, JSON.stringify(sorted));
  }
  return sorted;
}

function mergeRiskProjects(currentProjects, newProjects) {
  const map = new Map(currentProjects.map((project) => [project.name, project]));

  for (const project of newProjects) {
    const current = map.get(project.name);
    if (!current) {
      map.set(project.name, project);
      continue;
    }

    map.set(project.name, {
      ...current,
      ...project,
      severity: severityRank(project.severity) > severityRank(current.severity) ? project.severity : current.severity,
      findingCount: Math.max(current.findingCount || 0, project.findingCount || 0),
      files: uniqueStrings([...(current.files || []), ...(project.files || [])]),
      fileLocations: mergeFileLocations(current.fileLocations, project.fileLocations),
      rules: uniqueStrings([...(current.rules || []), ...(project.rules || [])]),
      stages: uniqueStrings([...(current.stages || []), ...(project.stages || [])]),
      providers: uniqueStrings([...(current.providers || []), ...(project.providers || [])]),
      categories: uniqueStrings([...(current.categories || []), ...(project.categories || [])]),
      firstDetectedAt: current.firstDetectedAt || current.firstSeenAt || project.firstDetectedAt || project.firstSeenAt,
      firstSeenAt: current.firstSeenAt || current.firstDetectedAt || project.firstSeenAt || project.firstDetectedAt,
      lastDetectedAt: project.lastDetectedAt || project.lastSeenAt || new Date().toISOString(),
      lastSeenAt: project.lastSeenAt || project.lastDetectedAt || new Date().toISOString()
    });
  }

  return [...map.values()];
}

function actionableRiskProjects(projects = []) {
  return projects.filter((project) => {
    const stages = Array.isArray(project.stages) ? project.stages : [];
    if (stages.some((stage) => stage === "token-pattern" || stage === "entropy-context" || stage === "vulnerability-pattern")) return true;
    return Boolean(project.actionable || project.evidenceLevel === "credential" || project.evidenceLevel === "static_vulnerability_pattern");
  });
}

function uniqueStrings(values) {
  return [...new Set(values.filter(Boolean))];
}

function buildHighRiskFiles(vault) {
  const analyses = vault?.analyses || [];
  const analysisByFinding = new Map();
  for (const analysis of analyses) {
    for (const key of analysis.findingKeys || []) {
      const current = analysisByFinding.get(key);
      if (!current || new Date(analysis.analyzedAt) > new Date(current.analyzedAt)) {
        analysisByFinding.set(key, analysis);
      }
    }
  }

  const groups = new Map();
  for (const finding of vault?.findings || []) {
    if (!isHighRiskFinding(finding)) continue;
    const key = `${finding.repository || "unknown"}:${finding.file}`;
    const current = groups.get(key) || {
      repository: finding.repository,
      file: finding.file,
      displayPath: displayFilePath(finding.repository, finding.file),
      fileUrl: finding.fileUrl,
      severity: finding.severity,
      findings: [],
      analysis: null
    };
    current.severity = severityRank(finding.severity) > severityRank(current.severity) ? finding.severity : current.severity;
    if (!current.fileUrl && finding.fileUrl) current.fileUrl = finding.fileUrl;
    current.findings.push(finding);
    const analysis = analysisByFinding.get(finding.key) || finding.aiAnalysis;
    if (analysis && (!current.analysis || new Date(analysis.analyzedAt) > new Date(current.analysis.analyzedAt))) {
      current.analysis = analysis;
    }
    groups.set(key, current);
  }

  return [...groups.values()].sort(
    (left, right) =>
      severityRank(right.severity) - severityRank(left.severity) ||
      right.findings.length - left.findings.length
  );
}

function isHighRiskFinding(finding) {
  if (finding.actionable === false) return false;
  return (
    finding.stage !== "risk-file-name" &&
    (["critical", "high"].includes(finding.severity) ||
      finding.exploitability?.confidence === "high" ||
      finding.actionable === true ||
      finding.evidenceLevel === "credential")
  );
}

function displayFilePath(repository, file) {
  const prefix = `${repository}/`;
  return repository && String(file || "").startsWith(prefix) ? file.slice(prefix.length) : file;
}

function normalizeFileLocations(project) {
  if (Array.isArray(project.fileLocations) && project.fileLocations.length) {
    return project.fileLocations.filter((location) => location?.path || location?.url);
  }

  return (project.files || []).map((file) => ({
    path: file,
    displayPath: file?.startsWith(`${project.name}/`) ? file.slice(project.name.length + 1) : file,
    url: null,
    findingCount: 1
  }));
}

function mergeFileLocations(currentLocations = [], newLocations = []) {
  const map = new Map();
  for (const location of [...currentLocations, ...newLocations]) {
    if (!location?.path && !location?.url) continue;
    const key = location.path || location.url;
    const current = map.get(key);
    map.set(key, {
      ...current,
      ...location,
      url: location.url || current?.url || null,
      findingCount: Math.max(current?.findingCount || 0, location.findingCount || 0),
      lines: uniqueStrings([...(current?.lines || []), ...(location.lines || [])])
    });
  }
  return [...map.values()];
}

function severityRank(severity) {
  return {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }[severity] || 0;
}

createRoot(document.getElementById("root")).render(<App />);
