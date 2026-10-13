import path from "node:path";
import express from "express";
import { analyzeHighRiskFiles, testAiProviderAvailability } from "./aiAnalysis.js";
import { scanTarget } from "./scanner.js";
import { clearVault, getVault, persistScanResult } from "./vault.js";

const app = express();
const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || "127.0.0.1";
// 公网演示模式：只允许 GitHub API 扫描（禁止扫描服务器本地路径）、不做密钥有效性验证、禁止清空风险库
const publicDemo = process.env.PUBLIC_DEMO === "1";

app.use((request, response, next) => {
  response.setHeader("Access-Control-Allow-Origin", process.env.APP_ORIGIN || "http://localhost:5173");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (request.method === "OPTIONS") {
    response.sendStatus(204);
    return;
  }
  next();
});

app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_request, response) => {
  response.json({ ok: true, service: "vulnerability-scanner" });
});

app.get("/api/vault", async (_request, response) => {
  try {
    response.json(await getVault());
  } catch (error) {
    response.status(500).json({
      error: error instanceof Error ? error.message : "Failed to load vault."
    });
  }
});

app.delete("/api/vault", async (_request, response) => {
  if (publicDemo) {
    response.status(403).json({ error: "演示环境已禁用清空操作" });
    return;
  }
  try {
    response.json(await clearVault());
  } catch (error) {
    response.status(500).json({
      error: error instanceof Error ? error.message : "Failed to clear vault."
    });
  }
});

app.post("/api/scan", async (request, response) => {
  try {
    const {
      target,
      scanHistory,
      maxHistoryCommits,
      githubApiMode,
      maxRepositories,
      maxFilesPerRepo,
      scanTheme,
      enableValidityCheck
    } =
      request.body || {};
    const result = await scanTarget(target, {
      githubApiMode: publicDemo || Boolean(githubApiMode),
      scanHistory: !publicDemo && Boolean(scanHistory),
      maxHistoryCommits,
      maxRepositories,
      maxFilesPerRepo,
      scanTheme,
      enableValidityCheck: !publicDemo && Boolean(enableValidityCheck)
    });
    const persistence =
      result.findings?.length || result.riskProjects?.length
        ? await persistScanResult(result).catch((error) => ({
            storage: {
              type: "error",
              configured: false,
              label: "Persistence error",
              reason: error instanceof Error ? error.message : "Failed to persist scan result."
            },
            vault: null
          }))
        : null;
    response.json({ ...result, persistence });
  } catch (error) {
    response.status(400).json({
      error: error instanceof Error ? error.message : "Scan failed."
    });
  }
});

app.post("/api/analyze", async (request, response) => {
  try {
    const { apiKey, findingKeys, model, provider, testOnly } = request.body || {};
    if (testOnly) {
      response.json(await testAiProviderAvailability({ apiKey, model, provider }));
      return;
    }

    response.json(await analyzeHighRiskFiles({ apiKey, findingKeys, model, provider }));
  } catch (error) {
    response.status(error.status || 500).json({
      error: error instanceof Error ? error.message : "AI analysis failed."
    });
  }
});

// 容器部署：同时托管前端构建产物，网关按 /scanner/ 前缀转发过来
const staticDir = process.env.STATIC_DIR;
if (staticDir) {
  app.use(express.static(staticDir));
  app.get(/^\/(?!api\/).*/, (_request, response) => {
    response.sendFile(path.join(staticDir, "index.html"));
  });
}

app.listen(port, host, () => {
  console.log(`漏洞扫描器 API listening on http://${host}:${port}`);
});
