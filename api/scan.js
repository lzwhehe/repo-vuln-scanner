import { scanTarget } from "../server/scanner.js";
import { persistScanResult } from "../server/vault.js";

export async function POST(request) {
  try {
    const body = await request.json();
    const result = await scanTarget(body.target, {
      githubApiMode: true,
      scanHistory: false,
      githubToken: process.env.GITHUB_TOKEN,
      maxRepositories: body.maxRepositories,
      maxFilesPerRepo: body.maxFilesPerRepo,
      scanTheme: body.scanTheme || "ai",
      enableValidityCheck: false
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

    return Response.json({ ...result, persistence });
  } catch (error) {
    console.error(error);
    return Response.json(
      { error: error instanceof Error ? error.message : "Scan failed." },
      { status: 400 }
    );
  }
}
