import { analyzeHighRiskFiles, testAiProviderAvailability } from "../server/aiAnalysis.js";

export async function POST(request) {
  try {
    const body = await request.json();
    if (body.testOnly) {
      return Response.json(
        await testAiProviderAvailability({
          apiKey: body.apiKey,
          model: body.model,
          provider: body.provider
        })
      );
    }

    return Response.json(
      await analyzeHighRiskFiles({
        apiKey: body.apiKey,
        findingKeys: body.findingKeys,
        model: body.model,
        provider: body.provider
      })
    );
  } catch (error) {
    console.error(error);
    return Response.json(
      { error: error instanceof Error ? error.message : "AI analysis failed." },
      { status: error.status || 500 }
    );
  }
}
